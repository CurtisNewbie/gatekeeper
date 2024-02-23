package gatekeeper

import (
	"errors"
	"io"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	errPathNotFound = miso.NewErrf("Path not found")
	gatewayClient   *http.Client

	timerHistoVec     *prometheus.HistogramVec = miso.NewPromHistoVec("gatekeeper_request_duration", []string{"url"})
	timerExclPath                              = miso.NewSet[string]()
	histoVecTimerPool                          = sync.Pool{
		New: func() any {
			return miso.NewVecTimer(timerHistoVec)
		},
	}
)

func init() {
	gatewayClient = &http.Client{Timeout: 0}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 1500
	transport.MaxIdleConnsPerHost = 1000
	transport.IdleConnTimeout = time.Minute * 10 // make sure that we can maximize the re-use of connnections
	gatewayClient.Transport = transport
}

type ServicePath struct {
	ServiceName string
	Path        string
}

func Bootstrap(args []string) {
	prepareFilters()
	miso.PreServerBootstrap(prepareServer)
	miso.BootstrapServer(args)
}

func prepareServer(rail miso.Rail) error {
	common.LoadBuiltinPropagationKeys()

	miso.Infof("gatekeeper version: %v", Version)

	miso.SetProp(miso.PropServerPropagateInboundTrace, false)      // disable trace propagation, we are the entry point
	miso.SetProp(miso.PropServerGenerateEndpointDocEnabled, false) // do not generate apidoc
	miso.SetProp(miso.PropConsulRegisterDefaultHealthcheck, false) // disable the default health check endpoint to avoid conflicts

	// whitelisted path patterns
	whitelistPatterns = miso.GetPropStrSlice(PropWhitelistPathPatterns)

	// bootstrap metrics and prometheus stuff manually
	miso.ManualBootstrapPrometheus()

	// handle pprof endpoints manually
	miso.ManualPprofRegister()

	// healthcheck -> metrics -> pprof -> proxy
	handler :=
		WrapHealthHandler(
			WrapMetricsHandler(
				WrapPprofHandler(ProxyRequestHandler),
			),
		)

	miso.RawAny("/*proxyPath", handler)

	// paths that are not measured by prometheus timer
	timerExclPath.AddAll(miso.GetPropStrSlice(PropTimerExclPath))
	timerExclPath.Add(miso.GetPropStr(miso.PropMetricsRoute))
	return nil
}

func parseServicePath(url string) (ServicePath, error) {
	rurl := []rune(url)[1:] // remove leading '/'

	// root path, invalid request
	if len(rurl) < 1 {
		return ServicePath{}, errPathNotFound
	}

	start := 0
	for i := range rurl {
		if rurl[i] == '/' && i > 0 {
			start = i
			break
		}
	}

	if start < 1 {
		return ServicePath{}, errPathNotFound
	}

	return ServicePath{
		ServiceName: string(rurl[0:start]),
		Path:        string(rurl[start:]),
	}, nil
}

func WrapHealthHandler(handler miso.RawTRouteHandler) miso.RawTRouteHandler {

	healthcheckPath := miso.GetPropStr(miso.PropConsulHealthcheckUrl)
	if miso.IsBlankStr(healthcheckPath) {
		return handler
	}

	miso.PerfLogExclPath(healthcheckPath)
	return func(inb *miso.Inbound) {
		w, r := inb.Unwrap()
		// check if it's a healthcheck endpoint (for consul), we don't really return anything, so it's fine to expose it
		if r.URL.Path == healthcheckPath {
			w.WriteHeader(200)
			return
		}

		handler(inb)
	}
}

func WrapMetricsHandler(handler miso.RawTRouteHandler) miso.RawTRouteHandler {

	metricsEndpoint := miso.GetPropStr(miso.PropMetricsRoute)
	if !miso.IsBlankStr(metricsEndpoint) {
		miso.PerfLogExclPath(metricsEndpoint)
	}

	if !miso.GetPropBool(miso.PropMetricsEnabled) {
		return func(inb *miso.Inbound) {
			w, r := inb.Unwrap()
			rail := inb.Rail()
			if r.URL.Path == metricsEndpoint {
				rail.Warnf("Invalid request, metrics endpoint is disabled")
				w.WriteHeader(404)
				return
			}
			handler(inb)
		}
	}

	prometheusHandler := miso.PrometheusHandler()
	return func(inb *miso.Inbound) {
		w, r := inb.Unwrap()

		if r.URL.Path == metricsEndpoint {
			prometheusHandler.ServeHTTP(w, r)
			return
		}

		if timerExclPath.Has(r.URL.Path) {
			handler(inb)
			return
		}

		timer := histoVecTimerPool.Get().(*miso.VecTimer)
		handler(inb) // handle the result
		timer.ObserveDuration(r.URL.Path)
		PutHistoVecTimerPool(timer)
	}
}

func PutHistoVecTimerPool(t *miso.VecTimer) {
	t.Reset()
	histoVecTimerPool.Put(t)
}

func ProxyRequestHandler(inb *miso.Inbound) {
	rail := inb.Rail()
	w, r := inb.Unwrap()
	rail.Debugf("Request: %v %v, headers: %v", r.Method, r.URL.Path, r.Header)

	// parse the request path, extract service name, and the relative url for the backend server
	var sp ServicePath
	var err error
	if sp, err = parseServicePath(r.URL.Path); err != nil {
		rail.Warnf("Invalid request, %v", err)
		w.WriteHeader(404)
		return
	}
	rail.Debugf("parsed service path: %#v", sp)

	pc := NewProxyContext(rail, inb)
	pc.SetAttr(SERVICE_PATH, sp)

	filters := GetFilters()
	for i := range filters {
		fr, err := filters[i](pc)
		if err != nil || !fr.Next {
			rail.Debugf("request filtered, err: %v, ok: %v", err, fr)
			if err != nil {
				inb.HandleResult(miso.WrapResp(rail, nil, err, r.RequestURI), nil)
				return
			}

			return // discontinue, the filter should write the response itself, e.g., returning a 403 status code
		}
		pc = fr.ProxyContext // replace the ProxyContext, trace may be set
	}

	// continue propgating the trace
	rail = pc.Rail

	// route requests dynamically using service discovery
	relPath := sp.Path
	if r.URL.RawQuery != "" {
		relPath += "?" + r.URL.RawQuery
	}
	cli := miso.NewTClient(rail, relPath).
		UseClient(gatewayClient).
		EnableServiceDiscovery(sp.ServiceName).
		EnableTracing()

	propagationKeys := miso.NewSet[string]()
	propagationKeys.AddAll(miso.GetPropagationKeys())

	// propagate all headers to client
	for k, arr := range r.Header {
		// the inbound request may contain headers that are one of our propagation keys
		// this can be a security problem
		if propagationKeys.Has(k) {
			continue
		}
		for _, v := range arr {
			cli.AddHeader(k, v)
		}
	}

	var tr *miso.TResponse
	switch r.Method {
	case http.MethodGet:
		tr = cli.Get()
	case http.MethodPut:
		tr = cli.Put(r.Body)
	case http.MethodPost:
		tr = cli.Post(r.Body)
	case http.MethodDelete:
		tr = cli.Delete()
	case http.MethodHead:
		tr = cli.Head()
	case http.MethodOptions:
		tr = cli.Options()
	default:
		w.WriteHeader(404)
		return
	}

	if tr.Err != nil {
		rail.Debugf("post proxy request, request failed, err: %v", tr.Err)
		if errors.Is(tr.Err, miso.ErrConsulServiceInstanceNotFound) {
			w.WriteHeader(404)
			return
		}
		inb.HandleResult(miso.WrapResp(rail, nil, tr.Err, r.RequestURI), nil)
		return
	}
	defer tr.Close()

	rail.Debugf("post proxy request, proxied response headers: %v, status: %v", tr.RespHeader, tr.StatusCode)

	// headers from backend servers
	for k, v := range tr.RespHeader {
		for _, hv := range v {
			w.Header().Add(k, hv)
		}
	}
	rail.Debug(w.Header())

	// write data from backend to client
	if tr.Resp.Body != nil {
		io.Copy(w, tr.Resp.Body)
	}
	w.WriteHeader(tr.StatusCode)

	rail.Debugf("proxy request handled")
}

func WrapPprofHandler(handler miso.RawTRouteHandler) miso.RawTRouteHandler {

	if miso.IsProdMode() && !miso.GetPropBool(miso.PropServerPprofEnabled) {
		return handler
	}

	miso.PerfLogExclPath("/debug/pprof")
	miso.PerfLogExclPath("/debug/pprof/cmdline")
	miso.PerfLogExclPath("/debug/pprof/profile")
	miso.PerfLogExclPath("/debug/pprof/symbol")
	miso.PerfLogExclPath("/debug/pprof/trace")

	return func(inb *miso.Inbound) {
		w, r := inb.Unwrap()

		if r.URL.Path == "/debug/pprof/cmdline" {
			pprof.Cmdline(w, r)
			return
		} else if r.URL.Path == "/debug/pprof/profile" {
			pprof.Profile(w, r)
			return
		} else if r.URL.Path == "/debug/pprof/symbol" {
			pprof.Symbol(w, r)
			return
		} else if r.URL.Path == "/debug/pprof/trace" {
			pprof.Trace(w, r)
			return
		} else if strings.HasPrefix(r.URL.Path, "/debug/pprof") {
			pprof.Index(w, r)
			return
		}

		handler(inb)
	}
}
