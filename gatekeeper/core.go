package gatekeeper

import (
	"errors"
	"net/http"
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	errPathNotFound = miso.NewErr("Path not found")
	gatewayClient   *http.Client
	timerHistoVec   *prometheus.HistogramVec
)

func init() {
	gatewayClient = &http.Client{Timeout: 0}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 1500
	transport.MaxIdleConnsPerHost = 1000
	transport.IdleConnTimeout = time.Minute * 10 // make sure that we can maximize the re-use of connnections
	gatewayClient.Transport = transport

	timerHistoVec = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "gatekeeper_request_duration"}, []string{"url"})
	prometheus.DefaultRegisterer.MustRegister(timerHistoVec)
}

type ServicePath struct {
	ServiceName string
	Path        string
}

func Bootstrap(args []string) {
	prepareFilters()
	prepareServer()
	miso.BootstrapServer(args)
}

func prepareServer() {
	common.LoadBuiltinPropagationKeys()

	miso.SetProp(miso.PropServerPropagateInboundTrace, false) // disable trace propagation, we are the entry point

	// bootstrap metrics and prometheus stuff manually
	miso.ManualBootstrapPrometheus()

	// healthcheck -> metrics -> proxy
	miso.RawAny("/*proxyPath", WrapHealthHandler(WrapMetricsHandler(ProxyRequestHandler)))
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

	// disable the default health check endpoint to avoid conflicts
	miso.SetProp(miso.PropConsulRegisterDefaultHealthcheck, false)

	healthcheckPath := miso.GetPropStr(miso.PropConsulHealthcheckUrl)
	if miso.IsBlankStr(healthcheckPath) {
		return handler
	}

	miso.PerfLogExclPath(healthcheckPath)
	return func(c *gin.Context, rail miso.Rail) {
		// check if it's a healthcheck endpoint (for consul), we don't really return anything, so it's fine to expose it
		if c.Request.URL.Path == healthcheckPath {
			c.AbortWithStatus(200)
			return
		}

		handler(c, rail)
	}
}

func WrapMetricsHandler(handler miso.RawTRouteHandler) miso.RawTRouteHandler {

	metricsEndpoint := miso.GetPropStr(miso.PropMetricsRoute)
	miso.PerfLogExclPath(metricsEndpoint)

	if miso.IsBlankStr(metricsEndpoint) {
		return handler
	}

	if !miso.GetPropBool(miso.PropMetricsEnabled) {
		return func(c *gin.Context, rail miso.Rail) {
			if c.Request.URL.Path == metricsEndpoint {
				rail.Warnf("Invalid request, metrics endpoint is disabled")
				c.AbortWithStatus(404)
				return
			}
			handler(c, rail)
		}
	}

	prometheusHandler := miso.PrometheusHandler()
	return func(c *gin.Context, rail miso.Rail) {
		start := time.Now()

		if c.Request.URL.Path == metricsEndpoint {
			prometheusHandler.ServeHTTP(c.Writer, c.Request)
			return
		}

		// prometheus, observe time took for each request
		defer func() {
			timerHistoVec.WithLabelValues(c.Request.URL.Path).Observe(float64(time.Since(start).Milliseconds()))
		}()

		handler(c, rail)
	}
}

func ProxyRequestHandler(c *gin.Context, rail miso.Rail) {
	rail.Debugf("Request: %v %v, headers: %v", c.Request.Method, c.Request.URL.Path, c.Request.Header)

	// parse the request path, extract service name, and the relative url for the backend server
	sp, err := parseServicePath(c.Request.URL.Path)
	rail.Debugf("parsed servicePath: %+v, err: %v", sp, err)

	if err != nil {
		rail.Warnf("Invalid request, %v", err)
		c.AbortWithStatus(404)
		return
	}

	pc := NewProxyContext(rail, c)
	pc.SetAttr(SERVICE_PATH, sp)

	filters := GetFilters()
	for i := range filters {
		fr, err := filters[i](pc)
		if err != nil || !fr.Next {
			rail.Debugf("request filtered, err: %v, ok: %v", err, fr)
			if err != nil {
				miso.DispatchErrJson(c, rail, err)
				return
			}

			return // discontinue, the filter should write the response itself, e.g., returning a 403 status code
		}
		pc = fr.ProxyContext // replace the ProxyContext, trace may be set
	}

	// continue propgating the trace
	rail = pc.Rail

	// set trace back to Gin for the PerfMiddleware, this feels like a hack, but we have to do this
	c.Set(miso.X_TRACEID, rail.CtxValStr(miso.X_TRACEID))
	c.Set(miso.X_SPANID, rail.CtxValStr(miso.X_SPANID))

	// route requests dynamically using service discovery
	relPath := sp.Path
	if c.Request.URL.RawQuery != "" {
		relPath += "?" + c.Request.URL.RawQuery
	}
	cli := miso.NewTClient(rail, relPath).
		UseClient(gatewayClient).
		EnableServiceDiscovery(sp.ServiceName).
		EnableTracing()

	// propagate all headers to client
	for k, arr := range c.Request.Header {
		for i := range arr {
			cli.AddHeader(k, arr[i])
		}
	}

	var r *miso.TResponse
	switch c.Request.Method {
	case http.MethodGet:
		r = cli.Get()
	case http.MethodPut:
		r = cli.Put(c.Request.Body)
	case http.MethodPost:
		r = cli.Post(c.Request.Body)
	case http.MethodDelete:
		r = cli.Delete()
	case http.MethodHead:
		r = cli.Head()
	case http.MethodOptions:
		r = cli.Options()
	default:
		c.AbortWithStatus(404)
		return
	}

	if r.Err != nil {
		rail.Debugf("post proxy request, request failed, err: %v", r.Err)
		if errors.Is(r.Err, miso.ErrConsulServiceInstanceNotFound) {
			c.AbortWithStatus(404)
			return
		}

		miso.DispatchErrJson(c, rail, r.Err)
		return
	}
	defer r.Close()

	rail.Debugf("post proxy request, proxied response headers: %v, status: %v", r.RespHeader, r.StatusCode)

	// headers from backend servers
	respHeader := map[string]string{}
	for k, v := range r.RespHeader {
		if len(v) > 0 {
			respHeader[k] = v[0]
		}
	}

	// write data from backend to client
	if r.Resp.Body == nil {
		c.Status(r.StatusCode)
		for k, v := range respHeader {
			c.Header(k, v)
		}
	} else {
		c.DataFromReader(r.StatusCode, r.Resp.ContentLength, c.GetHeader("Content-Type"), r.Resp.Body, respHeader)
	}

	rail.Debugf("proxy request handled")
}
