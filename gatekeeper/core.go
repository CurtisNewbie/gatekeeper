package gatekeeper

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/curtisnewbie/miso/middleware/jwt"
	"github.com/curtisnewbie/miso/middleware/logbot"
	"github.com/curtisnewbie/miso/middleware/user-vault/common"
	"github.com/curtisnewbie/miso/miso"
	"github.com/curtisnewbie/miso/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cast"
)

var (
	errPathNotFound = miso.NewErrf("Path not found")
	gatewayClient   *http.Client

	timerHistoVec     *prometheus.HistogramVec = miso.NewPromHistoVec("gatekeeper_request_duration", []string{"url"})
	timerExclPath                              = util.NewSet[string]()
	histoVecTimerPool                          = sync.Pool{
		New: func() any {
			return miso.NewVecTimer(timerHistoVec)
		},
	}

	whitelistPatterns []string
)

const (
	AttrMetricsTimer = "metrics.timer"
	AttrAuthInfo     = "GK_AUTH_INFO"
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
	logbot.EnableLogbotErrLogReport()
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

	// create proxy
	proxy := miso.NewHttpProxy("/", ResolveServiceTarget)

	// healthcheck filter
	healthcheckPath := miso.GetPropStr(miso.PropConsulHealthcheckUrl)
	if !util.IsBlankStr(healthcheckPath) {
		miso.PerfLogExclPath(healthcheckPath)
		proxy.AddFilter(miso.ProxyFilter{Order: 0, PreRequest: HealthPreFilter})
	}

	// metrics filter
	metricsEndpoint := miso.GetPropStr(miso.PropMetricsRoute)
	if !util.IsBlankStr(metricsEndpoint) {
		miso.PerfLogExclPath(metricsEndpoint)
		if miso.GetPropBool(miso.PropMetricsEnabled) {
			proxy.AddFilter(miso.ProxyFilter{
				Order:       1,
				PreRequest:  MetricsPreFilter,
				PostRequest: MetricsPostFilter,
			})
		}
	}

	// pprof filter
	if miso.IsProdMode() && !miso.GetPropBool(miso.PropServerPprofEnabled) {
		miso.PerfLogExclPath("/debug/pprof")
		miso.PerfLogExclPath("/debug/pprof/cmdline")
		miso.PerfLogExclPath("/debug/pprof/profile")
		miso.PerfLogExclPath("/debug/pprof/symbol")
		miso.PerfLogExclPath("/debug/pprof/trace")
		proxy.AddFilter(miso.ProxyFilter{Order: 2, PreRequest: PprofPreFilter})
	}

	// gatekeeper filter
	proxy.AddFilter(miso.ProxyFilter{Order: 3, PreRequest: AuthPreFilter})
	proxy.AddFilter(miso.ProxyFilter{Order: 4, PreRequest: AccessPreFilter})
	proxy.AddFilter(miso.ProxyFilter{Order: 5, PreRequest: TracePreFilter})

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

func HealthPreFilter(pc *miso.ProxyContext) (miso.FilterResult, error) {
	healthcheckPath := miso.GetPropStr(miso.PropConsulHealthcheckUrl)

	// check if it's a healthcheck endpoint (for consul), we don't really return anything, so it's fine to expose it
	if pc.ProxyPath == healthcheckPath {
		w, _ := pc.Inb.Unwrap()
		w.WriteHeader(200)
		return miso.FilterResult{Next: false}, nil
	}

	return miso.FilterResult{Next: true}, nil
}

func MetricsPreFilter(pc *miso.ProxyContext) (miso.FilterResult, error) {
	metricsEndpoint := miso.GetPropStr(miso.PropMetricsRoute)
	prometheusHandler := miso.PrometheusHandler()
	w, r := pc.Inb.Unwrap()

	if r.URL.Path == metricsEndpoint {
		prometheusHandler.ServeHTTP(w, r)
		return miso.FilterResult{Next: false}, nil
	}

	if timerExclPath.Has(r.URL.Path) {
		return miso.FilterResult{Next: true}, nil
	}

	timer := histoVecTimerPool.Get().(*miso.VecTimer)
	timer.Reset()
	pc.SetAttr(AttrMetricsTimer, timer)
	return miso.FilterResult{Next: true}, nil
}

func MetricsPostFilter(pc *miso.ProxyContext) {
	v, ok := pc.GetAttr(AttrMetricsTimer)
	if !ok {
		return
	}
	pc.DelAttr(AttrMetricsTimer)
	if timer, ok := v.(*miso.VecTimer); ok {
		defer histoVecTimerPool.Put(timer)
		timer.ObserveDuration(pc.ProxyPath)
	}
}

func PprofPreFilter(pc *miso.ProxyContext) (miso.FilterResult, error) {
	w, r := pc.Inb.Unwrap()
	if r.URL.Path == "/debug/pprof/cmdline" {
		pprof.Cmdline(w, r)
		return miso.FilterResult{Next: false}, nil
	} else if r.URL.Path == "/debug/pprof/profile" {
		pprof.Profile(w, r)
		return miso.FilterResult{Next: false}, nil
	} else if r.URL.Path == "/debug/pprof/symbol" {
		pprof.Symbol(w, r)
		return miso.FilterResult{Next: false}, nil
	} else if r.URL.Path == "/debug/pprof/trace" {
		pprof.Trace(w, r)
		return miso.FilterResult{Next: false}, nil
	} else if strings.HasPrefix(r.URL.Path, "/debug/pprof") {
		pprof.Index(w, r)
		return miso.FilterResult{Next: false}, nil
	}
	return miso.FilterResult{Next: true}, nil
}

type GatewayError struct {
	StatusCode int
}

func (g GatewayError) Status() int {
	return g.StatusCode
}

func (g GatewayError) Error() string {
	return fmt.Sprintf("gateway error, %v", g.StatusCode)
}

func ResolveServiceTarget(rail miso.Rail, proxyPath string) (string, error) {
	if proxyPath == miso.GetPropStr(miso.PropConsulHealthcheckUrl) {
		return proxyPath, nil
	}
	if proxyPath == miso.GetPropStr(miso.PropMetricsRoute) {
		return proxyPath, nil
	}
	if strings.HasPrefix(proxyPath, "/debug/pprof") {
		return proxyPath, nil
	}

	// parse the request path, extract service name, and the relative url for the backend server
	var sp ServicePath
	var err error
	if sp, err = parseServicePath(proxyPath); err != nil {
		miso.Warnf("Invalid request, %v", err)
		return "", GatewayError{StatusCode: 404}
	}
	miso.Debugf("parsed service path: %#v", sp)
	target, err := miso.GetServiceRegistry().ResolveUrl(miso.EmptyRail(), sp.ServiceName, sp.Path)
	if err != nil {
		miso.Warnf("ServiceRegistry ResolveUrl failed, %v", err)
		return "", GatewayError{StatusCode: 404}
	}
	return target, nil
}

func AuthPreFilter(pc *miso.ProxyContext) (miso.FilterResult, error) {
	rail := pc.Rail
	_, r := pc.Inb.Unwrap()
	authorization := r.Header.Get("Authorization")
	rail.Debugf("Authorization: %v", authorization)

	// no token available
	if authorization == "" {
		return miso.FilterResult{Next: true}, nil
	}

	// decode jwt token, extract claims and build a user struct as attr
	tkn, err := jwt.JwtDecode(authorization)
	rail.Debugf("DecodeToken, tkn: %v, err: %v", tkn, err)

	// token invalid, but the public endpoints are still accessible, so we don't stop here
	if err != nil || !tkn.Valid {
		rail.Debugf("Token invalid, %v", err)
		return miso.FilterResult{Next: true}, nil
	}

	// extract the user info from it
	claims := tkn.Claims
	var user common.User

	if v, ok := claims["username"]; ok {
		user.Username = cast.ToString(v)
	}
	if v, ok := claims["userno"]; ok {
		user.UserNo = cast.ToString(v)
	}
	if v, ok := claims["roleno"]; ok {
		user.RoleNo = cast.ToString(v)
	}
	pc.SetAttr(AttrAuthInfo, user)
	rail.Debugf("user: %#v", user)
	rail.Debugf("set user to proxyContext: %v", pc)

	return miso.FilterResult{Next: true}, nil
}

func AccessPreFilter(pc *miso.ProxyContext) (miso.FilterResult, error) {
	w, r := pc.Inb.Unwrap()
	rail := pc.Rail

	rail.Debugf("proxyContext: %v", pc)

	var roleNo string
	var u common.User = common.NilUser()

	if v, ok := pc.GetAttr(AttrAuthInfo); ok && v != nil {
		u = v.(common.User)
		roleNo = u.RoleNo
	}

	inWhitelist := false
	for _, pat := range whitelistPatterns {
		if ok, _ := path.Match(pat, r.URL.Path); ok {
			inWhitelist = true
			break
		}
	}

	var cr CheckResAccessResp
	if inWhitelist {
		cr = CheckResAccessResp{true}
	} else {
		var err error
		cr, err = ValidateResourceAccess(*rail, CheckResAccessReq{
			Url:    r.URL.Path,
			Method: r.Method,
			RoleNo: roleNo,
		})

		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			rail.Warnf("Request forbidden, err: %v", err)
			return miso.FilterResult{Next: false}, nil
		}
	}

	if !cr.Valid {
		rail.Warnf("Request forbidden (resource access not authorized), url: %v, user: %+v", r.URL.Path, u)

		// authenticated, but doesn't have enough authority to access the endpoint
		if !u.IsNil {
			w.WriteHeader(http.StatusForbidden)
			return miso.FilterResult{Next: false}, nil
		}

		// token invalid or expired
		w.WriteHeader(http.StatusUnauthorized)
		return miso.FilterResult{Next: false}, nil
	}

	return miso.FilterResult{Next: true}, nil
}

func TracePreFilter(pc *miso.ProxyContext) (miso.FilterResult, error) {
	v, ok := pc.GetAttr(AttrAuthInfo)

	if !ok || v == nil { // not authenticated
		return miso.FilterResult{Next: true}, nil
	}

	u := v.(common.User)
	*pc.Rail = common.StoreUser(*pc.Rail, u)
	pc.Rail.Debugf("Setup trace for user info, rail: %+v", pc.Rail)
	return miso.FilterResult{Next: true}, nil
}
