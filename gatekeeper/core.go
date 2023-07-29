package gatekeeper

import (
	"errors"
	"net/http"

	"github.com/curtisnewbie/gocommon/client"
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/consul"
	"github.com/curtisnewbie/gocommon/server"
	"github.com/gin-gonic/gin"
)

type ServicePath struct {
	ServiceName string
	Path        string
}

// -----------------------------------------------------------

var (
	errPathNotFound = common.NewWebErr("Path not found")
)

// -----------------------------------------------------------

// Bootstrap Gatekeeper
func Bootstrap(args []string) {
	prepareFilters()
	prepareServer()
	server.BootstrapServer(args)
}

func prepareServer() {

	common.SetProp(common.PROP_SERVER_PROPAGATE_INBOUND_TRACE, false)      // disable trace propagation, we are now the gateway
	common.SetProp(common.PROP_CONSUL_REGISTER_DEFAULT_HEALTHCHECK, false) // disable the default health check endpoint to avoid conflicts
	common.SetProp(common.PROP_CONSUL_HEALTHCHECK_URL, "/health")          // for consul health check

	server.RawAny("/*proxyPath", func(c *gin.Context, ec common.ExecContext) {
		ec.Log.Debugf("pre filter, method: %v, url: %v, headers: %v", c.Request.Method, c.Request.URL, c.Request.Header)

		// check if it's a healthcheck endpoint (for consul), we don't really return anything, so it's fine to expose it
		if c.Request.URL.Path == "/health" {
			c.AbortWithStatus(200)
			return
		}

		// parse the relatvie url, extract serviceName, and the relative url for the backend server
		sp, err := parseServicePath(c.Request.URL.Path)
		ec.Log.Debugf("parsed servicePath: %+v, err: %v", sp, err)

		if err != nil {
			ec.Log.Warnf("Invalid request, %v", err)
			c.AbortWithStatus(404)
			return
		}

		proxyContext := ProxyContext{}
		proxyContext[SERVICE_PATH] = sp

		filters := GetFilters()
		for i := range filters {
			if ok, err := filters[i](c, &ec, proxyContext); err != nil || !ok {
				ec.Log.Debugf("request filtered, err: %v, ok: %v", err, ok)
				if err != nil {
					server.DispatchErrJson(c, err)
					return
				}
				return
			}
		}

		// route requests dynamically using service discovery
		cli := client.NewDynTClient(ec, sp.Path+"?"+c.Request.URL.RawQuery, sp.ServiceName).
			EnableTracing()

		// propagate all headers to client
		for k, arr := range c.Request.Header {
			for i := range arr {
				cli.AddHeader(k, arr[i])
			}
		}

		var r *client.TResponse
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
			ec.Log.Debugf("post proxy request, request failed, err: %v", r.Err)
			if errors.Is(r.Err, consul.ErrServiceInstanceNotFound) {
				c.AbortWithStatus(404)
				return
			}

			server.DispatchErrJson(c, r.Err)
			return
		}
		defer r.Close()

		ec.Log.Debugf("post proxy request, proxied response headers: %v, status: %v", r.RespHeader, r.StatusCode)

		// headers from backend servers
		respHeader := map[string]string{}
		for k, v := range r.RespHeader {
			if len(v) > 0 {
				respHeader[k] = v[0]
			}
		}

		// write data from backend to client
		c.DataFromReader(r.StatusCode, r.Resp.ContentLength, c.GetHeader("Content-Type"), r.Resp.Body, respHeader)

		ec.Log.Debugf("proxy request handled")
	})
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
