package gatekeeper

import (
	"github.com/curtisnewbie/gocommon/client"
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/server"
	"github.com/gin-gonic/gin"
)

var (
	errPathNotFound = common.NewWebErr("Path not found")
)

// Bootstrap Gatekeeper
func Bootstrap(args []string) {
	prepareServer()
	server.BootstrapServer(args)
}

func prepareServer() {

	// make sure the trace propagation is disabled
	server.PostServerBootstrapped(func(c common.ExecContext) error {
		common.SetProp(common.PROP_SERVER_PROPAGATE_INBOUND_TRACE, false)
		return nil
	})

	server.RawAny("/proxy/*proxyPath", func(c *gin.Context, ec common.ExecContext) {
		filters := GetFilters()
		for i := range filters {
			if err := filters[i](c, ec); err != nil {
				server.DispatchErrJson(c, err)
				return
			}
		}

		// parse the relatvie url, extract serviceName, and the relative url for the backend server
		sp, err := parseServicePath(c.Request.URL.Path)
		if err != nil {
			ec.Log.Warnf("Invalid request, %v", err)
			c.AbortWithStatus(404)
			return
		}

		// route requests dynamically using service discovery
		cli := client.NewDynTClient(ec, sp.Path, sp.ServiceName).
			EnableTracing()

		// propagate all headers to client
		for k, arr := range c.Request.Header {
			for i := range arr {
				cli.AddHeader(k, arr[i])
			}
		}

		var r *client.TResponse
		switch c.Request.Method {
		case "GET":
			r = cli.Get(nil)
		case "PUT":
			r = cli.Put(c.Request.Body)
		case "POST":
			r = cli.Post(c.Request.Body)
		case "DELETE":
			r = cli.Delete(nil)
		default:
			c.AbortWithStatus(404)
			return
		}

		if r.Err != nil {
			server.DispatchErrJson(c, r.Err)
			return
		}
		defer r.Close()

		// headers from backend servers
		respHeader := map[string]string{}
		for k, v := range r.RespHeader {
			if len(v) > 0 {
				respHeader[k] = v[0]
			}
		}

		// write data from backend to client
		c.DataFromReader(r.StatusCode, r.Resp.ContentLength, c.GetHeader("Content-Type"), r.Resp.Body, respHeader)
	})
}

type ServicePath struct {
	ServiceName string
	Path        string
}

func parseServicePath(url string) (ServicePath, error) {
	// /proxy/...
	striped := []rune(url)[7:]

	// root path, invalid request
	if len(striped) < 1 {
		return ServicePath{}, errPathNotFound
	}

	start := 0
	for i := range striped {
		if striped[i] == '/' && i > 0 {
			start = i
			break
		}
	}

	if start < 1 {
		return ServicePath{}, errPathNotFound
	}

	return ServicePath{
		ServiceName: string(striped[0:start]),
		Path:        string(striped[start:]),
	}, nil
}
