package gatekeeper

import (
	"strings"

	"github.com/curtisnewbie/gocommon/client"
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/server"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
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
		for i, _ := range filters {
			if err := filters[i](c, ec); err != nil {
				server.DispatchErrJson(c, err)
				return
			}
		}

		// parse the relatvie url, extract serviceName, and the relative url for the backend server
		sp, err := parseServicePath(c.Request.URL.Path)
		if err != nil {
			server.DispatchErrJson(c, err)
			return
		}

		// route requests dynamically using service discovery
		cli := client.NewDynTClient(ec, sp.Path, sp.ServiceName).
			EnableTracing().
			EnableRequestLog()

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
		}

		if r == nil {
			server.DispatchErrJson(c, errPathNotFound)
			return
		}

		if r.Err != nil {
			server.DispatchErrJson(c, r.Err)
			return
		}
		defer r.Close()

		// headers from backend servers
		rh := map[string]string{}
		for k, v := range r.RespHeader {
			if len(v) > 0 {
				rh[k] = v[0]
			}
		}

		// write data from backend to client
		c.DataFromReader(r.StatusCode, r.Resp.ContentLength, c.GetHeader("Content-Type"), r.Resp.Body, rh)
	})
}

type ServicePath struct {
	ServiceName string
	Path        string
}

func parseServicePath(url string) (ServicePath, error) {
	url = strings.Replace(url, "/proxy/", "", 1)

	logrus.Infof("url: %v", url)
	tkn := strings.SplitN(url, "/", 2)
	if len(tkn) < 2 {
		return ServicePath{}, errPathNotFound
	}

	for _, v := range tkn {
		logrus.Infof("tkn: %v", v)
	}

	return ServicePath{
		ServiceName: tkn[0],
		Path:        tkn[1],
	}, nil
}
