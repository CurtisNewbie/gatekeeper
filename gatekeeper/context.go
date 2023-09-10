package gatekeeper

import (
	"github.com/curtisnewbie/miso/miso"
	"github.com/gin-gonic/gin"
)

const (
	SERVICE_PATH = "GK_SERVICE_PATH"
	AUTH_INFO    = "GK_AUTH_INFO"
)

type ProxyContext struct {
	Rail miso.Rail
	Gin  *gin.Context

	attr map[string]any // attributes, it's lazy, only initialized on write
}

func (pc *ProxyContext) SetAttr(key string, val any) {
	if pc.attr == nil {
		pc.attr = map[string]any{}
	}

	pc.attr[key] = val
}

func (pc *ProxyContext) GetAttr(key string) (any, bool) {
	if pc.attr == nil {
		return nil, false
	}

	v, ok := pc.attr[key]
	return v, ok
}

func NewProxyContext(rail miso.Rail, c *gin.Context) ProxyContext {
	return ProxyContext{
		attr: nil,
		Gin:  c,
		Rail: rail,
	}
}
