package gatekeeper

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/jwt"
	"github.com/gin-gonic/gin"
)

// ------------------------------------------------------------

type Filter = func(c *gin.Context, ec *common.ExecContext, proxyContext ProxyContext) (bool, error)

// ------------------------------------------------------------

var (
	filters []Filter = []Filter{}
	rwmu    sync.RWMutex
)

// ------------------------------------------------------------

func AddFilter(f Filter) {
	rwmu.Lock()
	defer rwmu.Unlock()
	filters = append(filters, f)
}

func GetFilters() []Filter {
	rwmu.RLock()
	defer rwmu.RUnlock()
	copied := make([]Filter, len(filters))
	copy(copied, filters)
	return copied
}

func prepareFilters() {

	// first filter extract authentication
	AddFilter(func(c *gin.Context, ec *common.ExecContext, proxyContext ProxyContext) (bool, error) {
		authorization := c.GetHeader("Authorization")
		ec.Log.Debugf("Authorization: %v", authorization)

		if authorization != "" {
			tkn, err := jwt.DecodeToken(authorization)
			ec.Log.Debugf("DecodeToken, tkn: %v, err: %v", tkn, err)

			// requests may or may not be authenticated, some requests are 'PUBLIC', we just try to extract the user info from it
			if err == nil && tkn.Valid {
				claims := tkn.Claims
				var user common.User

				if v, ok := claims["id"]; ok {
					user.UserId = fmt.Sprintf("%v", v)
				}
				if v, ok := claims["username"]; ok {
					user.Username = fmt.Sprintf("%v", v)
				}
				if v, ok := claims["userno"]; ok {
					user.UserNo = fmt.Sprintf("%v", v)
				}
				if v, ok := claims["roleno"]; ok {
					user.RoleNo = fmt.Sprintf("%v", v)
				}
				proxyContext[AUTH_INFO] = &user
				ec.Log.Debugf("set user to proxyContext: %v", proxyContext)
			}
		}
		return true, nil
	})

	// second filter validate authorization
	AddFilter(func(c *gin.Context, ec *common.ExecContext, proxyContext ProxyContext) (bool, error) {

		ec.Log.Debugf("proxyContext: %v", proxyContext)

		var u *common.User = nil
		if v, ok := proxyContext[AUTH_INFO]; ok && v != nil {
			u = v.(*common.User)
		}
		var roleNo string
		if u != nil {
			roleNo = u.RoleNo
		}

		r, err := TestResourceAccess(*ec, TestResAccessReq{
			Url:    c.Request.URL.Path,
			Method: c.Request.Method,
			RoleNo: roleNo,
		})

		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			ec.Log.Warnf("Request forbidden, err: %v", err)
			return false, nil
		}

		if !r.Valid {
			ec.Log.Warn("Request forbidden, valid = false")
			if u == nil { // the endpoint is not publicly accessible, the request is not authenticated
				c.AbortWithStatus(http.StatusUnauthorized)
				return false, nil
			}

			c.AbortWithStatus(http.StatusForbidden) // request authenticated, but doesn't have enouth authority to access the endpoint
			return false, nil
		}

		return true, nil
	})

	// set user info to context for tracing
	AddFilter(func(_ *gin.Context, ec *common.ExecContext, proxyContext ProxyContext) (bool, error) {
		var u *common.User = nil
		if v, ok := proxyContext[AUTH_INFO]; ok && v != nil {
			u = v.(*common.User)
		}

		if u == nil {
			return true, nil
		}

		ec.Ctx = context.WithValue(ec.Ctx, "id", u.UserId)         //lint:ignore SA1029 have to do this
		ec.Ctx = context.WithValue(ec.Ctx, "username", u.Username) //lint:ignore SA1029 have to do this
		ec.Ctx = context.WithValue(ec.Ctx, "userno", u.UserNo)     //lint:ignore SA1029 have to do this
		ec.Ctx = context.WithValue(ec.Ctx, "roleno", u.RoleNo)     //lint:ignore SA1029 have to do this
		return true, nil
	})
}
