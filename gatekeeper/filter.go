package gatekeeper

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/jwt"
	"github.com/gin-gonic/gin"
)

// ------------------------------------------------------------

type Filter = func(c *gin.Context, ec common.ExecContext, proxyContext ProxyContext) (bool, error)

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
	AddFilter(func(c *gin.Context, ec common.ExecContext, proxyContext ProxyContext) (bool, error) {
		authorization := c.GetHeader("Authorization")
		if authorization != "" {
			tkn, err := jwt.DecodeToken(authorization)
			if err != nil {
				return false, common.NewWebErr("Invalid Authentication Token", err.Error())
			}

			if !tkn.Valid {
				return false, common.NewWebErr("Invalid Authentication Token")
			}

			claims := tkn.Claims
			var user common.User = common.User{}

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
		}
		return true, nil
	})

	// second filter validate authorization
	AddFilter(func(c *gin.Context, ec common.ExecContext, proxyContext ProxyContext) (bool, error) {

		var u *common.User = nil
		if v, ok := proxyContext[AUTH_INFO]; ok && v != nil {
			u = v.(*common.User)
		}
		var roleNo string = ""
		if u != nil {
			roleNo = u.RoleNo
		}

		r, err := TestResourceAccess(ec.Ctx, TestResAccessReq{
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
			c.AbortWithStatus(http.StatusForbidden)
			return false, nil
		}

		return true, nil
	})

}
