package gatekeeper

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"sync"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
)

// ------------------------------------------------------------

type Filter = func(proxyContext ProxyContext) (FilterResult, error)

type FilterResult struct {
	ProxyContext ProxyContext
	Next         bool
}

func NewFilterResult(pc ProxyContext, next bool) FilterResult {
	return FilterResult{ProxyContext: pc, Next: next}
}

// ------------------------------------------------------------

var (
	filters           []Filter = []Filter{}
	rwmu              sync.RWMutex
	whitelistPatterns []string
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
	AddFilter(func(pc ProxyContext) (FilterResult, error) {
		rail := pc.Rail
		next := true

		authorization := pc.Gin.GetHeader("Authorization")
		rail.Debugf("Authorization: %v", authorization)

		// no token available
		if authorization == "" {
			return NewFilterResult(pc, next), nil
		}

		// decode jwt token, extract claims and build a user struct as attr
		tkn, err := miso.JwtDecode(authorization)
		rail.Debugf("DecodeToken, tkn: %v, err: %v", tkn, err)

		// token invalid, but the public endpoints are still accessible, so we don't stop here
		if err != nil || !tkn.Valid {
			rail.Debugf("Token invalid, %v", err)
			return NewFilterResult(pc, next), nil
		}

		// extract the user info from it
		claims := tkn.Claims
		var user common.User

		if v, ok := claims["id"]; ok {
			n, err := strconv.Atoi(fmt.Sprintf("%v", v))
			if err == nil {
				user.UserId = n
			}
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
		pc.SetAttr(AUTH_INFO, user)
		rail.Debugf("set user to proxyContext: %v", pc)

		return NewFilterResult(pc, next), nil
	})

	// second filter validate authorization
	AddFilter(func(pc ProxyContext) (FilterResult, error) {
		c := pc.Gin
		rail := pc.Rail

		rail.Debugf("proxyContext: %v", pc)

		var roleNo string
		var u common.User = common.NilUser()

		if v, ok := pc.GetAttr(AUTH_INFO); ok && v != nil {
			u = v.(common.User)
			roleNo = u.RoleNo
		}

		inWhitelist := false
		for _, pat := range whitelistPatterns {
			if ok, _ := path.Match(pat, c.Request.URL.Path); ok {
				inWhitelist = true
				break
			}
		}

		var r CheckResAccessResp
		if inWhitelist {
			r = CheckResAccessResp{true}
		} else {
			var err error
			r, err = ValidateResourceAccess(rail, CheckResAccessReq{
				Url:    c.Request.URL.Path,
				Method: c.Request.Method,
				RoleNo: roleNo,
			})

			if err != nil {
				c.AbortWithStatus(http.StatusForbidden)
				rail.Warnf("Request forbidden, err: %v", err)
				return NewFilterResult(pc, false), nil
			}
		}

		if !r.Valid {
			rail.Warnf("Request forbidden (resource access not authorized), url: %v, user: %+v", c.Request.URL.Path, u)

			authorization := pc.Gin.GetHeader("Authorization")

			// token invalid or expired
			if authorization != "" {
				c.AbortWithStatus(http.StatusUnauthorized)
				return NewFilterResult(pc, false), nil
			}

			c.AbortWithStatus(http.StatusForbidden) // request authenticated, but doesn't have enouth authority to access the endpoint
			return NewFilterResult(pc, false), nil
		}

		return NewFilterResult(pc, true), nil
	})

	// set user info to context for tracing
	AddFilter(func(pc ProxyContext) (FilterResult, error) {

		v, ok := pc.GetAttr(AUTH_INFO)

		if !ok || v == nil { // not authenticated
			return NewFilterResult(pc, true), nil
		}

		u := v.(common.User)
		pc.Rail = pc.Rail.
			WithCtxVal("x-id", u.UserId).
			WithCtxVal("x-username", u.Username).
			WithCtxVal("x-userno", u.UserNo).
			WithCtxVal("x-roleno", u.RoleNo)

		pc.Rail.Debugf("Setup trace for user info, rail: %+v", pc.Rail)
		return NewFilterResult(pc, true), nil
	})
}
