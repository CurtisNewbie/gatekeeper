package gatekeeper

import (
	"net/http"
	"path"
	"sync"

	"github.com/curtisnewbie/miso/middleware/user-vault/common"
	"github.com/curtisnewbie/miso/miso"
	"github.com/spf13/cast"
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

		_, r := pc.Inb.Unwrap()
		authorization := r.Header.Get("Authorization")
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

		if v, ok := claims["username"]; ok {
			user.Username = cast.ToString(v)
		}
		if v, ok := claims["userno"]; ok {
			user.UserNo = cast.ToString(v)
		}
		if v, ok := claims["roleno"]; ok {
			user.RoleNo = cast.ToString(v)
		}
		pc.SetAttr(AUTH_INFO, user)
		rail.Debugf("user: %#v", user)
		rail.Debugf("set user to proxyContext: %v", pc)

		return NewFilterResult(pc, next), nil
	})

	// second filter validate authorization
	AddFilter(func(pc ProxyContext) (FilterResult, error) {
		w, r := pc.Inb.Unwrap()
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
			cr, err = ValidateResourceAccess(rail, CheckResAccessReq{
				Url:    r.URL.Path,
				Method: r.Method,
				RoleNo: roleNo,
			})

			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				rail.Warnf("Request forbidden, err: %v", err)
				return NewFilterResult(pc, false), nil
			}
		}

		if !cr.Valid {
			rail.Warnf("Request forbidden (resource access not authorized), url: %v, user: %+v", r.URL.Path, u)

			// authenticated, but doesn't have enough authority to access the endpoint
			if !u.IsNil {
				w.WriteHeader(http.StatusForbidden)
				return NewFilterResult(pc, false), nil
			}

			// token invalid or expired
			w.WriteHeader(http.StatusUnauthorized)
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
		pc.Rail = common.StoreUser(pc.Rail, u)
		pc.Rail.Debugf("Setup trace for user info, rail: %+v", pc.Rail)
		return NewFilterResult(pc, true), nil
	})
}
