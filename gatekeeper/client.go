package gatekeeper

import "github.com/curtisnewbie/miso/miso"

type CheckResAccessReq struct {
	RoleNo string `json:"roleNo"`
	Url    string `json:"url"`
	Method string `json:"method"`
}

type CheckResAccessResp struct {
	Valid bool `json:"valid"`
}

// Check whether this role has access to the url
func ValidateResourceAccess(c miso.Rail, req CheckResAccessReq) (CheckResAccessResp, error) {
	var r miso.GnResp[CheckResAccessResp]
	err := miso.NewDynTClient(c, "/remote/path/resource/access-test", "user-vault").
		PostJson(req).
		Json(&r)

	if err != nil {
		return CheckResAccessResp{}, err
	}
	return r.Res()
}
