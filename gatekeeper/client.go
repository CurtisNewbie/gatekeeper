package gatekeeper

import "github.com/curtisnewbie/miso/miso"

type TestResAccessReq struct {
	RoleNo string `json:"roleNo"`
	Url    string `json:"url"`
	Method string `json:"method"`
}

type TestResAccessResp struct {
	Valid bool `json:"valid"`
}

// Test whether this role has access to the url
func TestResourceAccess(c miso.Rail, req TestResAccessReq) (TestResAccessResp, error) {
	var r miso.GnResp[TestResAccessResp]
	err := miso.NewDynTClient(c, "/remote/path/resource/access-test", "goauth").
		EnableTracing().
		PostJson(req).
		Json(&r)

	if err != nil {
		return TestResAccessResp{}, err
	}
	return r.Res()
}
