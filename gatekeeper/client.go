package gatekeeper

import (
	"context"

	"github.com/curtisnewbie/gocommon/client"
	"github.com/curtisnewbie/gocommon/common"
)

type TestResAccessReq struct {
	RoleNo string `json:"roleNo"`
	Url    string `json:"url"`
	Method string `json:"method"`
}

type TestResAccessResp struct {
	Valid bool `json:"valid"`
}

// Test whether this role has access to the url
func TestResourceAccess(ctx context.Context, req TestResAccessReq) (TestResAccessResp, error) {
	c := common.EmptyExecContext()
	tr := client.NewDynTClient(c, "/remote/path/resource/access-test", "goauth").
		EnableTracing().
		PostJson(req)

	if tr.Err != nil {
		return TestResAccessResp{}, tr.Err
	}

	var r common.GnResp[TestResAccessResp]
	if e := tr.ReadJson(&r); e != nil {
		return TestResAccessResp{}, e
	}

	err := r.Err()
	if err != nil {
		return TestResAccessResp{}, err
	}

	return r.Data, nil
}
