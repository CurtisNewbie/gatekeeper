package gatekeeper

import (
	"sync"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/gin-gonic/gin"
)

// ------------------------------------------------------------

type Filter = func(c *gin.Context, ec common.ExecContext) error

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
	copied = append(copied, filters...)
	return copied
}
