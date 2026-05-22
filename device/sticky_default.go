//go:build !linux

package device

import (
	"github.com/bepass-org/psiphon/conn"
	"github.com/bepass-org/psiphon/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
