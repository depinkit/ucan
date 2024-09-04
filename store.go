package ucan

import (
	"io"

	"gitlab.com/nunet/device-management-service/lib/did"
)

func SaveCapabilityContext(_ CapabilityContext, _ io.Writer) (int, error) {
	// TODO
	return 0, ErrTODO
}

func LoadCapabilityContext(_ io.Reader, _ did.TrustContext) (CapabilityContext, error) {
	// TODO
	return nil, ErrTODO
}
