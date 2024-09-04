package ucan

import (
	"errors"
)

var (
	ErrNotAuthorized     = errors.New("not authorized")
	ErrCapabilityExpired = errors.New("capability expired")
	ErrBadToken          = errors.New("bad token")
	ErrTooBig            = errors.New("capability blob too big")

	ErrTODO = errors.New("TODO")
)
