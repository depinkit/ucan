package ucan

import (
	"strings"
)

type Capability string

const Root = Capability("/")

func (c Capability) Implies(other Capability) bool {
	if c == other || c == Root {
		return true
	}

	return strings.HasPrefix(string(other), string(c)+"/")
}
