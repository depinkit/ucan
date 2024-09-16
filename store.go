package ucan

import (
	"encoding/json"
	"fmt"
	"io"

	"gitlab.com/nunet/device-management-service/lib/did"
)

type Saver interface {
	Save(wr io.Writer) error
}

type CapabilityContextView struct {
	DID     did.DID
	Roots   []did.DID
	Require TokenList
	Provide TokenList
}

func SaveCapabilityContext(ctx CapabilityContext, wr io.Writer) error {
	if bctx, ok := ctx.(*BasicCapabilityContext); ok {
		return saveCapabilityContext(bctx, wr)
	} else if saver, ok := ctx.(Saver); ok {
		return saver.Save(wr)
	}

	return fmt.Errorf("cannot save context: %w", ErrBadContext)
}

func saveCapabilityContext(ctx *BasicCapabilityContext, wr io.Writer) error {
	roots, require, provide := ctx.ListRoots()

	view := CapabilityContextView{
		DID:     ctx.provider.DID(),
		Roots:   roots,
		Require: require,
		Provide: provide,
	}

	encoder := json.NewEncoder(wr)
	if err := encoder.Encode(&view); err != nil {
		return fmt.Errorf("encoding capability context view: %w", err)
	}

	return nil
}

func LoadCapabilityContext(trust did.TrustContext, rd io.Reader) (CapabilityContext, error) {
	var view CapabilityContextView

	decoder := json.NewDecoder(rd)
	if err := decoder.Decode(&view); err != nil {
		return nil, fmt.Errorf("decoding capability context view: %w", err)
	}

	var require, provide TokenList
	for _, t := range view.Require.Tokens {
		if !t.Expired() {
			require.Tokens = append(require.Tokens, t)
		}
	}

	for _, t := range view.Provide.Tokens {
		if !t.Expired() {
			provide.Tokens = append(provide.Tokens, t)
		}
	}

	return NewCapabilityContext(trust, view.DID, view.Roots, require, provide)
}
