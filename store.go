// Copyright 2024, Nunet
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

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
	DID     did.DID   `json:"did"`
	Roots   []did.DID `json:"roots"`
	Require TokenList `json:"require"`
	Provide TokenList `json:"provide"`
	Revoke  TokenList `json:"revoke"`
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
	roots, require, provide, revoke := ctx.ListRoots()

	view := CapabilityContextView{
		DID:     ctx.provider.DID(),
		Roots:   roots,
		Require: require,
		Provide: provide,
		Revoke:  revoke,
	}

	encoder := json.NewEncoder(wr)
	if err := encoder.Encode(&view); err != nil {
		return fmt.Errorf("encoding capability context view: %w", err)
	}

	return nil
}

func LoadCapabilityContextWithName(name string, trust did.TrustContext, rd io.Reader) (CapabilityContext, error) {
	var view CapabilityContextView

	decoder := json.NewDecoder(rd)
	if err := decoder.Decode(&view); err != nil {
		return nil, fmt.Errorf("decoding capability context view: %w", err)
	}

	var require, provide, revoke TokenList
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

	for _, t := range view.Revoke.Tokens {
		if !t.Expired() {
			revoke.Tokens = append(revoke.Tokens, t)
		}
	}

	return NewCapabilityContextWithName(name, trust, view.DID, view.Roots, require, provide, revoke)
}

func LoadCapabilityContext(trust did.TrustContext, rd io.Reader) (CapabilityContext, error) {
	return LoadCapabilityContextWithName("dms", trust, rd)
}
