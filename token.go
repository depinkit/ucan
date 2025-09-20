// Copyright 2024, Nunet
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package ucan

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/depinkit/did"
)

type Action string

const (
	Invoke    Action = "invoke"
	Delegate  Action = "delegate"
	Broadcast Action = "broadcast"
	Revoke    Action = "revoke"

	nonceLength = 12 // 96 bits
)

var signaturePrefix = []byte("dms:token:")

type Token struct {
	// Domain tokens
	Domain *DomainToken `json:"domain,omitempty"`
	// UCAN standard (when it is done) envelope for BYO anhcors
	UCAN *BYOToken `json:"ucan,omitempty"`
}

type DomainToken struct {
	Action     Action       `json:"act"`
	Issuer     did.DID      `json:"iss"`
	Subject    did.DID      `json:"sub"`
	Audience   did.DID      `json:"aud"`
	Topic      []Capability `json:"topic,omitempty"`
	Capability []Capability `json:"cap"`
	Nonce      []byte       `json:"nonce"`
	Expire     uint64       `json:"exp"`
	Depth      uint64       `json:"depth,omitempty"`
	Chain      *Token       `json:"chain,omitempty"`
	Signature  []byte       `json:"sig,omitempty"`
}

type BYOToken struct {
	// TODO followup
}

type TokenList struct {
	Tokens []*Token `json:"tok,omitempty"`
}

type RevocationSet struct {
	lk      sync.RWMutex
	revoked map[string]*Token
}

func (r *RevocationSet) Revoked(key string) bool {
	r.lk.RLock()
	defer r.lk.RUnlock()

	_, revoked := r.revoked[key]
	return revoked
}

func (r *RevocationSet) Revoke(t *Token) {
	r.lk.Lock()
	defer r.lk.Unlock()

	r.revoked[t.RevocationKey()] = t
}

func (r *RevocationSet) List() []*Token {
	r.lk.RLock()
	defer r.lk.RUnlock()

	result := make([]*Token, 0, len(r.revoked))
	now := uint64(time.Now().UnixNano())
	for _, t := range r.revoked {
		if t.ExpireBefore(now) {
			continue
		}

		result = append(result, t)
	}

	return result
}

func (r *RevocationSet) gc(now uint64) {
	r.lk.Lock()
	defer r.lk.Unlock()

	for key, token := range r.revoked {
		if token.ExpireBefore(now) {
			delete(r.revoked, key)
		}
	}
}

func (t *Token) RevocationKey() string {
	switch {
	case t.Domain != nil:
		return t.Domain.RevocationKey()
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return ""
	}
}

func (t *DomainToken) RevocationKey() string {
	return fmt.Sprintf("%s#%s#%s", t.Issuer, t.Subject, string(t.Nonce))
}

func (t *DomainToken) Revoked(revoke *RevocationSet) bool {
	return revoke.Revoked(t.RevocationKey())
}

func (t *Token) SignatureData() ([]byte, error) {
	switch {
	case t.Domain != nil:
		return t.Domain.SignatureData()
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return nil, ErrBadToken
	}
}

func (t *DomainToken) SignatureData() ([]byte, error) {
	tCopy := *t
	tCopy.Signature = nil

	data, err := json.Marshal(&tCopy)
	if err != nil {
		return nil, fmt.Errorf("signature data: %w", err)
	}

	result := make([]byte, len(signaturePrefix)+len(data))
	copy(result, signaturePrefix)
	copy(result[len(signaturePrefix):], data)

	return result, nil
}

func (t *Token) Issuer() did.DID {
	switch {
	case t.Domain != nil:
		return t.Domain.Issuer
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return did.DID{}
	}
}

func (t *Token) Subject() did.DID {
	switch {
	case t.Domain != nil:
		return t.Domain.Subject
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return did.DID{}
	}
}

func (t *Token) Audience() did.DID {
	switch {
	case t.Domain != nil:
		return t.Domain.Audience
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return did.DID{}
	}
}

func (t *Token) Capability() []Capability {
	switch {
	case t.Domain != nil:
		return t.Domain.Capability
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return nil
	}
}

func (t *Token) Topic() []Capability {
	switch {
	case t.Domain != nil:
		return t.Domain.Topic
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return nil
	}
}

func (t *Token) Expire() uint64 {
	switch {
	case t.Domain != nil:
		return t.Domain.Expire
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return 0
	}
}

func (t *Token) Nonce() []byte {
	switch {
	case t.Domain != nil:
		return t.Domain.Nonce
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return nil // expired right after the unix big bang
	}
}

func (t *Token) Action() Action {
	switch {
	case t.Domain != nil:
		return t.Domain.Action
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return Action("")
	}
}

func (t *Token) Verify(trust did.TrustContext, now uint64, revoke *RevocationSet) error {
	return t.verify(trust, now, 0, revoke)
}

func (t *Token) verify(trust did.TrustContext, now, depth uint64, revoke *RevocationSet) error {
	switch {
	case t.Domain != nil:
		return t.Domain.verify(trust, now, depth, revoke)
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return ErrBadToken
	}
}

func (t *DomainToken) verify(trust did.TrustContext, now, depth uint64, revoke *RevocationSet) error {
	if t.ExpireBefore(now) {
		return ErrCapabilityExpired
	}

	if t.Action == Revoke {
		anchor, err := trust.GetAnchor(t.Issuer)
		if err != nil {
			return fmt.Errorf("verify: anchor: %w", err)
		}

		data, err := t.SignatureData()
		if err != nil {
			return fmt.Errorf("verify: signature data: %w", err)
		}

		if err := anchor.Verify(data, t.Signature); err != nil {
			return fmt.Errorf("verify: signature: %w", err)
		}

		return nil
	}

	if t.Depth > 0 && depth > t.Depth {
		return fmt.Errorf("max token depth exceeded: %w", ErrNotAuthorized)
	}

	if t.Revoked(revoke) {
		return fmt.Errorf("verify: token has been revoked: %w", ErrNotAuthorized)
	}

	if t.Chain != nil {
		if t.Chain.Action() != Delegate {
			return fmt.Errorf("verify: chain does not allow delegation: %w", ErrNotAuthorized)
		}

		if t.Chain.ExpireBefore(t.Expire) {
			return ErrCapabilityExpired
		}

		if err := t.Chain.verify(trust, now, depth+1, revoke); err != nil {
			return err
		}

		if !t.Issuer.Equal(t.Chain.Subject()) {
			return fmt.Errorf("verify: issuer/chain subject misnmatch: %w", ErrNotAuthorized)
		}

		needCapability := slices.Clone(t.Capability)
		for _, c := range t.Capability {
			if t.Chain.allowDelegation(t.Issuer, t.Audience, t.Topic, t.Expire, c) {
				needCapability = slices.DeleteFunc(needCapability, func(oc Capability) bool {
					return c == oc
				})
				if len(needCapability) == 0 {
					break
				}
			}
		}
		if len(needCapability) > 0 {
			return fmt.Errorf("verify: capabilities are not allowed by the chain: %w", ErrNotAuthorized)
		}
	}

	anchor, err := trust.GetAnchor(t.Issuer)
	if err != nil {
		return fmt.Errorf("verify: anchor: %w", err)
	}

	data, err := t.SignatureData()
	if err != nil {
		return fmt.Errorf("verify: signature data: %w", err)
	}

	if err := anchor.Verify(data, t.Signature); err != nil {
		return fmt.Errorf("verify: signature: %w", err)
	}

	return nil
}

func (t *Token) AllowAction(ot *Token) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.AllowAction(ot)
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) AllowAction(ot *Token) bool {
	if t.Action != Delegate {
		return false
	}

	if t.ExpireBefore(ot.Expire()) {
		return false
	}

	if !ot.Anchor(t.Subject) {
		return false
	}

	if t.Depth > 0 {
		depth, ok := ot.AnchorDepth(t.Subject)
		if ok && depth > t.Depth {
			return false
		}
	}

	if !t.Audience.Empty() && !t.Audience.Equal(ot.Audience()) {
		return false
	}

	for _, oc := range ot.Capability() {
		allow := false
		for _, c := range t.Capability {
			if c.Implies(oc) {
				allow = true
				break
			}
		}
		if !allow {
			return false
		}
	}

	for _, otherTopic := range ot.Topic() {
		allow := false
		for _, topic := range t.Topic {
			if topic.Implies(otherTopic) {
				allow = true
				break
			}
		}
		if !allow {
			return false
		}
	}

	return true
}

func (t *Token) Size() int {
	data, _ := t.SignatureData()
	return len(data)
}

func (t *Token) Subsumes(ot *Token) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.Subsumes(ot)
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) Subsumes(ot *Token) bool {
	if t.Issuer.Equal(ot.Issuer()) &&
		t.Subject.Equal(ot.Subject()) &&
		t.Audience.Equal(ot.Audience()) &&
		t.Expire >= ot.Expire() {
	loop:
		for _, oc := range ot.Capability() {
			for _, c := range t.Capability {
				if c.Implies(oc) {
					continue loop
				}
			}
			return false
		}
		return true
	}

	return false
}

func (t *Token) AllowInvocation(subject, audience did.DID, c Capability) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.AllowInvocation(subject, audience, c)
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) AllowInvocation(subject, audience did.DID, c Capability) bool {
	if t.Action != Invoke {
		return false
	}

	if !t.Subject.Equal(subject) {
		return false
	}

	if !t.Audience.Empty() && !t.Audience.Equal(audience) {
		return false
	}

	for _, granted := range t.Capability {
		if granted.Implies(c) {
			return true
		}
	}

	return false
}

func (t *Token) AllowBroadcast(subject did.DID, topic Capability, c Capability) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.AllowBroadcast(subject, topic, c)
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) AllowBroadcast(subject did.DID, topic Capability, c Capability) bool {
	if t.Action != Broadcast {
		return false
	}

	if !t.Subject.Equal(subject) {
		return false
	}

	if !t.Audience.Empty() {
		return false
	}

	allow := false
	for _, allowTopic := range t.Topic {
		if allowTopic.Implies(topic) {
			allow = true
			break
		}
	}

	if !allow {
		return false
	}

	for _, allowCap := range t.Capability {
		if allowCap.Implies(c) {
			return true
		}
	}

	return false
}

func (t *Token) AllowDelegation(action Action, issuer, audience did.DID, topics []Capability, expire uint64, c Capability) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.AllowDelegation(action, issuer, audience, topics, expire, c)

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) AllowDelegation(action Action, issuer, audience did.DID, topics []Capability, expire uint64, c Capability) bool {
	if action == Delegate {
		if !t.verifyDepth(2) {
			// certificate would be dead end with 1
			return false
		}
	} else {
		if !t.verifyDepth(1) {
			return false
		}
	}

	return t.allowDelegation(issuer, audience, topics, expire, c)
}

func (t *Token) allowDelegation(issuer, audience did.DID, topics []Capability, expire uint64, c Capability) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.allowDelegation(issuer, audience, topics, expire, c)

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) allowDelegation(issuer, audience did.DID, topics []Capability, expire uint64, c Capability) bool {
	if t.Action != Delegate {
		return false
	}

	if t.ExpireBefore(expire) {
		return false
	}

	if !t.Subject.Equal(issuer) {
		return false
	}

	if !t.Audience.Empty() && !t.Audience.Equal(audience) {
		return false
	}

	for _, topic := range topics {
		allow := false
		for _, myTopic := range t.Topic {
			if myTopic.Implies(topic) {
				allow = true
				break
			}
		}

		if !allow {
			return false
		}
	}

	for _, myCap := range t.Capability {
		if myCap.Implies(c) {
			return true
		}
	}

	return false
}

func (t *Token) verifyDepth(depth uint64) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.verifyDepth(depth)
	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) verifyDepth(depth uint64) bool {
	if t.Depth > 0 && depth > t.Depth {
		return false
	}

	if t.Chain != nil {
		return t.Chain.verifyDepth(depth + 1)
	}

	return true
}

func (t *Token) Delegate(provider did.Provider, subject, audience did.DID, topics []Capability, expire, depth uint64, c []Capability) (*Token, error) {
	switch {
	case t.Domain != nil:
		result, err := t.Domain.Delegate(provider, subject, audience, topics, expire, depth, c)
		if err != nil {
			return nil, fmt.Errorf("delegate invocation: %w", err)
		}

		return &Token{Domain: result}, nil

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return nil, ErrBadToken
	}
}

func (t *DomainToken) Delegate(provider did.Provider, subject, audience did.DID, topics []Capability, expire, depth uint64, c []Capability) (*DomainToken, error) {
	return t.delegate(Delegate, provider, subject, audience, topics, expire, depth, c)
}

func (t *DomainToken) delegate(action Action, provider did.Provider, subject, audience did.DID, topics []Capability, expire, depth uint64, c []Capability) (*DomainToken, error) {
	if t.Action != Delegate {
		return nil, ErrNotAuthorized
	}

	if action == Delegate {
		if !t.verifyDepth(2) {
			// certificate would be dead end with 1
			return nil, ErrNotAuthorized
		}
	} else {
		if !t.verifyDepth(1) {
			return nil, ErrNotAuthorized
		}
	}

	nonce := make([]byte, nonceLength)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	result := &DomainToken{
		Action:     action,
		Issuer:     provider.DID(),
		Subject:    subject,
		Audience:   audience,
		Topic:      topics,
		Capability: c,
		Nonce:      nonce,
		Expire:     expire,
		Depth:      depth,
		Chain:      &Token{Domain: t},
	}

	data, err := result.SignatureData()
	if err != nil {
		return nil, fmt.Errorf("delegate: %w", err)
	}

	sig, err := provider.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	result.Signature = sig
	return result, nil
}

func (t *Token) DelegateInvocation(provider did.Provider, subject, audience did.DID, expire uint64, c []Capability) (*Token, error) {
	switch {
	case t.Domain != nil:
		result, err := t.Domain.DelegateInvocation(provider, subject, audience, expire, c)
		if err != nil {
			return nil, fmt.Errorf("delegate invocation: %w", err)
		}

		return &Token{Domain: result}, nil

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return nil, ErrBadToken
	}
}

func (t *DomainToken) DelegateInvocation(provider did.Provider, subject, audience did.DID, expire uint64, c []Capability) (*DomainToken, error) {
	return t.delegate(Invoke, provider, subject, audience, nil, expire, 0, c)
}

func (t *Token) DelegateBroadcast(provider did.Provider, subject did.DID, topic Capability, expire uint64, c []Capability) (*Token, error) {
	switch {
	case t.Domain != nil:
		result, err := t.Domain.DelegateBroadcast(provider, subject, topic, expire, c)
		if err != nil {
			return nil, fmt.Errorf("delegate invocation: %w", err)
		}

		return &Token{Domain: result}, nil

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return nil, ErrBadToken
	}
}

func (t *DomainToken) DelegateBroadcast(provider did.Provider, subject did.DID, topic Capability, expire uint64, c []Capability) (*DomainToken, error) {
	return t.delegate(Broadcast, provider, subject, did.DID{}, []Capability{topic}, expire, 0, c)
}

func (t *Token) Anchor(anchor did.DID) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.Anchor(anchor)

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) Anchor(anchor did.DID) bool {
	if t.Issuer.Equal(anchor) {
		return true
	}

	if t.Chain != nil {
		return t.Chain.Anchor(anchor)
	}

	return false
}

func (t *Token) AnchorDepth(anchor did.DID) (uint64, bool) {
	switch {
	case t.Domain != nil:
		return t.Domain.AnchorDepth(anchor)

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return 0, false
	}
}

func (t *DomainToken) AnchorDepth(anchor did.DID) (depth uint64, have bool) {
	if t.Issuer.Equal(anchor) {
		have = true
		depth = 0
	}

	if t.Chain != nil {
		if chainDepth, chainHave := t.Chain.AnchorDepth(anchor); chainHave {
			have = true
			depth = chainDepth + 1
		}
	}

	return depth, have
}

func (t *Token) Expiry() uint64 {
	switch {
	case t.Domain != nil:
		return t.Domain.Expire

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return 0
	}
}

func (t *Token) Expired() bool {
	return t.ExpireBefore(uint64(time.Now().UnixNano()))
}

func (t *Token) ExpireBefore(deadline uint64) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.ExpireBefore(deadline)

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return true
	}
}

func (t *DomainToken) ExpireBefore(deadline uint64) bool {
	if deadline > t.Expire {
		return true
	}

	if t.Chain != nil {
		return t.Chain.ExpireBefore(deadline)
	}

	return false
}

func (t *Token) SelfSigned(origin did.DID) bool {
	switch {
	case t.Domain != nil:
		return t.Domain.SelfSigned(origin)

	case t.UCAN != nil:
		// TODO UCAN envelopes for BYO trust; followup
		fallthrough
	default:
		return false
	}
}

func (t *DomainToken) SelfSigned(origin did.DID) bool {
	if t.Chain != nil {
		return t.Chain.SelfSigned(origin)
	}

	return t.Issuer.Equal(origin)
}
