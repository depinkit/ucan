// Copyright 2024, Nunet
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package ucan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"gitlab.com/nunet/device-management-service/lib/crypto"
	"gitlab.com/nunet/device-management-service/lib/did"
)

const (
	maxCapabilitySize = 16384

	SelfSignNo SelfSignMode = iota
	SelfSignAlso
	SelfSignOnly
)

type SelfSignMode int

// CapabilityContext exposes the necessary functionalities to manage capabilities
// between different contexts. The work is based on UCAN but we're not
// strictly following its specs.
//
// TODO: explain side-chains
//
// TODO: explain anchor concept
//
// Some concepts:
//
// - Issuer: the one delegating/granting/invoking capabilities. Responsible for signing the token.
// - Audience: is the resource which the capabilities can be applied upon.
// - Subject:
//   - is the receiver, when delegating/granting capabilities
//   - is the invoker, when invoking capabilities
type CapabilityContext interface {
	// Name returns the context name
	Name() string

	// DID returns the context's controlling DID
	DID() did.DID

	// Trust returns the context's did trust context
	Trust() did.TrustContext

	// Consume ingests some or all of the provided capability tokens.
	// It'll only return an error if all provided capabilities were not ingested.
	Consume(origin did.DID, capToken []byte) error

	// Discard discards previously consumed capability tokens
	Discard(capTokens []byte)

	// Require ensures that at least one of the capabilities is delegated from
	// the subject to the audience, with an appropriate anchor
	// An empty list will mean that no capabilities are required and is vacuously
	// true.
	//
	// TODO (if necessary): create a RequireAll() since this method is basically a RequireAny()
	Require(anchor did.DID, subject crypto.ID, audience crypto.ID, require []Capability) error

	// RequireBroadcast ensures that at least one of the capabilities is delegated
	// to thes subject for the specified broadcast topics
	RequireBroadcast(origin did.DID, subject crypto.ID, topic string, require []Capability) error

	// Provide prepares the appropriate capability tokens to prove and delegate authority
	// to a subject for an audience.
	// - It delegates invocations to the subject with an audience and invoke capabilities
	// - It delegates the delegate capabilities to the target with audience the subject
	Provide(target did.DID, subject crypto.ID, audience crypto.ID, expire uint64, invoke []Capability, delegate []Capability) ([]byte, error)

	// ProvideBroadcast prepares the appropriate capability tokens to prove authority
	// to broadcast to a topic
	ProvideBroadcast(subject crypto.ID, topic string, expire uint64, broadcast []Capability) ([]byte, error)

	// AddRoots adds trust anchors
	//
	// require: regards to side-chains. It'll be used as one of the sources of truth when an entity is claiming having certain capabilities.
	//
	// provide: regards to the capabilities that we can delegate.
	AddRoots(trust []did.DID, require, provide TokenList, revoke TokenList) error

	// ListRoots list the current trust anchors
	ListRoots() ([]did.DID, TokenList, TokenList, TokenList)

	// RemoveRoots removes the specified trust anchors
	RemoveRoots(trust []did.DID, require, provide TokenList)

	// Delegate creates the appropriate delegation tokens anchored in our roots
	Delegate(subject, audience did.DID, topics []string, expire, depth uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error)

	// DelegateInvocation creates the appropriate invocation tokens anchored in anchor
	DelegateInvocation(target, subject, audience did.DID, expire uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error)

	// DelegateBroadcast creates the appropriate broadcast token anchored in our roots
	DelegateBroadcast(subject did.DID, topic string, expire uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error)

	// Grant creates the appropriate delegation tokens considering ourselves as the root
	Grant(action Action, subject, audience did.DID, topic []string, expire, depth uint64, provide []Capability) (TokenList, error)

	// Revoke creates a revocation for the provided token (token=(iss+sub+nonce))
	Revoke(*Token) (*Token, error)

	// Start starts a token garbage collector goroutine that clears expired tokens
	Start(gcInterval time.Duration)
	// Stop stops a previously started gc goroutine
	Stop()
}

type BasicCapabilityContext struct {
	mx       sync.Mutex
	name     string
	provider did.Provider
	trust    did.TrustContext
	roots    map[did.DID]struct{} // our root anchors of trust
	require  map[did.DID][]*Token // our acceptance side-roots
	provide  map[did.DID][]*Token // root capabilities -> tokens
	tokens   map[did.DID][]*Token // our context dependent capabilities; subject ->  tokens
	revoke   *RevocationSet       // revocation tokens

	stop func()
}

var _ CapabilityContext = (*BasicCapabilityContext)(nil)

func newCapabilityContext(name string, trust did.TrustContext, ctxDID did.DID, roots []did.DID, require, provide TokenList, revoke TokenList) (*BasicCapabilityContext, error) {
	ctx := &BasicCapabilityContext{
		name:    name,
		trust:   trust,
		roots:   make(map[did.DID]struct{}),
		require: make(map[did.DID][]*Token),
		provide: make(map[did.DID][]*Token),
		revoke:  &RevocationSet{revoked: make(map[string]*Token)},
		tokens:  make(map[did.DID][]*Token),
	}

	p, err := trust.GetProvider(ctxDID)
	if err != nil {
		return nil, fmt.Errorf("new capability context: %w", err)
	}

	ctx.provider = p

	if err := ctx.AddRoots(roots, require, provide, revoke); err != nil {
		return nil, fmt.Errorf("new capability context: %w", err)
	}

	return ctx, nil
}

func NewCapabilityContext(trust did.TrustContext, ctxDID did.DID, roots []did.DID, require, provide TokenList, revoke TokenList) (CapabilityContext, error) {
	return newCapabilityContext("dms", trust, ctxDID, roots, require, provide, revoke)
}

func NewCapabilityContextWithName(name string, trust did.TrustContext, ctxDID did.DID, roots []did.DID, require, provide TokenList, revoke TokenList) (CapabilityContext, error) {
	return newCapabilityContext(name, trust, ctxDID, roots, require, provide, revoke)
}

func (ctx *BasicCapabilityContext) Name() string {
	return ctx.name
}

func (ctx *BasicCapabilityContext) DID() did.DID {
	return ctx.provider.DID()
}

func (ctx *BasicCapabilityContext) Trust() did.TrustContext {
	return ctx.trust
}

func (ctx *BasicCapabilityContext) Start(gcInterval time.Duration) {
	if ctx.stop != nil {
		gcCtx, cancel := context.WithCancel(context.Background())
		go ctx.gc(gcCtx, gcInterval)
		ctx.stop = cancel
	}
}

func (ctx *BasicCapabilityContext) Stop() {
	if ctx.stop != nil {
		ctx.stop()
	}
}

func (ctx *BasicCapabilityContext) AddRoots(roots []did.DID, require, provide, revoke TokenList) error {
	ctx.addRoots(roots)

	now := uint64(time.Now().UnixNano())

	for _, t := range revoke.Tokens {
		if t.Action() != Revoke {
			return fmt.Errorf("verify token: %w", ErrBadToken)
		}
		if err := t.Verify(ctx.trust, now, ctx.revoke); err != nil {
			return fmt.Errorf("verify token: %w", err)
		}

		ctx.consumeRevokeToken(t)
	}

	for _, t := range require.Tokens {
		if err := t.Verify(ctx.trust, now, ctx.revoke); err != nil {
			return fmt.Errorf("verify token: %w", err)
		}

		ctx.consumeRequireToken(t)
	}

	for _, t := range provide.Tokens {
		if err := t.Verify(ctx.trust, now, ctx.revoke); err != nil {
			return fmt.Errorf("verify token: %w", err)
		}

		ctx.consumeProvideToken(t)
	}

	ctx.cleanUpTokens()

	return nil
}

func (ctx *BasicCapabilityContext) cleanUpTokens() {
	now := time.Now().UnixNano()
	for _, anchor := range ctx.getRequireAnchors() {
		tokenList := ctx.getRequireTokens(anchor)
		for i, t := range tokenList {
			if err := t.Verify(ctx.trust, uint64(now), ctx.revoke); err != nil {
				tokenList = append(tokenList[:i], tokenList[i+1:]...)
			}
		}
		ctx.require[anchor] = tokenList
	}

	for _, anchor := range ctx.getProvideAnchors() {
		tokenList := ctx.getProvideTokens(anchor)
		for i, t := range tokenList {
			if err := t.Verify(ctx.trust, uint64(now), ctx.revoke); err != nil {
				tokenList = append(tokenList[:i], tokenList[i+1:]...)
			}
		}
		ctx.provide[anchor] = tokenList
	}

	for subject, tokenList := range ctx.tokens {
		for i, t := range tokenList {
			if err := t.Verify(ctx.trust, uint64(now), ctx.revoke); err != nil {
				tokenList = append(tokenList[:i], tokenList[i+1:]...)
			}
		}
		ctx.tokens[subject] = tokenList
	}
}

func (ctx *BasicCapabilityContext) ListRoots() ([]did.DID, TokenList, TokenList, TokenList) {
	var require, provide, revoke []*Token

	roots := ctx.getRoots()

	for _, anchor := range ctx.getRequireAnchors() {
		tokenList := ctx.getRequireTokens(anchor)
		require = append(require, tokenList...)
	}

	for _, anchor := range ctx.getProvideAnchors() {
		tokenList := ctx.getProvideTokens(anchor)
		provide = append(provide, tokenList...)
	}

	revoke = ctx.revoke.List()
	return roots, TokenList{Tokens: require}, TokenList{Tokens: provide}, TokenList{Tokens: revoke}
}

func (ctx *BasicCapabilityContext) RemoveRoots(trust []did.DID, require, provide TokenList) {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	for _, root := range trust {
		delete(ctx.roots, root)
	}

	for _, t := range require.Tokens {
		tokenList, ok := ctx.require[t.Issuer()]
		if ok {
			tokenList = slices.DeleteFunc(tokenList, func(ot *Token) bool {
				return bytes.Equal(t.Nonce(), ot.Nonce())
			})
			if len(tokenList) > 0 {
				ctx.require[t.Issuer()] = tokenList
			} else {
				delete(ctx.require, t.Issuer())
			}
		}
	}

	for _, t := range provide.Tokens {
		tokenList, ok := ctx.provide[t.Issuer()]
		if ok {
			tokenList = slices.DeleteFunc(tokenList, func(ot *Token) bool {
				return bytes.Equal(t.Nonce(), ot.Nonce())
			})
			if len(tokenList) > 0 {
				ctx.provide[t.Issuer()] = tokenList
			} else {
				delete(ctx.provide, t.Issuer())
			}
		}
	}
}

func (ctx *BasicCapabilityContext) Grant(action Action, subject, audience did.DID, topics []string, expire, depth uint64, provide []Capability) (TokenList, error) {
	nonce := make([]byte, nonceLength)
	_, err := rand.Read(nonce)
	if err != nil {
		return TokenList{}, fmt.Errorf("nonce: %w", err)
	}

	topicCap := make([]Capability, 0, len(topics))
	for _, topic := range topics {
		topicCap = append(topicCap, Capability(topic))
	}

	result := &DomainToken{
		Issuer:     ctx.DID(),
		Subject:    subject,
		Audience:   audience,
		Action:     action,
		Topic:      topicCap,
		Capability: provide,
		Nonce:      nonce,
		Expire:     expire,
		Depth:      depth,
	}

	data, err := result.SignatureData()
	if err != nil {
		return TokenList{}, fmt.Errorf("grant: %w", err)
	}

	sig, err := ctx.provider.Sign(data)
	if err != nil {
		return TokenList{}, fmt.Errorf("sign: %w", err)
	}

	result.Signature = sig
	return TokenList{Tokens: []*Token{{Domain: result}}}, nil
}

func (ctx *BasicCapabilityContext) Revoke(token *Token) (*Token, error) {
	if !ctx.DID().Equal(token.Issuer()) {
		return nil, ErrNotAuthorized
	}

	revocationToken := &DomainToken{
		Action:  Revoke,
		Issuer:  token.Issuer(),
		Subject: token.Subject(),
		Nonce:   token.Nonce(),
		Expire:  token.Expiry(),
	}

	data, err := revocationToken.SignatureData()
	if err != nil {
		return nil, fmt.Errorf("revoke: %w", err)
	}

	sig, err := ctx.provider.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	revocationToken.Signature = sig
	return &Token{Domain: revocationToken}, nil
}

func (ctx *BasicCapabilityContext) Delegate(subject, audience did.DID, topics []string, expire, depth uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error) {
	if len(provide) == 0 {
		return TokenList{}, nil
	}

	topicCap := make([]Capability, 0, len(topics))
	for _, topic := range topics {
		topicCap = append(topicCap, Capability(topic))
	}

	var result []*Token

	if selfSign == SelfSignOnly {
		goto selfsign
	}

	for _, trustAnchor := range ctx.getProvideAnchors() {
		tokenList := ctx.getProvideTokens(trustAnchor)
		if len(tokenList) == 0 {
			continue
		}

		for _, t := range tokenList {
			var providing []Capability
			definitiveExpire := expire

			if definitiveExpire == 0 {
				definitiveExpire = t.Expire()
			}

			for _, c := range provide {
				if t.Anchor(trustAnchor) && t.AllowDelegation(Delegate, ctx.DID(), audience, topicCap, definitiveExpire, c) {
					providing = append(providing, c)
				}
			}

			if len(providing) == 0 {
				continue
			}

			if len(provide) > len(providing) {
				// attempt to widen caps
				continue
			}

			token, err := t.Delegate(ctx.provider, subject, audience, topicCap, definitiveExpire, depth, providing)
			if err != nil {
				log.Debugf("error delegating %s to %s: %s", providing, subject, err)
				continue
			}

			result = append(result, token)
		}
	}

	if selfSign == SelfSignNo {
		if len(result) == 0 {
			return TokenList{}, ErrNotAuthorized
		}

		return TokenList{Tokens: result}, nil
	}

selfsign:
	tokens, err := ctx.Grant(Delegate, subject, audience, topics, expire, depth, provide)
	if err != nil {
		return TokenList{}, fmt.Errorf("error granting invocation: %w", err)
	}
	result = append(result, tokens.Tokens...)

	return TokenList{Tokens: result}, nil
}

func (ctx *BasicCapabilityContext) DelegateInvocation(target, subject, audience did.DID, expire uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error) {
	if len(provide) == 0 {
		return TokenList{}, nil
	}

	var result []*Token

	// first get tokens we have about ourselves and see if any allows delegation to
	// the subject for the audience
	tokenList := ctx.getSubjectTokens(ctx.DID())
	tokens := ctx.delegateInvocation(tokenList, target, subject, audience, expire, provide)
	result = append(result, tokens...)

	if selfSign == SelfSignOnly {
		goto selfsign
	}

	// then we issue tokens chained on our provide anchors as appropriate
	for _, trustAnchor := range ctx.getProvideAnchors() {
		tokenList := ctx.getProvideTokens(trustAnchor)
		tokens := ctx.delegateInvocation(tokenList, trustAnchor, subject, audience, expire, provide)
		result = append(result, tokens...)
	}

	if selfSign == SelfSignNo {
		if len(result) == 0 {
			return TokenList{}, ErrNotAuthorized
		}

		return TokenList{Tokens: result}, nil
	}

selfsign:
	selfTokens, err := ctx.Grant(Invoke, subject, audience, nil, expire, 0, provide)
	if err != nil {
		return TokenList{}, fmt.Errorf("error granting invocation: %w", err)
	}
	result = append(result, selfTokens.Tokens...)

	return TokenList{Tokens: result}, nil
}

func (ctx *BasicCapabilityContext) delegateInvocation(tokenList []*Token, anchor, subject, audience did.DID, expire uint64, provide []Capability) []*Token {
	var result []*Token //nolint
	for _, t := range tokenList {
		var providing []Capability
		for _, c := range provide {
			if t.Anchor(anchor) && t.AllowDelegation(Invoke, ctx.DID(), audience, nil, expire, c) {
				providing = append(providing, c)
			}
		}

		if len(providing) == 0 {
			continue
		}

		if len(provide) > len(providing) {
			// attempt to widen caps
			continue
		}

		token, err := t.DelegateInvocation(ctx.provider, subject, audience, expire, providing)
		if err != nil {
			log.Debugf("error delegating invocation %s to %s: %s", providing, subject, err)
			continue
		}

		result = append(result, token)
	}

	return result
}

func (ctx *BasicCapabilityContext) DelegateBroadcast(subject did.DID, topic string, expire uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error) {
	if len(provide) == 0 {
		return TokenList{}, nil
	}

	var result []*Token

	if selfSign == SelfSignOnly {
		goto selfsign
	}

	// first we issue tokens chained on our provide anchors as appropriate
	for _, trustAnchor := range ctx.getProvideAnchors() {
		tokenList := ctx.getProvideTokens(trustAnchor)
		tokens := ctx.delegateBroadcast(tokenList, trustAnchor, subject, topic, expire, provide)
		result = append(result, tokens...)
	}

	if selfSign == SelfSignNo {
		if len(result) == 0 {
			return TokenList{}, ErrNotAuthorized
		}
		return TokenList{Tokens: result}, nil
	}

selfsign:
	selfTokens, err := ctx.Grant(Broadcast, subject, did.DID{}, []string{topic}, expire, 0, provide)
	if err != nil {
		return TokenList{}, fmt.Errorf("error granting broadcast: %w", err)
	}
	result = append(result, selfTokens.Tokens...)

	return TokenList{Tokens: result}, nil
}

func (ctx *BasicCapabilityContext) delegateBroadcast(tokenList []*Token, anchor did.DID, subject did.DID, topic string, expire uint64, provide []Capability) []*Token {
	topicCap := Capability(topic)
	var result []*Token //nolint
	for _, t := range tokenList {
		var providing []Capability
		for _, c := range provide {
			if t.Anchor(anchor) && t.AllowDelegation(Broadcast, ctx.DID(), did.DID{}, []Capability{topicCap}, expire, c) {
				providing = append(providing, c)
			}
		}

		if len(providing) == 0 {
			continue
		}

		if len(provide) > len(providing) {
			// attempt to widen caps
			continue
		}

		token, err := t.DelegateBroadcast(ctx.provider, subject, topicCap, expire, providing)
		if err != nil {
			log.Debugf("error delegating invocation %s to %s: %s", providing, subject, err)
			continue
		}

		result = append(result, token)
	}

	return result
}

func (ctx *BasicCapabilityContext) Consume(origin did.DID, capToken []byte) error {
	if len(capToken) > maxCapabilitySize {
		return ErrTooBig
	}

	var tokens TokenList
	if err := json.Unmarshal(capToken, &tokens); err != nil {
		return fmt.Errorf("unmarshaling payload: %w", err)
	}

	rootAnchors := ctx.getRoots()
	requireAnchors := ctx.getRequireAnchors()
	now := uint64(time.Now().UnixNano())

	for _, t := range tokens.Tokens {
		if t.Anchor(ctx.DID()) {
			goto verify
		}

		if t.Anchor(origin) {
			goto verify
		}

		for _, anchor := range rootAnchors {
			if t.Anchor(anchor) {
				goto verify
			}
		}

		for _, anchor := range requireAnchors {
			for _, rt := range ctx.getRequireTokens(anchor) {
				if rt.AllowAction(t) {
					goto verify
				}
			}
		}

		log.Debugf("ignoring token %+v", *t)
		continue

	verify:
		if err := t.Verify(ctx.trust, now, ctx.revoke); err != nil {
			log.Warnf("failed to verify token issued by %s: %s", t.Issuer(), err)
			continue
		}

		ctx.consumeSubjectToken(t)
	}

	return nil
}

func (ctx *BasicCapabilityContext) Discard(capTokens []byte) {
	var tokens TokenList
	if err := json.Unmarshal(capTokens, &tokens); err != nil {
		return
	}

	ctx.discardTokens(tokens.Tokens)
}

func (ctx *BasicCapabilityContext) consumeAnchorToken(getf func() []*Token, setf func(result []*Token), t *Token) {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	tokenList := getf()
	result := make([]*Token, 0, len(tokenList)+1)

	for _, ot := range tokenList {
		if ot.Subsumes(t) {
			return
		}

		if t.Subsumes(ot) {
			continue
		}

		result = append(result, ot)
	}
	result = append(result, t)

	setf(result)
}

func (ctx *BasicCapabilityContext) consumeRequireToken(t *Token) {
	ctx.consumeAnchorToken(
		func() []*Token { return ctx.require[t.Issuer()] },
		func(result []*Token) {
			ctx.require[t.Issuer()] = result
		},
		t,
	)
}

func (ctx *BasicCapabilityContext) consumeProvideToken(t *Token) {
	ctx.consumeAnchorToken(
		func() []*Token { return ctx.provide[t.Issuer()] },
		func(result []*Token) {
			ctx.provide[t.Issuer()] = result
		},
		t,
	)
}

func (ctx *BasicCapabilityContext) consumeSubjectToken(t *Token) {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	subject := t.Subject()

	tokenList := ctx.tokens[subject]
	tokenList = append(tokenList, t)
	ctx.tokens[subject] = tokenList
}

func (ctx *BasicCapabilityContext) consumeRevokeToken(t *Token) {
	ctx.revoke.Revoke(t)
}

func (ctx *BasicCapabilityContext) Require(anchor did.DID, subject crypto.ID, audience crypto.ID, require []Capability) error {
	if len(require) == 0 {
		return fmt.Errorf("no capabilities: %w", ErrNotAuthorized)
	}

	subjectDID, err := did.FromID(subject)
	if err != nil {
		return fmt.Errorf("DID for subject: %w", err)
	}

	audienceDID, err := did.FromID(audience)
	if err != nil {
		return fmt.Errorf("DID for audience: %w", err)
	}

	tokenList := ctx.getSubjectTokens(subjectDID)
	roots := ctx.getRoots()
	requireAnchors := ctx.getRequireAnchors()

	for _, t := range tokenList {
		for _, c := range require {
			if t.Anchor(anchor) && t.AllowInvocation(subjectDID, audienceDID, c) {
				return nil
			}

			for _, anchor := range roots {
				if t.Anchor(anchor) && t.AllowInvocation(subjectDID, audienceDID, c) {
					return nil
				}
			}

			for _, anchor := range requireAnchors {
				for _, rt := range ctx.getRequireTokens(anchor) {
					if rt.AllowAction(t) && t.AllowInvocation(subjectDID, audienceDID, c) {
						return nil
					}
				}
			}
		}
	}

	return ErrNotAuthorized
}

func (ctx *BasicCapabilityContext) RequireBroadcast(anchor did.DID, subject crypto.ID, topic string, require []Capability) error {
	if len(require) == 0 {
		return fmt.Errorf("no capabilities: %w", ErrNotAuthorized)
	}

	subjectDID, err := did.FromID(subject)
	if err != nil {
		return fmt.Errorf("DID for subject: %w", err)
	}

	tokenList := ctx.getSubjectTokens(subjectDID)
	roots := ctx.getRoots()
	requireAnchors := ctx.getRequireAnchors()
	topicCap := Capability(topic)

	for _, t := range tokenList {
		for _, c := range require {
			if t.Anchor(anchor) && t.AllowBroadcast(subjectDID, topicCap, c) {
				return nil
			}

			for _, anchor := range roots {
				if t.Anchor(anchor) && t.AllowBroadcast(subjectDID, topicCap, c) {
					return nil
				}
			}

			for _, anchor := range requireAnchors {
				for _, rt := range ctx.getRequireTokens(anchor) {
					if rt.AllowAction(t) && t.AllowBroadcast(subjectDID, topicCap, c) {
						return nil
					}
				}
			}
		}
	}

	return ErrNotAuthorized
}

func (ctx *BasicCapabilityContext) Provide(target did.DID, subject crypto.ID, audience crypto.ID, expire uint64, invoke []Capability, provide []Capability) ([]byte, error) {
	if len(invoke) == 0 && len(provide) == 0 {
		return nil, fmt.Errorf("no capabilities: %w", ErrNotAuthorized)
	}

	subjectDID, err := did.FromID(subject)
	if err != nil {
		return nil, fmt.Errorf("DID for subject: %w", err)
	}

	audienceDID, err := did.FromID(audience)
	if err != nil {
		return nil, fmt.Errorf("DID for audience: %w", err)
	}

	var result []*Token
	var invocation, delegation TokenList

	if len(invoke) == 0 {
		return nil, fmt.Errorf("no invocation capabilities: %w", ErrNotAuthorized)
	}

	invocation, err = ctx.DelegateInvocation(target, subjectDID, audienceDID, expire, invoke, SelfSignAlso)
	if err != nil {
		return nil, fmt.Errorf("cannot provide invocation tokens: %w", err)
	}

	if len(invocation.Tokens) == 0 {
		return nil, fmt.Errorf("cannot provide the necessary invocation tokens: %w", ErrNotAuthorized)
	}

	result = append(result, invocation.Tokens...)

	if len(provide) == 0 {
		goto marshal
	}

	delegation, err = ctx.Delegate(target, subjectDID, nil, expire, 1, provide, SelfSignOnly)
	if err != nil {
		return nil, fmt.Errorf("cannot provide delegation tokens: %w", err)
	}

	if len(delegation.Tokens) == 0 {
		return nil, fmt.Errorf("cannot provide the necessary delegation tokens: %w", ErrNotAuthorized)
	}

	result = append(result, delegation.Tokens...)

marshal:
	payload := TokenList{Tokens: result}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	return data, nil
}

func (ctx *BasicCapabilityContext) ProvideBroadcast(subject crypto.ID, topic string, expire uint64, provide []Capability) ([]byte, error) {
	if len(provide) == 0 {
		return nil, fmt.Errorf("no capabilities: %w", ErrNotAuthorized)
	}

	subjectDID, err := did.FromID(subject)
	if err != nil {
		return nil, fmt.Errorf("DID for subject: %w", err)
	}

	broadcast, err := ctx.DelegateBroadcast(subjectDID, topic, expire, provide, SelfSignAlso)
	if err != nil {
		return nil, fmt.Errorf("cannot provide broadcast tokens: %w", err)
	}

	if len(broadcast.Tokens) == 0 {
		return nil, fmt.Errorf("cannot provide the necessary broadcast tokens: %w", ErrNotAuthorized)
	}

	data, err := json.Marshal(broadcast)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	return data, nil
}

func (ctx *BasicCapabilityContext) getRoots() []did.DID {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	result := make([]did.DID, 0, len(ctx.roots))
	for anchor := range ctx.roots {
		result = append(result, anchor)
	}

	return result
}

func (ctx *BasicCapabilityContext) addRoots(anchors []did.DID) {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	for _, anchor := range anchors {
		ctx.roots[anchor] = struct{}{}
	}
}

func (ctx *BasicCapabilityContext) getRequireAnchors() []did.DID {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	result := make([]did.DID, 0, len(ctx.require))
	for anchor := range ctx.require {
		result = append(result, anchor)
	}

	return result
}

func (ctx *BasicCapabilityContext) getProvideAnchors() []did.DID {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	result := make([]did.DID, 0, len(ctx.provide))
	for anchor := range ctx.provide {
		result = append(result, anchor)
	}

	return result
}

func (ctx *BasicCapabilityContext) getTokens(getf func() ([]*Token, bool), setf func([]*Token)) []*Token {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	tokenList, ok := getf()
	if !ok {
		return nil
	}

	// filter expired
	now := uint64(time.Now().UnixNano())
	result := slices.DeleteFunc(slices.Clone(tokenList), func(t *Token) bool {
		return t.ExpireBefore(now)
	})

	setf(result)
	return result
}

func (ctx *BasicCapabilityContext) getRequireTokens(anchor did.DID) []*Token {
	return ctx.getTokens(
		func() ([]*Token, bool) { result, ok := ctx.require[anchor]; return result, ok },
		func(result []*Token) { ctx.require[anchor] = result },
	)
}

func (ctx *BasicCapabilityContext) getProvideTokens(anchor did.DID) []*Token {
	return ctx.getTokens(
		func() ([]*Token, bool) { result, ok := ctx.provide[anchor]; return result, ok },
		func(result []*Token) { ctx.provide[anchor] = result },
	)
}

func (ctx *BasicCapabilityContext) getSubjectTokens(subject did.DID) []*Token {
	return ctx.getTokens(
		func() ([]*Token, bool) { result, ok := ctx.tokens[subject]; return result, ok },
		func(result []*Token) { ctx.tokens[subject] = result },
	)
}

func (ctx *BasicCapabilityContext) discardTokens(tokens []*Token) {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	for _, t := range tokens {
		subject := t.Subject()
		subjectTokens := slices.DeleteFunc(slices.Clone(ctx.tokens[subject]), func(ot *Token) bool {
			return t.Issuer() == ot.Issuer() && bytes.Equal(t.Nonce(), ot.Nonce())
		})

		if len(subjectTokens) == 0 {
			delete(ctx.tokens, subject)
		} else {
			ctx.tokens[subject] = subjectTokens
		}
	}
}

func (ctx *BasicCapabilityContext) gc(gcCtx context.Context, gcInterval time.Duration) {
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx.gcTokens()
		case <-gcCtx.Done():
			return
		}
	}
}

func (ctx *BasicCapabilityContext) gcTokens() {
	ctx.mx.Lock()
	defer ctx.mx.Unlock()

	now := uint64(time.Now().UnixNano())

	for anchor, tokens := range ctx.require {
		tokens = slices.DeleteFunc(slices.Clone(tokens), func(t *Token) bool {
			return t.ExpireBefore(now)
		})
		if len(tokens) == 0 {
			delete(ctx.require, anchor)
		} else {
			ctx.require[anchor] = tokens
		}
	}

	for anchor, tokens := range ctx.provide {
		tokens = slices.DeleteFunc(slices.Clone(tokens), func(t *Token) bool {
			return t.ExpireBefore(now)
		})
		if len(tokens) == 0 {
			delete(ctx.provide, anchor)
		} else {
			ctx.provide[anchor] = tokens
		}
	}

	ctx.revoke.gc(now)

	for subject, tokens := range ctx.tokens {
		tokens = slices.DeleteFunc(slices.Clone(tokens), func(t *Token) bool {
			return t.ExpireBefore(now)
		})
		if len(tokens) == 0 {
			delete(ctx.tokens, subject)
		} else {
			ctx.tokens[subject] = tokens
		}
	}
}
