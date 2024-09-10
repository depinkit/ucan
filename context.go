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

type CapabilityContext interface {
	// DID returns the context's controlling DID
	DID() did.DID

	// Trust returns the context's did trust context
	Trust() did.TrustContext

	// Consume ingests the provided capability tokens
	Consume(origin did.DID, cap []byte) error

	// Discard discards previously consumed capability tokens
	Discard(cap []byte)

	// Require ensures that at least one of the capabilities is delegated from
	// the subject to the audience, with an appropriate anchor
	// An empty list will mean that no capabilities are required and is vacuously
	// true.
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

	// AddRoots adds trust anchors and/or capabilities derived from our anchors
	AddRoots(trust []did.DID, require, provide TokenList) error

	// Delegate creates the appropriate delegation tokens anchored in our roots
	Delegate(subject, audience did.DID, topics []string, expire, depth uint64, cap []Capability, selfSign SelfSignMode) (TokenList, error)

	// DelegateInvocation creates the appropriate invocation tokens anchored in anchor
	DelegateInvocation(target, subject, audience did.DID, expire uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error)

	// DelegateBroadcast creates the appropriate broadcast token anchored in our roots
	DelegateBroadcast(subject did.DID, topic string, expire uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error)

	// Grant creates the appropriate delegation tokens considering ourselves as the root
	Grant(action Action, subject, audience did.DID, topic []string, expire, depth uint64, provide []Capability) (TokenList, error)

	// Start starts a token garbage collector goroutine that clears expired tokens
	Start(gcInterval time.Duration)
	// Stop stops a previously started gc goroutine
	Stop()
}

type BasicCapabilityContext struct {
	mx       sync.Mutex
	provider did.Provider
	trust    did.TrustContext
	roots    map[did.DID]struct{} // our root anchors of trust
	require  map[did.DID][]*Token // our acceptance side-roots
	provide  map[did.DID][]*Token // root capabilities -> tokens
	tokens   map[did.DID][]*Token // our context dependent capabilities; subject ->  tokens

	stop func()
}

var _ CapabilityContext = (*BasicCapabilityContext)(nil)

func NewCapabilityContext(trust did.TrustContext, ctxDID did.DID, roots []did.DID, require, provide TokenList) (CapabilityContext, error) {
	ctx := &BasicCapabilityContext{
		trust:   trust,
		roots:   make(map[did.DID]struct{}),
		require: make(map[did.DID][]*Token),
		provide: make(map[did.DID][]*Token),
		tokens:  make(map[did.DID][]*Token),
	}

	p, err := trust.GetProvider(ctxDID)
	if err != nil {
		return nil, fmt.Errorf("new capability context: %w", err)
	}

	ctx.provider = p

	if err := ctx.AddRoots(roots, require, provide); err != nil {
		return nil, fmt.Errorf("new capability context: %w", err)
	}

	return ctx, nil
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

func (ctx *BasicCapabilityContext) AddRoots(roots []did.DID, require, provide TokenList) error {
	ctx.addRoots(roots)

	now := uint64(time.Now().UnixNano())
	for _, t := range require.Tokens {
		if err := t.Verify(ctx.trust, now); err != nil {
			return fmt.Errorf("verify token: %w", err)
		}

		ctx.consumeRequireToken(t)
	}

	for _, t := range provide.Tokens {
		if err := t.Verify(ctx.trust, now); err != nil {
			return fmt.Errorf("verify token: %w", err)
		}

		ctx.consumeProvideToken(t)
	}

	return nil
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

	result := &DMSToken{
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
	return TokenList{Tokens: []*Token{{DMS: result}}}, nil
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
			for _, c := range provide {
				if t.Anchor(trustAnchor) && t.AllowDelegation(Delegate, ctx.DID(), audience, topicCap, expire, c) {
					providing = append(providing, c)
				}
			}

			if len(providing) == 0 {
				continue
			}

			token, err := t.Delegate(ctx.provider, subject, audience, topicCap, expire, depth, providing)
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

		token, err := t.DelegateBroadcast(ctx.provider, subject, topicCap, expire, providing)
		if err != nil {
			log.Debugf("error delegating invocation %s to %s: %s", providing, subject, err)
			continue
		}

		result = append(result, token)
	}

	return result
}

func (ctx *BasicCapabilityContext) Consume(origin did.DID, data []byte) error {
	if len(data) > maxCapabilitySize {
		return ErrTooBig
	}

	var tokens TokenList
	if err := json.Unmarshal(data, &tokens); err != nil {
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

		continue

	verify:
		if err := t.Verify(ctx.trust, now); err != nil {
			log.Warnf("failed to verify token issued by %s: %s", t.Issuer(), err)
			continue
		}

		ctx.consumeSubjectToken(t)
	}

	return nil
}

func (ctx *BasicCapabilityContext) Discard(data []byte) {
	var tokens TokenList
	if err := json.Unmarshal(data, &tokens); err != nil {
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

func (ctx *BasicCapabilityContext) Require(anchor did.DID, subject crypto.ID, audience crypto.ID, cap []Capability) error {
	if len(cap) == 0 {
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
		for _, c := range cap {
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
