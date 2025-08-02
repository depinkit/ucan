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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"gitlab.com/nunet/device-management-service/lib/did"
)

// Note: for adversarial tests, we first check the valid scenario
// then we check the adversarial scenarion. Otherwise, we may have
// false positives

func TestBadSignature(t *testing.T) {
	t.Parallel()
	// `Consume()` method will not return an error when bad signature
	// but it won't add the invalid token to the context
	t.Run("bad signature when consuming", func(t *testing.T) {
		t.Parallel()
		root := makeCapabilityContext(t)
		bob := makeActorCapabilityContext(t, root, Capability("/test/invoke"))
		alice := makeActorCapabilityContext(t, root, Capability("/test/invoke"))

		bobID := makeActorIDFromDID(t, bob.DID())
		aliceID := makeActorIDFromDID(t, alice.DID())

		actorCap, err := bob.Provide(
			alice.DID(),
			bobID,
			aliceID,
			makeExpiry(30*time.Second),
			[]Capability{Capability("/test/invoke")},
			[]Capability{Capability("/test/reply")},
		)
		require.NoError(t, err, "provide")

		// VALID scenario
		err = alice.Consume(bob.DID(), actorCap)
		require.NoError(t, err, "consume")

		err = alice.Require(alice.DID(), bobID, aliceID, []Capability{Capability("/test/invoke")})
		require.NoError(t, err, "require")

		// ADVERSARIAL SCENARIO
		// Invalid token: tamper signature
		alice.Discard(actorCap) // first we have to discard the valid token consumed

		var tokens TokenList
		err = json.Unmarshal(actorCap, &tokens)
		require.NoError(t, err, "unmarshal actorCap")

		// Tamper tokens's signatures
		for _, token := range tokens.Tokens {
			if token.Domain != nil {
				token.Domain.Signature = []byte("invalid signature")
			}
		}
		tamperedCap, err := json.Marshal(tokens)
		require.NoError(t, err, "marshal tampered cap")

		// Invalid tokens are ignored when consuming
		err = alice.Consume(bob.DID(), tamperedCap)
		require.NoError(t, err, "consume")

		// try to require
		err = alice.Require(alice.DID(), bobID, aliceID, []Capability{Capability("/test/invoke")})
		require.Error(t, err, "require")
	})

	// `AddRoots()` method should return an error when bad signatur, TokenList{}e
	t.Run("bad signature when adding roots with require or provide", func(t *testing.T) {
		t.Parallel()
		bobRoot := makeCapabilityContext(t)
		aliceRoot := makeCapabilityContext(t)
		bob := makeActorCapabilityContext(t, bobRoot, Capability("/test/invoke"))
		alice := makeActorCapabilityContext(t, aliceRoot)

		// Use Grant() to get a token list
		tokenList, err := bob.Grant(
			Delegate,
			bob.DID(),
			alice.DID(),
			[]string{},
			makeExpiry(30*time.Second),
			1,
			[]Capability{Capability("/test/invoke")},
		)
		require.NoError(t, err, "grant")

		// VALID scenario
		err = alice.AddRoots(nil, tokenList, TokenList{}, TokenList{})
		require.NoError(t, err)

		err = alice.AddRoots(nil, tokenList, TokenList{}, TokenList{})
		require.NoError(t, err)

		// ADVERSARIAL scenario
		// Tamper with the signature of the tokens
		for _, token := range tokenList.Tokens {
			if token.Domain != nil {
				token.Domain.Signature = []byte("invalid signature")
			}
		}

		// Try to use AddRoots() having tokens for require
		err = alice.AddRoots(nil, tokenList, TokenList{}, TokenList{})
		require.Error(t, err, "AddRoots should fail with tampered signature in require tokens")
		require.ErrorIs(t, err, did.ErrInvalidSignature)

		// Try to use AddRoots() having tokens for provide
		err = alice.AddRoots(nil, TokenList{}, tokenList, TokenList{})
		require.Error(t, err, "AddRoots should fail with tampered signature in provide tokens")
		require.ErrorIs(t, err, did.ErrInvalidSignature)
	})
}

// TestChangeAudience expects an error when a third actor (Joe) attempts to change
// the audience to itself of tokens provided by Bob which the audience is Alice.
func TestChangeAudience(t *testing.T) {
	t.Parallel()
	root := makeCapabilityContext(t)
	bob := makeActorCapabilityContext(t, root, Capability("/test/invoke"))
	alice := makeActorCapabilityContext(t, root)
	joe := makeActorCapabilityContext(t, root)

	bobID := makeActorID(t)
	aliceID := makeActorID(t)
	joeID := makeActorID(t)

	actorCap, err := bob.Provide(
		alice.DID(),
		bobID,
		aliceID,
		makeExpiry(30*time.Second),
		[]Capability{Capability("/test/invoke")},
		[]Capability{Capability("/test/reply")},
	)
	require.NoError(t, err, "provide")

	// VALID scenario: alice succeed on require but not joe
	err = alice.Consume(bob.DID(), actorCap)
	require.NoError(t, err, "alice consumes")

	err = alice.Require(alice.DID(), bobID, aliceID, []Capability{Capability("/test/invoke")})
	require.NoError(t, err, "alice requires")

	err = joe.Consume(bob.DID(), actorCap)
	require.NoError(t, err, "joe consumes")

	err = joe.Require(joe.DID(), bobID, joeID, []Capability{Capability("/test/invoke")})
	require.Error(t, err, "joe requires")
	require.ErrorIs(t, err, ErrNotAuthorized)

	// Simulate Joe intercepting the actorCap
	interceptedCap := actorCap

	// Joe attempts to modify the audience in the intercepted capability
	var tokens TokenList
	err = json.Unmarshal(interceptedCap, &tokens)
	require.NoError(t, err, "unmarshal intercepted cap")

	for _, token := range tokens.Tokens {
		if token.Domain != nil {
			token.Domain.Audience = joe.DID()
		}
	}

	modifiedCap, err := json.Marshal(tokens)
	require.NoError(t, err, "marshal modified cap")

	err = joe.Consume(bob.DID(), modifiedCap)
	require.NoError(t, err, "consume modified cap")

	// Joe attempts to require the capability with itself as the audience
	err = joe.Require(
		joe.DID(),
		bobID,
		joeID,
		[]Capability{Capability("/test/invoke")},
	)
	require.Error(t, err, "require modified cap")
	require.ErrorIs(t, err, ErrNotAuthorized)
}

// TestWidenCaps expects an error when trying to widen capabilities when creating delegation tokens
func TestWidenCaps(t *testing.T) {
	bobRoot := makeCapabilityContext(t)
	aliceRoot := makeCapabilityContext(t)
	bob := makeActorCapabilityContext(t, bobRoot, Capability("/test/invoke"))
	alice := makeActorCapabilityContext(t, aliceRoot)
	topic := "/test/nunet"

	t.Run("widen caps trying to delegate", func(t *testing.T) {
		// VALID scenario
		_, err := bob.Delegate(
			alice.DID(),
			alice.DID(),
			[]string{},
			makeExpiry(30*time.Second),
			10,
			[]Capability{Capability("/test/invoke")},
			SelfSignNo,
		)
		require.NoError(t, err)

		// ADVERSARIAL scenario
		_, err = bob.Delegate(
			alice.DID(),
			alice.DID(),
			[]string{},
			makeExpiry(30*time.Second),
			10,
			[]Capability{Capability("/test/invoke"), Capability("/test/send")},
			SelfSignNo,
		)
		require.Error(t, err, "delegate")
		require.ErrorIs(t, err, ErrNotAuthorized)
	})

	t.Run("trying to widen capabilities for a given broadcast topic", func(t *testing.T) {
		// VALID scenario
		tokens, err := bobRoot.Grant(
			Delegate,
			bob.DID(),
			did.DID{},
			[]string{topic},
			makeExpiry(120*time.Second),
			0,
			[]Capability{Capability("/test/invoke")},
		)
		require.NoError(t, err, "granting broadcast capability")

		err = bob.AddRoots(nil, TokenList{}, tokens, TokenList{})
		require.NoError(t, err, "add roots")

		// delegate broadcast to alice
		_, err = bob.DelegateBroadcast(
			alice.DID(),
			topic,
			makeExpiry(30*time.Second),
			[]Capability{Capability("/test/invoke")},
			SelfSignNo,
		)
		require.NoError(t, err)

		// ADVERSARIAL scenario: trying to widen capabilities for a given broadcast topic
		_, err = bob.DelegateBroadcast(
			alice.DID(),
			topic,
			makeExpiry(30*time.Second),
			[]Capability{Capability("/test/invoke"), Capability("/test/send")},
			SelfSignNo,
		)
		require.Error(t, err, "delegate-broadcast")
		require.ErrorIs(t, err, ErrNotAuthorized)
	})
}

func TestAdversarialChains(t *testing.T) {
	t.Parallel()
	t.Run("attempt to extend expiration of delegation chain", func(t *testing.T) {
		// Bob -> Alice -> Joe
		// Bob grants to Alice which in turn delegates to Joe
		//
		// But silly Alice tries to extend the expiration time.
		//
		// Note: pay attention on the expirations
		t.Parallel()
		bobRoot := makeCapabilityContext(t)
		aliceRoot := makeCapabilityContext(t)
		root3 := makeCapabilityContext(t)

		bob := makeActorCapabilityContext(t, bobRoot)
		alice := makeActorCapabilityContext(t, aliceRoot)
		joe := makeActorCapabilityContext(t, root3)

		bobAliceTokens, err := bob.Grant(
			Delegate,
			alice.DID(),
			bob.DID(),
			nil,
			makeExpiry(20*time.Second),
			0,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob delegating to Alice")

		err = alice.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{})
		require.NoError(t, err, "Alice adding Bob's tokens")

		aliceJoeTokens, err := alice.Delegate(
			joe.DID(),
			bob.DID(),
			nil,
			makeExpiry(15*time.Second),
			0,
			[]Capability{Capability("/bob/hi")},
			SelfSignNo,
		)
		require.NoError(t, err, "Alice delegating to Joe")

		// VALID scenario
		err = joe.AddRoots(nil, TokenList{}, aliceJoeTokens, TokenList{})
		require.NoError(t, err, "Joe adding alice delegated tokens as provide")

		// ADVERSARIAL scenario
		aliceJoeTokens.Tokens[0].Domain.Chain.Domain.Expire = makeExpiry(50 * time.Second)

		err = joe.AddRoots(nil, TokenList{}, aliceJoeTokens, TokenList{})
		require.Error(t, err, "Joe adding alice tampered tokens as provide")
	})
	t.Run("should fail on expired certificate chains", func(t *testing.T) {
		// Bob -> Alice -> Joe
		// Bob grants to Alice which in turn delegates to Joe
		//
		// But when Joe tries to use invoke it, it's already expired
		//
		// Note: pay attention on the expirations
		t.Parallel()

		bobRoot := makeCapabilityContext(t)
		aliceRoot := makeCapabilityContext(t)
		root3 := makeCapabilityContext(t)

		bob := makeActorCapabilityContext(t, bobRoot)
		alice := makeActorCapabilityContext(t, aliceRoot)
		joe := makeActorCapabilityContext(t, root3)

		bobID := makeActorIDFromDID(t, bob.DID())
		joeID := makeActorIDFromDID(t, joe.DID())

		bobAliceTokens, err := bob.Grant(
			Delegate,
			alice.DID(),
			bob.DID(),
			nil,
			makeExpiry(10*time.Second),
			0,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob delegating to Alice")

		err = alice.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{})
		require.NoError(t, err, "Alice adding Bob's tokens")

		aliceJoeTokens, err := alice.Delegate(
			joe.DID(),
			bob.DID(),
			nil,
			makeExpiry(5*time.Second),
			0,
			[]Capability{Capability("/bob/hi")},
			SelfSignNo,
		)
		require.NoError(t, err, "Alice delegating to Joe")

		err = joe.AddRoots(nil, TokenList{}, aliceJoeTokens, TokenList{})
		require.NoError(t, err, "Joe adding alice tokens as provide")

		joeInvokeTokens, err := joe.Provide(
			bob.DID(),
			joeID,
			bobID,
			makeExpiry(3*time.Second),
			[]Capability{Capability("/bob/hi")},
			nil,
		)
		require.NoError(t, err, "Joe providing invoke tokens")

		err = bob.Consume(joe.DID(), joeInvokeTokens)
		require.NoError(t, err, "Bob consuming Joe's tokens")

		// VALID scenario
		err = bob.Require(
			bob.DID(),
			joeID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob is requiring capabilities in which Joe is the subject")

		// ADVERSARIAL scenario
		<-time.After(3 * time.Second)
		err = bob.Require(
			bob.DID(),
			joeID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.Error(t, err, "Bob is requiring capabilities in which Joe is the subject. But it's already expired")
	})
	t.Run("invalid chain", func(t *testing.T) {
		// Bob -> Alice -> Joe
		// Bob grants to Alice which in turn delegates to Joe
		//
		// But Alice had its chain modified so Joe will not be able to add it as roots.
		//
		// Note: pay attention on the expirations
		t.Parallel()

		bobRoot := makeCapabilityContext(t)
		aliceRoot := makeCapabilityContext(t)
		root3 := makeCapabilityContext(t)

		bob := makeActorCapabilityContext(t, bobRoot)
		alice := makeActorCapabilityContext(t, aliceRoot)
		joe := makeActorCapabilityContext(t, root3)

		bobAliceTokens, err := bob.Grant(
			Delegate,
			alice.DID(),
			bob.DID(),
			nil,
			makeExpiry(10*time.Second),
			0,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob delegating to Alice")

		err = alice.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{})
		require.NoError(t, err, "Alice adding Bob's tokens")

		aliceJoeTokens, err := alice.Delegate(
			joe.DID(),
			bob.DID(),
			nil,
			makeExpiry(5*time.Second),
			0,
			[]Capability{Capability("/bob/hi")},
			SelfSignNo,
		)
		require.NoError(t, err, "Alice delegating to Joe")

		// VALID SCENARIO
		err = joe.AddRoots(nil, TokenList{}, aliceJoeTokens, TokenList{})
		require.NoError(t, err, "Joe adding valid alice delegated tokens")

		// INVALID SCENARIO
		aliceJoeTokens.Tokens[0].Domain.Chain.Domain.Capability = []Capability{Capability("/other-capability")}

		err = joe.AddRoots(nil, TokenList{}, aliceJoeTokens, TokenList{})
		require.Error(t, err, "Joe adding alice delegated tokens (but it was tampered)")
	})
}

func TestUCAN(t *testing.T) {
	t.Parallel()
	t.Run("should fail when attempt to claim capabilities without anchoring on our root anchors", func(t *testing.T) {
		t.Parallel()
		root := makeCapabilityContext(t)

		// bob is not anchored on our root
		bob := makeCapabilityContext(t)
		bobID := makeActorID(t)

		alice := makeActorCapabilityContext(t, root, Capability("/test/invoke"))
		aliceID := makeActorID(t)

		caps, err := alice.Provide(
			bob.DID(),
			aliceID,
			bobID,
			makeExpiry(30*time.Second),
			[]Capability{Capability("/test/invoke")},
			[]Capability{},
		)
		require.NoError(t, err, "provide")

		err = bob.Consume(alice.DID(), caps)
		require.NoError(t, err, "consume")

		err = bob.Require(
			bob.DID(),
			aliceID,
			bobID,
			[]Capability{Capability("/test/invoke")},
		)
		require.Error(t, err, "require")
		require.ErrorIs(t, err, ErrNotAuthorized)
	})
}
