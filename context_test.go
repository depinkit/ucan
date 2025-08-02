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
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"gitlab.com/nunet/device-management-service/lib/did"
)

// TestDelegationChain tests a simple chain of delegation as follows:
//
// Bob -> Alice -> Joe
//
// 1. Bob grants /bob/hi to Alice
//
// 2. Alice delegates the capability to Joe
//
// 3. Joe creates invocation tokens which are in turn consumed and required by Bob.
//
// The last step is basically:
// Joe: hey, can I invoke this on you?
// Bob: consumes token, check caps through Require()
func TestDelegationChain(t *testing.T) {
	// Important: do NOT remove the commented prints.
	// This test is helpful to understand how a chain of delegation works visually.
	t.Parallel()

	root1 := makeCapabilityContext(t)
	root2 := makeCapabilityContext(t)
	root3 := makeCapabilityContext(t)

	bob := makeActorCapabilityContext(t, root1)
	alice := makeActorCapabilityContext(t, root2)
	joe := makeActorCapabilityContext(t, root3)

	// t.Logf("bob: %v\n", bob.DID())
	// t.Logf("alice: %v\n", alice.DID())
	// t.Logf("joe: %v\n", joe.DID())

	bobID := makeActorIDFromDID(t, bob.DID())
	joeID := makeActorIDFromDID(t, joe.DID())

	// reminder: Grant() does not depend on root capabilities, so
	// we can delegate whatever we want since it's self signed
	bobAliceTokens, err := bob.Grant(
		Delegate,
		alice.DID(),
		bob.DID(),
		nil,
		makeExpiry(50*time.Second),
		0,
		[]Capability{Capability("/bob/hi")},
	)
	require.NoError(t, err, "Bob delegating to Alice")

	// we have to add as Provide so that we can delegate the granted caps
	err = alice.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{})
	require.NoError(t, err, "Alice adding Bob's tokens")

	aliceJoeTokens, err := alice.Delegate(
		joe.DID(),
		bob.DID(),
		nil,
		makeExpiry(40*time.Second),
		0,
		[]Capability{Capability("/bob/hi")},
		SelfSignNo,
	)
	require.NoError(t, err, "Alice delegating to Joe")

	err = joe.AddRoots(nil, TokenList{}, aliceJoeTokens, TokenList{})
	require.NoError(t, err, "Joe adding alice tokens as provide")

	// Joe prepares tokens for invoking capabilities on Bob
	joeInvokeTokens, err := joe.Provide(
		bob.DID(),
		joeID,
		bobID,
		makeExpiry(30*time.Second),
		[]Capability{Capability("/bob/hi")},
		nil,
	)
	require.NoError(t, err, "Joe providing invoke tokens")

	// Bob consumes Joe's tokens
	err = bob.Consume(joe.DID(), joeInvokeTokens)
	require.NoError(t, err, "Bob consuming Joe's tokens")

	// Bob requires the capabilities from Joe
	// Here is where Bob cheks if Joe has the necessary capabilities
	err = bob.Require(
		bob.DID(),
		joeID,
		bobID,
		[]Capability{Capability("/bob/hi")},
	)
	require.NoError(t, err, "Bob requiring capabilities from Joe")
}

func TestRequire(t *testing.T) {
	t.Run("should succeed when same anchored root of trust", func(t *testing.T) {
		root1 := makeCapabilityContext(t)
		actor1 := makeActorCapabilityContext(t, root1, Capability("/test/invoke"))
		actor2 := makeActorCapabilityContext(t, root1, Capability("/test/invoke"))

		actor1ID := makeActorID(t)
		actor2ID := makeActorID(t)

		actorCap, err := actor1.Provide(
			actor2.DID(),
			actor1ID,
			actor2ID,
			makeExpiry(30*time.Second),
			[]Capability{Capability("/test/invoke")},
			[]Capability{Capability("/test/reply")},
		)
		require.NoError(t, err, "provide")

		err = actor2.Consume(actor1.DID(), actorCap)
		require.NoError(t, err, "consume")

		err = actor2.Require(
			actor2.DID(),
			actor1ID,
			actor2ID,
			[]Capability{Capability("/test/invoke")},
		)
		require.NoError(t, err, "require")
	})

	t.Run("should fail when anchored in different root of trust", func(t *testing.T) {
		root1 := makeCapabilityContext(t)
		root2 := makeCapabilityContext(t)
		actor1 := makeActorCapabilityContext(t, root1, Capability("/test/invoke"))
		actor2 := makeActorCapabilityContext(t, root2, Capability("/test/invoke"))

		actor1ID := makeActorID(t)
		actor2ID := makeActorID(t)

		actorCap, err := actor1.Provide(
			actor2.DID(),
			actor1ID,
			actor2ID,
			makeExpiry(30*time.Second),
			[]Capability{Capability("/test/invoke")},
			[]Capability{Capability("/test/reply")},
		)
		require.NoError(t, err, "provide")

		err = actor2.Consume(actor1.DID(), actorCap)
		require.NoError(t, err, "consume")

		err = actor2.Require(
			actor2.DID(),
			actor1ID,
			actor2ID,
			[]Capability{Capability("/test/invoke")},
		)
		require.Error(t, err, "require")
	})
}

func TestConsume(t *testing.T) {
	root := makeCapabilityContext(t)
	consumer := makeActorCapabilityContext(t, root, Capability("/test/invoke"))
	origin := makeCapabilityContext(t)
	rootAnchor := makeCapabilityContext(t)
	sideChainAnchor := makeCapabilityContext(t)

	// Add rootAnchor to consumer's roots
	err := consumer.AddRoots([]did.DID{rootAnchor.DID()}, TokenList{}, TokenList{}, TokenList{})
	require.NoError(t, err, "adding root anchor")

	// 1. Token where consumer is the anchor
	token1 := createToken(t, consumer, consumer.DID(), origin.DID(), Capability("/test/invoke"), makeExpiry(30*time.Second))

	// 2. Token where origin is the anchor
	token2 := createToken(t, origin, origin.DID(), consumer.DID(), Capability("/test/invoke"), makeExpiry(30*time.Second))

	// 3. Token where anchor is one of our rootAnchors
	token3 := createToken(t, rootAnchor, origin.DID(), consumer.DID(), Capability("/test/invoke"), makeExpiry(30*time.Second))

	// 4. Token allowed by side chain
	token4 := createToken(t, sideChainAnchor, origin.DID(), consumer.DID(), Capability("/test/other-cap"), makeExpiry(30*time.Second))

	// 5. Token not allowed by side chain because of unallowed audience
	token5 := createToken(t, sideChainAnchor, origin.DID(), origin.DID(), Capability("/test/not-allowed"), makeExpiry(30*time.Second))

	// 6. Token that would fail verification due to expiration
	token6 := createToken(t, origin, origin.DID(), consumer.DID(), Capability("/test/invoke"), makeExpiry(-30*time.Second))

	// Add sideChainAnchor token to consumer's require tokens
	sideChainToken := createToken(t, sideChainAnchor, sideChainAnchor.DID(), did.DID{}, Capability("/test/other-cap"), makeExpiry(60*time.Second))
	err = consumer.AddRoots(nil, TokenList{Tokens: []*Token{sideChainToken}}, TokenList{}, TokenList{})
	require.NoError(t, err, "adding side chain tokens")

	tokensToConsume := TokenList{
		Tokens: []*Token{token1, token2, token3, token4, token5, token6},
	}

	tokenListBytes, err := json.Marshal(tokensToConsume)
	require.NoError(t, err, "marshal token list")

	err = consumer.Consume(origin.DID(), tokenListBytes)
	require.NoError(t, err, "consume tokens")

	consumerCtx, ok := consumer.(*BasicCapabilityContext)
	require.True(t, ok, "consumer should be a BasicCapabilityContext")

	require.Len(t, consumerCtx.tokens, 2, "should have tokens for origin and consumer itself as subjects")

	tokensForOrigin, exists := consumerCtx.tokens[origin.DID()]
	require.True(t, exists, "should have tokens for origin")
	require.Len(t, tokensForOrigin, 3, "should have 3 valid tokens")

	tokensForConsumer, exists := consumerCtx.tokens[consumer.DID()]
	require.True(t, exists, "should have tokens for origin")
	require.Len(t, tokensForConsumer, 1, "should have 1 valid tokens")

	containsToken := func(tokens []*Token, token *Token) bool {
		for _, t := range tokens {
			if bytes.Equal(t.Nonce(), token.Nonce()) {
				return true
			}
		}
		return false
	}

	// Check that valid tokens were added
	require.True(t, containsToken(tokensForConsumer, token1), "should contain token1")
	require.True(t, containsToken(tokensForOrigin, token2), "should contain token2")
	require.True(t, containsToken(tokensForOrigin, token3), "should contain token3")
	require.True(t, containsToken(tokensForOrigin, token4), "should contain token4")

	// Check that invalid tokens were not added
	require.False(t, containsToken(tokensForOrigin, token5), "should not contain token5")
	require.False(t, containsToken(tokensForOrigin, token6), "should not contain token6")
}

func TestRevoke(t *testing.T) {
	t.Parallel()
	t.Run("revoke single token", func(t *testing.T) {
		// Important: do NOT remove the commented prints.
		// This test is helpful to understand how a chain of delegation works visually.
		t.Parallel()

		root1 := makeCapabilityContext(t)
		root2 := makeCapabilityContext(t)

		bob := makeActorCapabilityContext(t, root1)
		alice := makeActorCapabilityContext(t, root2)

		// t.Logf("bob: %v\n", bob.DID())
		// t.Logf("alice: %v\n", alice.DID())
		// t.Logf("joe: %v\n", joe.DID())

		bobID := makeActorIDFromDID(t, bob.DID())
		aliceID := makeActorIDFromDID(t, alice.DID())

		// reminder: Grant() does not depend on root capabilities, so
		// we can delegate whatever we want since it's self signed
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

		// we have to add as Provide so that we can delegate the granted caps
		err = alice.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{})
		require.NoError(t, err, "Alice adding Bob's tokens")
		err = bob.AddRoots(nil, bobAliceTokens, TokenList{}, TokenList{})
		require.NoError(t, err, "Bob adding Bob's tokens")

		// Joe prepares tokens for invoking capabilities on Bob
		aliceInvokeTokens, err := alice.Provide(
			bob.DID(),
			aliceID,
			bobID,
			makeExpiry(10*time.Second),
			[]Capability{Capability("/bob/hi")},
			nil,
		)
		require.NoError(t, err, "Alice providing invoke tokens")

		// Bob consumes Joe's tokens
		err = bob.Consume(alice.DID(), aliceInvokeTokens)
		require.NoError(t, err, "Bob consuming Joe's tokens")

		// Bob requires the capabilities from Joe
		// Here is where Bob cheks if Joe has the necessary capabilities
		err = bob.Require(
			bob.DID(),
			aliceID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob requiring capabilities from alice")

		for _, token := range bobAliceTokens.Tokens {
			revocation, err := bob.Revoke(token)
			require.NoError(t, err)
			require.NoError(t, bob.AddRoots(nil, TokenList{}, TokenList{}, TokenList{Tokens: []*Token{revocation}}))
		}

		err = bob.Require(
			bob.DID(),
			aliceID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.Error(t, err, "token has been revoked but require still passes")
	})

	t.Run("revoke token in chain", func(t *testing.T) {
		// Important: do NOT remove the commented prints.
		// This test is helpful to understand how a chain of delegation works visually.
		t.Parallel()

		root1 := makeCapabilityContext(t)
		root2 := makeCapabilityContext(t)
		root3 := makeCapabilityContext(t)

		bob := makeActorCapabilityContext(t, root1)
		alice := makeActorCapabilityContext(t, root2)
		joe := makeActorCapabilityContext(t, root3)

		// t.Logf("bob: %v\n", bob.DID())
		// t.Logf("alice: %v\n", alice.DID())
		// t.Logf("joe: %v\n", joe.DID())

		bobID := makeActorIDFromDID(t, bob.DID())
		aliceID := makeActorIDFromDID(t, alice.DID())
		joeID := makeActorIDFromDID(t, joe.DID())

		// reminder: Grant() does not depend on root capabilities, so
		// we can delegate whatever we want since it's self signed
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

		for _, tok := range bobAliceTokens.Tokens {
			token := tok
			// t.Logf("%+v\n\n", tok.DMS)
			for token.Domain.Chain != nil {
				token = token.Domain.Chain
				// t.Logf("%+v\n\n", token.DMS)
			}
		}

		// we have to add as Provide so that we can delegate the granted caps
		err = alice.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{})
		require.NoError(t, err, "Alice adding Bob's tokens")

		aliceJoeTokens, err := alice.Delegate(
			joe.DID(),
			bob.DID(),
			nil,
			makeExpiry(10*time.Second),
			0,
			[]Capability{Capability("/bob/hi")},
			SelfSignNo,
		)
		require.NoError(t, err, "Alice delegating to Joe")

		err = joe.AddRoots(nil, TokenList{}, aliceJoeTokens, TokenList{})
		require.NoError(t, err, "Joe adding alice tokens as provide")

		// Joe prepares tokens for invoking capabilities on Bob
		joeInvokeTokens, err := joe.Provide(
			bob.DID(),
			joeID,
			bobID,
			makeExpiry(5*time.Second),
			[]Capability{Capability("/bob/hi")},
			nil,
		)
		require.NoError(t, err, "Joe providing invoke tokens")

		// Bob consumes Joe's tokens
		err = bob.Consume(joe.DID(), joeInvokeTokens)
		require.NoError(t, err, "Bob consuming Joe's tokens")

		// Bob requires the capabilities from Joe
		// Here is where Bob cheks if Joe has the necessary capabilities
		err = bob.Require(
			bob.DID(),
			joeID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob requiring capabilities from Joe")

		for _, token := range bobAliceTokens.Tokens {
			revocation, err := bob.Revoke(token)
			require.NoError(t, err)
			require.NoError(t, bob.AddRoots(nil, TokenList{}, TokenList{}, TokenList{Tokens: []*Token{revocation}}))
		}

		err = bob.Require(
			bob.DID(),
			aliceID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.Error(t, err, "verify: token has been revoked")
	})
	t.Run("revoke token and try to anchor it after", func(t *testing.T) {
		// Important: do NOT remove the commented prints.
		// This test is helpful to understand how a chain of delegation works visually.
		t.Parallel()

		root1 := makeCapabilityContext(t)
		root2 := makeCapabilityContext(t)

		bob := makeActorCapabilityContext(t, root1)
		alice := makeActorCapabilityContext(t, root2)

		// t.Logf("bob: %v\n", bob.DID())
		// t.Logf("alice: %v\n", alice.DID())
		// t.Logf("joe: %v\n", joe.DID())

		bobID := makeActorIDFromDID(t, bob.DID())
		aliceID := makeActorIDFromDID(t, alice.DID())

		// reminder: Grant() does not depend on root capabilities, so
		// we can delegate whatever we want since it's self signed
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

		// we have to add as Provide so that we can delegate the granted caps
		err = alice.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{})
		require.NoError(t, err, "Alice adding Bob's tokens")

		// Joe prepares tokens for invoking capabilities on Bob
		aliceInvokeTokens, err := alice.Provide(
			bob.DID(),
			aliceID,
			bobID,
			makeExpiry(10*time.Second),
			[]Capability{Capability("/bob/hi")},
			nil,
		)
		require.NoError(t, err, "Alice providing invoke tokens")

		// Bob consumes Joe's tokens
		err = bob.Consume(alice.DID(), aliceInvokeTokens)
		require.NoError(t, err, "Bob consuming Joe's tokens")

		// Bob requires the capabilities from Joe
		// Here is where Bob cheks if Joe has the necessary capabilities
		err = bob.Require(
			bob.DID(),
			aliceID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob requiring capabilities from alice")

		for _, token := range bobAliceTokens.Tokens {
			revocation, err := bob.Revoke(token)
			require.NoError(t, err)
			require.NoError(t, bob.AddRoots(nil, TokenList{}, TokenList{}, TokenList{Tokens: []*Token{revocation}}))
		}

		err = bob.Require(
			bob.DID(),
			aliceID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.Error(t, err, "verify: token has been revoked")
		require.Error(t, bob.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{}), "verify: token has been revoked")
	})

	t.Run("expired revocation token cannot be anchored", func(t *testing.T) {
		// Important: do NOT remove the commented prints.
		// This test is helpful to understand how a chain of delegation works visually.
		t.Parallel()

		root1 := makeCapabilityContext(t)
		root2 := makeCapabilityContext(t)

		bob := makeActorCapabilityContext(t, root1)
		alice := makeActorCapabilityContext(t, root2)

		// t.Logf("bob: %v\n", bob.DID())
		// t.Logf("alice: %v\n", alice.DID())
		// t.Logf("joe: %v\n", joe.DID())

		bobID := makeActorIDFromDID(t, bob.DID())
		aliceID := makeActorIDFromDID(t, alice.DID())

		// reminder: Grant() does not depend on root capabilities, so
		// we can delegate whatever we want since it's self signed
		bobAliceTokens, err := bob.Grant(
			Delegate,
			alice.DID(),
			bob.DID(),
			nil,
			makeExpiry(5*time.Second),
			0,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob delegating to Alice")

		// we have to add as Provide so that we can delegate the granted caps
		err = alice.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{})
		require.NoError(t, err, "Alice adding Bob's tokens")

		// Joe prepares tokens for invoking capabilities on Bob
		aliceInvokeTokens, err := alice.Provide(
			bob.DID(),
			aliceID,
			bobID,
			makeExpiry(2*time.Second),
			[]Capability{Capability("/bob/hi")},
			nil,
		)
		require.NoError(t, err, "Alice providing invoke tokens")

		// Bob consumes Joe's tokens
		err = bob.Consume(alice.DID(), aliceInvokeTokens)
		require.NoError(t, err, "Bob consuming Joe's tokens")

		// Bob requires the capabilities from Joe
		// Here is where Bob cheks if Joe has the necessary capabilities
		err = bob.Require(
			bob.DID(),
			aliceID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.NoError(t, err, "Bob requiring capabilities from alice")

		for _, token := range bobAliceTokens.Tokens {
			revocation, err := bob.Revoke(token)
			require.NoError(t, err)
			require.NoError(t, bob.AddRoots(nil, TokenList{}, TokenList{}, TokenList{Tokens: []*Token{revocation}}))
		}

		err = bob.Require(
			bob.DID(),
			aliceID,
			bobID,
			[]Capability{Capability("/bob/hi")},
		)
		require.Error(t, err, "verify: token has been revoked")
		require.Error(t, bob.AddRoots(nil, TokenList{}, bobAliceTokens, TokenList{}), "verify: token has been revoked")

		<-time.After(5 * time.Second)

		for _, token := range bobAliceTokens.Tokens {
			revocation, err := bob.Revoke(token)
			require.NoError(t, err)
			require.Error(t, bob.AddRoots(nil, TokenList{}, TokenList{}, TokenList{Tokens: []*Token{revocation}}), ErrCapabilityExpired)
		}
	})
}
