package ucan

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"gitlab.com/nunet/device-management-service/lib/crypto"
	"gitlab.com/nunet/device-management-service/lib/did"
)

func makeTrustContext(t *testing.T) (did.DID, did.TrustContext) {
	privk, _, err := crypto.GenerateKeyPair(crypto.Ed25519)
	require.NoError(t, err, "generate key")

	provider, err := did.ProviderFromPrivateKey(privk)
	require.NoError(t, err, "provider from public key")

	ctx := did.NewTrustContext()
	ctx.AddProvider(provider)

	return provider.DID(), ctx
}

func makeRootCapabilityContext(t *testing.T) CapabilityContext {
	rootDID, trustCtx := makeTrustContext(t)

	capCtx, err := NewCapabilityContext(trustCtx, rootDID, nil, TokenList{}, TokenList{})
	require.NoError(t, err, "make capability context")

	return capCtx
}

func makeExpiry(d time.Duration) uint64 {
	return uint64(time.Now().Add(d).UnixNano())
}

func makeActorCapabilityContext(t *testing.T, rootCtx CapabilityContext, actorCap ...Capability) CapabilityContext {
	actorDID, actorTrustCtx := makeTrustContext(t)

	tokens, err := rootCtx.Grant(
		Delegate,
		actorDID,
		did.DID{},
		makeExpiry(120*time.Second),
		actorCap,
	)
	require.NoError(t, err, "granting capabilities to actor")

	actorCtx, err := NewCapabilityContext(
		actorTrustCtx,
		actorDID,
		[]did.DID{rootCtx.DID()},
		TokenList{},
		tokens,
	)
	require.NoError(t, err, "adding roots for actor")

	return actorCtx
}

func allowReciprocal(t *testing.T, actor, root, otherRoot CapabilityContext, actorCap ...Capability) {
	tokens, err := root.Grant(
		Delegate,
		otherRoot.DID(),
		did.DID{},
		makeExpiry(120*time.Second),
		actorCap)
	require.NoError(t, err, "granting reciprocal capabilities")

	err = actor.AddRoots(nil, tokens, TokenList{})
	require.NoError(t, err, "consuming reciprocal capabilities")
}

func makeActorID(t *testing.T) crypto.ID {
	_, pubk, err := crypto.GenerateKeyPair(crypto.Ed25519)
	require.NoError(t, err, "generate key")

	id, err := crypto.IDFromPublicKey(pubk)
	require.NoError(t, err, "id from public key")

	return id
}

func TestBasicUCAN(t *testing.T) {
	root := makeRootCapabilityContext(t)
	actor1 := makeActorCapabilityContext(t, root, Capability("/test/invoke"))
	actor2 := makeActorCapabilityContext(t, root, Capability("/test/invoke"))

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

	actorCap, err = actor2.Provide(
		actor1.DID(),
		actor2ID,
		actor1ID,
		makeExpiry(20*time.Second),
		[]Capability{Capability("/test/reply")},
		nil,
	)
	require.NoError(t, err, "provide")

	err = actor1.Consume(actor2.DID(), actorCap)
	require.NoError(t, err, "consume")

	err = actor1.Require(
		actor1.DID(),
		actor2ID,
		actor1ID,
		[]Capability{Capability("/test/reply")},
	)
	require.NoError(t, err, "require")
}

func TestTokenDiscard(t *testing.T) {
	root := makeRootCapabilityContext(t)
	actor1 := makeActorCapabilityContext(t, root, Capability("/test/invoke"))
	actor2 := makeActorCapabilityContext(t, root, Capability("/test/invoke"))

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

	actor2Ctx := actor2.(*BasicCapabilityContext)
	require.Greater(t, len(actor2Ctx.tokens), 0, "token store is not empty")

	actor2.Discard(actorCap)
	require.Equal(t, len(actor2Ctx.tokens), 0, "token store is empty")
}

func TestReciprocalUCAN(t *testing.T) {
	root1 := makeRootCapabilityContext(t)
	root2 := makeRootCapabilityContext(t)
	actor1 := makeActorCapabilityContext(t, root1, Capability("/test/invoke"))
	actor2 := makeActorCapabilityContext(t, root2, Capability("/test/invoke"))
	allowReciprocal(t, actor1, root1, root2, Capability("/test/invoke"))
	allowReciprocal(t, actor2, root2, root1, Capability("/test/invoke"))

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

	actorCap, err = actor2.Provide(
		actor1.DID(),
		actor2ID,
		actor1ID,
		makeExpiry(20*time.Second),
		[]Capability{Capability("/test/reply")},
		nil,
	)
	require.NoError(t, err, "provide")

	err = actor1.Consume(actor2.DID(), actorCap)
	require.NoError(t, err, "consume")

	err = actor1.Require(
		actor1.DID(),
		actor2ID,
		actor1ID,
		[]Capability{Capability("/test/reply")},
	)
	require.NoError(t, err, "require")
}

func TestReciprocalDistrust(t *testing.T) {
	root1 := makeRootCapabilityContext(t)
	root2 := makeRootCapabilityContext(t)
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
}
