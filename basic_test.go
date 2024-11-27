package ucan

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"gitlab.com/nunet/device-management-service/lib/crypto"
	"gitlab.com/nunet/device-management-service/lib/did"
)

func TestBasicUCAN(t *testing.T) {
	root := makeCapabilityContext(t)
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
	root := makeCapabilityContext(t)
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
	root1 := makeCapabilityContext(t)
	root2 := makeCapabilityContext(t)
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
}

func TestBroadcastUCAN(t *testing.T) {
	topic := "test"
	capability := Capability("/test/broadcast")

	root1 := makeCapabilityContext(t)
	root2 := makeCapabilityContext(t)
	actor1 := makeActorCapabilityContext(t, root1)
	actor2 := makeActorCapabilityContext(t, root2)
	allowBroadcast(t, actor1, actor2, root1, root2, topic, capability)

	actor1ID := makeActorID(t)
	actorCap, err := actor1.ProvideBroadcast(
		actor1ID,
		topic,
		makeExpiry(30*time.Second),
		[]Capability{capability},
	)
	require.NoError(t, err, "provide")

	err = actor2.Consume(actor1.DID(), actorCap)
	require.NoError(t, err, "consume")

	err = actor2.RequireBroadcast(
		actor2.DID(),
		actor1ID,
		topic,
		[]Capability{capability},
	)
	require.NoError(t, err, "require")
}

func TestBroadcastDistrust(t *testing.T) {
	topic := "test"
	capability := Capability("/test/broadcast")

	root1 := makeCapabilityContext(t)
	root2 := makeCapabilityContext(t)
	actor1 := makeActorCapabilityContext(t, root1)
	actor2 := makeActorCapabilityContext(t, root2)

	tokens, err := root1.Grant(
		Delegate,
		actor1.DID(),
		did.DID{},
		[]string{topic},
		makeExpiry(120*time.Second),
		0,
		[]Capability{capability},
	)
	require.NoError(t, err, "granting broadcast capability")

	err = actor1.AddRoots(nil, TokenList{}, tokens)
	require.NoError(t, err, "add roots")

	actor1ID := makeActorID(t)
	actorCap, err := actor1.ProvideBroadcast(
		actor1ID,
		topic,
		makeExpiry(30*time.Second),
		[]Capability{capability},
	)
	require.NoError(t, err, "provide")

	err = actor2.Consume(actor1.DID(), actorCap)
	require.NoError(t, err, "consume")

	err = actor2.RequireBroadcast(
		actor2.DID(),
		actor1ID,
		topic,
		[]Capability{capability},
	)
	require.Error(t, err, "require")
}

func TestDelegationDepth(t *testing.T) {
	root1 := makeCapabilityContext(t)
	root2 := makeCapabilityContext(t)
	root3 := makeCapabilityContext(t)

	expiry := makeExpiry(120 * time.Second)
	capabilities := []Capability{Capability("/test")}
	topic := "/broadcast/test"
	topics := []string{topic}

	tokens, err := root1.Grant(
		Delegate,
		root2.DID(),
		did.DID{},
		topics,
		expiry,
		1,
		capabilities,
	)
	require.NoError(t, err, "grant")

	err = root2.AddRoots(nil, TokenList{}, tokens)
	require.NoError(t, err, "provide anchor")

	_, err = root2.DelegateInvocation(
		root3.DID(),
		root3.DID(),
		did.DID{},
		expiry,
		capabilities,
		SelfSignNo,
	)
	require.NoError(t, err, "delegate invocation")

	_, err = root2.DelegateBroadcast(
		root3.DID(),
		topic,
		expiry,
		capabilities,
		SelfSignNo,
	)
	require.NoError(t, err, "delegate broadcast")

	_, err = root2.Delegate(
		root3.DID(),
		did.DID{},
		topics,
		expiry,
		0,
		capabilities,
		SelfSignNo,
	)
	require.Error(t, err, "delegate")
}

func makeTrustContext(t *testing.T) (did.DID, did.TrustContext) {
	privk, _, err := crypto.GenerateKeyPair(crypto.Ed25519)
	require.NoError(t, err, "generate key")

	provider, err := did.ProviderFromPrivateKey(privk)
	require.NoError(t, err, "provider from public key")

	ctx := did.NewTrustContext()
	ctx.AddProvider(provider)

	return provider.DID(), ctx
}

func makeCapabilityContext(t *testing.T) CapabilityContext {
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
		nil,
		makeExpiry(120*time.Second),
		0,
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
		nil,
		makeExpiry(120*time.Second),
		0,
		actorCap)
	require.NoError(t, err, "granting reciprocal capabilities")

	err = actor.AddRoots(nil, tokens, TokenList{})
	require.NoError(t, err, "add roots")
}

func allowBroadcast(t *testing.T, actor1, actor2, root1, root2 CapabilityContext, topic string, actorCap ...Capability) {
	tokens, err := root1.Grant(
		Delegate,
		actor1.DID(),
		did.DID{},
		[]string{topic},
		makeExpiry(120*time.Second),
		0,
		actorCap,
	)
	require.NoError(t, err, "granting broadcast capability")

	err = actor1.AddRoots(nil, TokenList{}, tokens)
	require.NoError(t, err, "add roots")

	tokens, err = root2.Grant(
		Delegate,
		root1.DID(),
		did.DID{},
		[]string{topic},
		makeExpiry(120*time.Second),
		0,
		actorCap,
	)
	require.NoError(t, err, "granting broadcast capability")

	err = actor2.AddRoots(nil, tokens, TokenList{})
	require.NoError(t, err, "add roots")
}

func makeActorID(t *testing.T) crypto.ID {
	_, pubk, err := crypto.GenerateKeyPair(crypto.Ed25519)
	require.NoError(t, err, "generate key")

	id, err := crypto.IDFromPublicKey(pubk)
	require.NoError(t, err, "id from public key")

	return id
}

func makeActorIDFromDID(t *testing.T, d did.DID) crypto.ID {
	pbkey, err := did.PublicKeyFromDID(d)
	require.NoError(t, err)

	id, err := crypto.IDFromPublicKey(pbkey)
	require.NoError(t, err)

	return id
}

func createToken(t *testing.T, issuer CapabilityContext,
	subjectDID, audienceDID did.DID, cap Capability, expiry uint64,
) *Token {
	nonce := make([]byte, nonceLength)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	token := &Token{
		DMS: &DMSToken{
			Issuer:     issuer.DID(),
			Subject:    subjectDID,
			Audience:   audienceDID,
			Action:     Delegate,
			Capability: []Capability{cap},
			Expire:     expiry,
			Nonce:      nonce,
		},
	}
	data, err := token.DMS.SignatureData()
	require.NoError(t, err)

	provider, err := issuer.Trust().GetProvider(issuer.DID())
	require.NoError(t, err)

	token.DMS.Signature, err = provider.Sign(data)
	require.NoError(t, err)

	return token
}
