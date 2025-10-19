# UCAN: User Controlled Authorization Networks

A Go implementation of UCAN providing decentralized, capability-based authorization for distributed systems. UCAN enables fine-grained access control through cryptographically verifiable capability tokens that can be delegated between parties without requiring a central authority.

**Origin:** This package was extracted from and is actively used by [NuNet's Device Management Service (DMS)](https://gitlab.com/nunet/device-management-service) and powers the security model for the [`github.com/depinkit/actor`](https://github.com/depinkit/actor) framework.

## Overview

UCAN (User Controlled Authorization Networks) solves the authorization problem in decentralized systems where:
- There is no central authority to grant permissions
- Entities are mutually distrustful
- Fine-grained access control is required
- Capabilities need to be delegated securely
- Authorization must work offline

This library provides:
- **Capability Tokens**: Self-contained authorization with cryptographic verification
- **Delegation Chains**: Secure capability delegation with attenuation
- **Hierarchical Capabilities**: UNIX-style path-based capability namespace
- **Revocation**: Explicit token revocation mechanisms
- **Broadcast Authorization**: Support for pub/sub topic authorization
- **Zero Trust**: Every interaction is individually authenticated

## Installation

```bash
go get github.com/depinkit/ucan
go get github.com/depinkit/crypto
go get github.com/depinkit/did
go get github.com/depinkit/actor  # For actor framework integration
```

## Getting Started

### Understanding UCAN

UCAN tokens are like JWT tokens, but designed for decentralized systems:

- **Self-Contained**: Tokens carry all necessary authorization information
- **Delegatable**: Recipients can delegate (attenuated) capabilities to others
- **Verifiable**: Cryptographic signatures ensure authenticity
- **Hierarchical**: Capabilities follow UNIX-like paths (/, /api, /api/read)
- **Time-Limited**: All tokens have expiration times
- **Revocable**: Issuers can revoke tokens before expiration

### Key Components

1. **Trust Context**: Holds cryptographic keys for signing
2. **Capability Context**: Manages tokens and trust relationships
3. **Capability Tokens**: Cryptographically signed authorization proofs
4. **Trust Anchors**: DIDs you trust to issue capabilities

### Quick Start: Simple Authorization

```go
package main

import (
    "fmt"
    "time"
    
    "github.com/depinkit/ucan"
    "github.com/depinkit/did"
    "github.com/depinkit/crypto"
)

func main() {
    // Create Alice (resource owner)
    alicePriv, _ := crypto.GeneratePrivateKey(crypto.KEY_ED25519)
    aliceDID := did.FromPublicKey(alicePriv.GetPublic())
    aliceTrust := did.NewTrustContext(alicePriv)
    aliceCap, _ := ucan.NewCapabilityContext(aliceTrust, aliceDID, 
        nil, ucan.TokenList{}, ucan.TokenList{}, ucan.TokenList{})
    
    // Create Bob (wants access)
    bobPriv, _ := crypto.GeneratePrivateKey(crypto.KEY_ED25519)
    bobDID := did.FromPublicKey(bobPriv.GetPublic())
    bobTrust := did.NewTrustContext(bobPriv)
    
    // Alice grants Bob read permission
    expiry := uint64(time.Now().Add(1 * time.Hour).UnixNano())
    tokens, _ := aliceCap.Grant(
        ucan.Invoke,                     // Bob can invoke, not delegate
        bobDID,                          // Grant to Bob
        bobDID,                          // Only Bob can use it
        []string{},                      // No topics
        expiry,                          // Expires in 1 hour
        0,                               // No depth limit
        []ucan.Capability{"/file/read"}, // What Bob can do
    )
    
    // Bob creates capability context with Alice's token
    bobCap, _ := ucan.NewCapabilityContext(bobTrust, bobDID,
        []did.DID{aliceDID}, // Bob trusts Alice
        ucan.TokenList{},    // No required
        tokens,              // Alice's grant
        ucan.TokenList{})    // No revocations
    
    // Bob verifies he has permission
    bobID := aliceDID.ID()
    err := bobCap.Require(
        aliceDID,                        // Trust anchor
        bobID,                           // Bob's ID
        bobID,                           // Audience
        []ucan.Capability{"/file/read"}, // Required capability
    )
    
    if err == nil {
        fmt.Println("✅ Authorization successful! Bob can read files.")
    } else {
        fmt.Printf("❌ Authorization failed: %v\n", err)
    }
}
```

##  Integration with NuActor Framework

UCAN is the security foundation for the [NuActor framework](https://github.com/depinkit/actor). Every actor interaction is automatically protected by UCAN capabilities - you just use the actor API and UCAN handles authorization behind the scenes.

### Why Use UCAN with Actors?

In decentralized systems like NuNet's compute network:
- **No Central Auth Server**: Each node independently verifies authorization
- **Dynamic Permissions**: Capabilities can be granted/revoked at runtime
- **Fine-Grained Control**: Different behaviors can require different capabilities
- **Delegation Chains**: Admins can delegate to managers who delegate to workers
- **Broadcast Control**: Control who can publish to which topics

### Complete Actor Example with UCAN

Here's a complete example showing how actors use UCAN for secure communication:

```go
package main

import (
    "encoding/json"
    "fmt"
    "time"
    
    "github.com/depinkit/actor"
    "github.com/depinkit/crypto"
    "github.com/depinkit/did"
    "github.com/depinkit/network"
    "github.com/depinkit/ucan"
)

func main() {
    // Create two actors with UCAN security
    alice := createActorWithUCAN("Alice")
    bob := createActorWithUCAN("Bob")
    
    // Alice grants Bob permission to invoke "/api/data"
    alice.Security().Grant(
        bob.Handle().DID,
        bob.Handle().DID,
        []ucan.Capability{"/api/data"},
        24 * time.Hour,
    )
    
    // Bob registers a protected behavior
    bob.AddBehavior("/api/data", func(msg actor.Envelope) {
        defer msg.Discard()  // Clean up capability tokens
        
        var request string
        json.Unmarshal(msg.Message, &request)
        fmt.Printf("Bob received authorized request: %s\n", request)
        
        reply, _ := actor.ReplyTo(msg, "Data: 42")
        bob.Send(reply)
    }, actor.WithBehaviorCapability("/api/data"))
    
    // Bob invokes the behavior (with automatic capability verification)
    message, _ := actor.Message(
        alice.Handle(),
        bob.Handle(),
        "/api/data",
        "Please send data",
    )
    
    replyChan, _ := alice.Invoke(message)
    reply := <-replyChan
    defer reply.Discard()
    
    var response string
    json.Unmarshal(reply.Message, &response)
    fmt.Printf("Alice received: %s\n", response)
}

func createActorWithUCAN(name string) actor.Actor {
    // Generate identity
    priv, _ := crypto.GeneratePrivateKey(crypto.KEY_ED25519)
    actorDID := did.FromPublicKey(priv.GetPublic())
    
    // Create trust and capability contexts
    trustCtx := did.NewTrustContext(priv)
    capCtx, _ := ucan.NewCapabilityContext(
        trustCtx, actorDID, nil,
        ucan.TokenList{}, ucan.TokenList{}, ucan.TokenList{},
    )
    
    // Trust self
    capCtx.AddRoot(actorDID)
    
    // Create security context
    security := actor.NewBasicSecurityContext(priv, actorDID, capCtx)
    
    // Create actor (network, limiter setup omitted for brevity)
    actorInstance, _ := actor.New(supervisor, network, security, limiter)
    actorInstance.Start()
    
    return actorInstance
}
```

### How UCAN Protects Actor Interactions

Every message sent between actors includes UCAN capability tokens:

1. **Message Creation**: When Actor A sends to Actor B, it includes capability tokens proving authorization
2. **Automatic Verification**: Actor B automatically verifies the token chain before executing the behavior
3. **Token Cleanup**: `defer msg.Discard()` ensures deterministic cleanup of consumed tokens
4. **Trust Anchors**: Each actor maintains its own trust anchors (roots) to validate incoming tokens

```go
// When Alice sends a message to Bob:
msg, _ := actor.Message(
    alice.Handle(),
    bob.Handle(),
    "/protected/behavior",
    payload,
)

// Behind the scenes:
// 1. Actor framework calls alice.Security().Provide()
// 2. UCAN creates and signs capability token
// 3. Token is embedded in msg.Capability field
// 4. Message is sent over network

alice.Send(msg)

// When Bob receives the message:
// 1. Actor framework calls bob.Security().Require()
// 2. UCAN verifies token signature
// 3. UCAN checks token chain against trust anchors
// 4. UCAN validates capability matches behavior
// 5. Only then is the behavior handler invoked
```

## Core Concepts

### Capabilities

Capabilities represent permissions in a hierarchical structure:

```go
// Define capabilities
const (
    RootCap = ucan.Capability("/")
    ReadCap = ucan.Capability("/file/read")
    WriteCap = ucan.Capability("/file/write")
    AdminCap = ucan.Capability("/admin")
)

// Check if one capability implies another
if AdminCap.Implies(ReadCap) {
    // Admin capability includes read permission
}
```

### Capability Context

A capability context manages tokens and provides the main API:

```go
type CapabilityContext interface {
    // Consume tokens from another party
    Consume(origin did.DID, capToken []byte) error
    
    // Require capabilities for an operation
    Require(anchor did.DID, subject crypto.ID, audience crypto.ID, require []Capability) error
    
    // Provide tokens to another party
    Provide(target did.DID, subject crypto.ID, audience crypto.ID, expire uint64, invoke []Capability, delegate []Capability) ([]byte, error)
    
    // Delegate capabilities to another party
    Delegate(subject, audience did.DID, topics []string, expire, depth uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error)
    
    // Revoke tokens
    Revoke(*Token) (*Token, error)
}
```

## Practical Examples with Actors

### 1. Actor-to-Actor Capability Delegation

This example shows how one actor delegates capabilities to another:

```go
// Scenario: Manager actor delegates task execution capability to Worker actor

func setupDelegation() {
    // Create manager actor
    manager := createActor("Manager")
    worker := createActor("Worker")
    
    // Manager delegates /task/execute capability to Worker
    err := manager.Security().Grant(
        worker.Handle().DID,              // Subject: Worker receives capability
        worker.Handle().DID,              // Audience: Only Worker can use it
        []ucan.Capability{"/task/execute"}, // Capability granted
        24 * time.Hour,                    // Valid for 24 hours
    )
    if err != nil {
        log.Fatal("Failed to grant capability:", err)
    }
    
    // Worker registers the protected behavior
    worker.AddBehavior("/task/execute", func(msg actor.Envelope) {
        defer msg.Discard() // IMPORTANT: Clean up UCAN tokens
        
        var task Task
        json.Unmarshal(msg.Message, &task)
        
        // Execute task
        result := executeTask(task)
        
        // Send result back
        reply, _ := actor.ReplyTo(msg, result)
        worker.Send(reply)
    }, actor.WithBehaviorCapability("/task/execute"))
    
    // Manager can now invoke the task
    task := Task{ID: "task-001", Action: "process"}
    msg, _ := actor.Message(
        manager.Handle(),
        worker.Handle(),
        "/task/execute",
        task,
    )
    
    // The UCAN capability token is automatically included and verified!
    replyChan, _ := manager.Invoke(msg)
    result := <-replyChan
    defer result.Discard()
}
```

### 2. Multi-Level Delegation Chain

Shows how capabilities can be delegated through multiple actors:

```go
// Scenario: Admin -> Manager -> Worker delegation chain

func multiLevelDelegation() {
    admin := createActor("Admin")
    manager := createActor("Manager")
    worker := createActor("Worker")
    
    // Step 1: Admin delegates to Manager (with delegation rights)
    // Manager can further delegate this capability
    err := admin.Security().Grant(
        manager.Handle().DID,
        manager.Handle().DID,
        []ucan.Capability{"/system/admin"},
        48 * time.Hour,
    )
    require.NoError(t, err)
    
    // Step 2: Manager delegates a subset to Worker
    // Worker gets narrower capability and cannot delegate further
    err = manager.Security().Grant(
        worker.Handle().DID,
        worker.Handle().DID,
        []ucan.Capability{"/system/admin/logs/read"}, // Narrower capability
        24 * time.Hour,
    )
    require.NoError(t, err)
    
    // Worker can now read logs, but cannot perform other admin tasks
    worker.AddBehavior("/system/admin/logs/read", func(msg actor.Envelope) {
        defer msg.Discard()
        logs := readSystemLogs()
        reply, _ := actor.ReplyTo(msg, logs)
        worker.Send(reply)
    }, actor.WithBehaviorCapability("/system/admin/logs/read"))
    
    // When Admin sends a message to Worker:
    // The UCAN token chain is: Admin -> Manager -> Worker
    // Each link in the chain attenuates (narrows) the capability
}
```

### 3. Broadcast Authorization with UCAN

Actors use UCAN to control who can broadcast to topics:

```go
// Scenario: Only authorized actors can broadcast system notifications

func broadcastWithAuth() {
    coordinator := createActor("Coordinator")
    listener1 := createActor("Listener1")
    listener2 := createActor("Listener2")
    
    topic := "/notifications/system"
    
    // Coordinator grants broadcast capability to listener1 only
    err := coordinator.Security().Grant(
        listener1.Handle().DID,
        did.DID{}, // Empty audience = "to whom it may concern"
        []ucan.Capability{topic}, // Topic as capability
        24 * time.Hour,
    )
    require.NoError(t, err)
    
    // Both listeners subscribe to the topic
    listener1.Subscribe(topic)
    listener2.Subscribe(topic)
    
    // Both add behavior handler
    for _, listener := range []actor.Actor{listener1, listener2} {
        listener.AddBehavior("/notify", func(msg actor.Envelope) {
            defer msg.Discard()
            
            var notification string
            json.Unmarshal(msg.Message, &notification)
            fmt.Printf("Received: %s\n", notification)
        }, actor.WithBehaviorTopic(topic))
    }
    
    // listener1 can broadcast (has capability)
    msg1, _ := actor.Message(
        listener1.Handle(),
        actor.Handle{},
        "/notify",
        "System update available!",
        actor.WithMessageTopic(topic),
    )
    listener1.Publish(msg1) // ✅ SUCCESS - authorized
    
    // listener2 cannot broadcast (lacks capability)
    msg2, _ := actor.Message(
        listener2.Handle(),
        actor.Handle{},
        "/notify",
        "Unauthorized broadcast attempt",
        actor.WithMessageTopic(topic),
    )
    listener2.Publish(msg2) // ❌ REJECTED - no capability token
}
```

### 4. Time-Limited Access

Grant temporary access to resources:

```go
func temporaryAccess() {
    server := createActor("Server")
    client := createActor("Client")
    
    // Grant access for only 5 minutes
    err := server.Security().Grant(
        client.Handle().DID,
        client.Handle().DID,
        []ucan.Capability{"/api/premium/features"},
        5 * time.Minute, // Short-lived token
    )
    
    // Client can access premium features
    msg, _ := actor.Message(
        client.Handle(),
        server.Handle(),
        "/api/premium/features",
        "Get premium data",
    )
    
    // Works while token is valid
    client.Send(msg) // ✅ SUCCESS
    
    // Wait for expiration
    time.Sleep(6 * time.Minute)
    
    // Token has expired
    client.Send(msg) // ❌ REJECTED - token expired
}
```

## Low-Level API Examples

These examples show direct UCAN API usage without the actor framework.

### 1. Basic Token Exchange

```go
func basicTokenExchange() {
    // Create contexts for two parties
    alice := makeCapabilityContext("alice")
    bob := makeCapabilityContext("bob")
    
    aliceID := makeActorID()
    bobID := makeActorID()
    
    // Alice provides tokens to Bob
    tokens, err := alice.Provide(
        bob.DID(),
        aliceID,
        bobID,
        makeExpiry(30*time.Second),
        []Capability{Capability("/file/read")},
        []Capability{Capability("/file/reply")},
    )
    require.NoError(t, err)
    
    // Bob consumes Alice's tokens
    err = bob.Consume(alice.DID(), tokens)
    require.NoError(t, err)
    
    // Bob requires the capabilities
    err = bob.Require(
        bob.DID(),
        aliceID,
        bobID,
        []Capability{Capability("/file/read")},
    )
    require.NoError(t, err)
}
```

### 2. Capability Delegation

```go
func capabilityDelegation() {
    // Create a delegation chain: Root -> Alice -> Bob
    root := makeCapabilityContext("root")
    alice := makeActorCapabilityContext(root, Capability("/api/read"))
    bob := makeActorCapabilityContext(root, Capability("/api/read"))
    
    // Root grants capabilities to Alice
    aliceTokens, err := root.Grant(
        ucan.Delegate,
        alice.DID(),
        root.DID(),
        nil,
        makeExpiry(50*time.Second),
        0,
        []Capability{Capability("/api/read")},
    )
    require.NoError(t, err)
    
    // Alice adds root's tokens as provide tokens
    err = alice.AddRoots(nil, ucan.TokenList{}, aliceTokens, ucan.TokenList{})
    require.NoError(t, err)
    
    // Alice delegates to Bob
    bobTokens, err := alice.Delegate(
        bob.DID(),
        root.DID(),
        nil,
        makeExpiry(40*time.Second),
        0,
        []Capability{Capability("/api/read")},
        ucan.SelfSignNo,
    )
    require.NoError(t, err)
    
    // Bob adds Alice's tokens
    err = bob.AddRoots(nil, ucan.TokenList{}, bobTokens, ucan.TokenList{})
    require.NoError(t, err)
}
```

### 3. Broadcast Authorization

```go
func broadcastAuthorization() {
    root := makeCapabilityContext("root")
    publisher := makeActorCapabilityContext(root, Capability("/pub/sub"))
    subscriber := makeActorCapabilityContext(root, Capability("/pub/sub"))
    
    topic := "news/tech"
    
    // Root grants broadcast capability to publisher
    broadcastTokens, err := root.Grant(
        ucan.Broadcast,
        publisher.DID(),
        root.DID(),
        []string{topic},
        makeExpiry(60*time.Second),
        0,
        []Capability{Capability("/pub/sub")},
    )
    require.NoError(t, err)
    
    // Publisher provides broadcast tokens
    tokens, err := publisher.ProvideBroadcast(
        makeActorID(),
        topic,
        makeExpiry(30*time.Second),
        []Capability{Capability("/pub/sub")},
    )
    require.NoError(t, err)
    
    // Subscriber consumes and requires broadcast tokens
    err = subscriber.Consume(publisher.DID(), tokens)
    require.NoError(t, err)
    
    err = subscriber.RequireBroadcast(
        subscriber.DID(),
        makeActorID(),
        topic,
        []Capability{Capability("/pub/sub")},
    )
    require.NoError(t, err)
}
```

### 4. Token Revocation

```go
func tokenRevocation() {
    root := makeCapabilityContext("root")
    user := makeActorCapabilityContext(root, Capability("/api/access"))
    
    // Create a token
    token := createToken(root, user.DID(), root.DID(), Capability("/api/access"), makeExpiry(60*time.Second))
    
    // Verify the token is valid
    err := token.Verify(root.Trust(), uint64(time.Now().UnixNano()), root.(*BasicCapabilityContext).revoke)
    require.NoError(t, err)
    
    // Revoke the token
    revokeToken, err := root.Revoke(token)
    require.NoError(t, err)
    
    // Add revocation to the context
    err = root.AddRoots(nil, ucan.TokenList{}, ucan.TokenList{}, ucan.TokenList{Tokens: []*Token{revokeToken}})
    require.NoError(t, err)
    
    // Verify the token is now revoked
    err = token.Verify(root.Trust(), uint64(time.Now().UnixNano()), root.(*BasicCapabilityContext).revoke)
    require.Error(t, err) // Should fail
}
```

### 5. Cross-Domain Authorization

```go
func crossDomainAuthorization() {
    // Create separate trust domains
    domain1 := makeCapabilityContext("domain1")
    domain2 := makeCapabilityContext("domain2")
    
    // Establish mutual trust
    allowReciprocal(domain1, domain1, domain2, Capability("/api/cross"))
    allowReciprocal(domain2, domain2, domain1, Capability("/api/cross"))
    
    user1 := makeActorCapabilityContext(domain1, Capability("/api/cross"))
    user2 := makeActorCapabilityContext(domain2, Capability("/api/cross"))
    
    user1ID := makeActorID()
    user2ID := makeActorID()
    
    // User1 provides tokens to User2 across domains
    tokens, err := user1.Provide(
        user2.DID(),
        user1ID,
        user2ID,
        makeExpiry(30*time.Second),
        []Capability{Capability("/api/cross")},
        []Capability{Capability("/api/reply")},
    )
    require.NoError(t, err)
    
    // User2 consumes and requires tokens from different domain
    err = user2.Consume(user1.DID(), tokens)
    require.NoError(t, err)
    
    err = user2.Require(
        user2.DID(),
        user1ID,
        user2ID,
        []Capability{Capability("/api/cross")},
    )
    require.NoError(t, err)
}
```

## API Reference

### Core Types

```go
// Capability represents a permission in hierarchical form
type Capability string

// Token represents a UCAN token
type Token struct {
    Domain  *DomainToken `json:"domain,omitempty"`
    UCAN *BYOToken `json:"ucan,omitempty"`
}

// DomainToken represents the DMS-specific token format
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

// Actions that can be performed
const (
    Invoke    Action = "invoke"
    Delegate  Action = "delegate"
    Broadcast Action = "broadcast"
    Revoke    Action = "revoke"
)
```

### Capability Context Methods

```go
// Create a new capability context
func NewCapabilityContext(trust did.TrustContext, ctxDID did.DID, roots []did.DID, require, provide, revoke TokenList) (CapabilityContext, error)

// Consume tokens from another party
func (ctx *BasicCapabilityContext) Consume(origin did.DID, capToken []byte) error

// Require capabilities for an operation
func (ctx *BasicCapabilityContext) Require(anchor did.DID, subject crypto.ID, audience crypto.ID, require []Capability) error

// Provide tokens to another party
func (ctx *BasicCapabilityContext) Provide(target did.DID, subject crypto.ID, audience crypto.ID, expire uint64, invoke []Capability, delegate []Capability) ([]byte, error)

// Delegate capabilities to another party
func (ctx *BasicCapabilityContext) Delegate(subject, audience did.DID, topics []string, expire, depth uint64, provide []Capability, selfSign SelfSignMode) (TokenList, error)

// Grant capabilities (self-signed)
func (ctx *BasicCapabilityContext) Grant(action Action, subject, audience did.DID, topic []string, expire, depth uint64, provide []Capability) (TokenList, error)

// Revoke a token
func (ctx *BasicCapabilityContext) Revoke(*Token) (*Token, error)
```

### Token Methods

```go
// Verify a token
func (t *Token) Verify(trust did.TrustContext, now uint64, revoke *RevocationSet) error

// Check if token allows an action
func (t *Token) AllowAction(ot *Token) bool

// Check if token allows invocation
func (t *Token) AllowInvocation(subject, audience did.DID, c Capability) bool

// Check if token allows broadcast
func (t *Token) AllowBroadcast(subject did.DID, topic Capability, c Capability) bool

// Delegate a token
func (t *Token) Delegate(provider did.Provider, subject, audience did.DID, topics []Capability, expire, depth uint64, c []Capability) (*Token, error)
```

## Security Considerations

1. **Token Expiration**: Always set appropriate expiration times for tokens
2. **Capability Granularity**: Use fine-grained capabilities to limit access
3. **Revocation**: Implement token revocation for compromised credentials
4. **Trust Anchors**: Carefully manage trust anchors and root authorities
5. **Token Storage**: Securely store and transmit tokens
6. **Verification**: Always verify tokens before accepting them

## Testing

The library includes comprehensive tests covering:

- Basic token operations
- Delegation chains
- Cross-domain authorization
- Broadcast tokens
- Token revocation
- Adversarial scenarios

Run tests with:

```bash
go test ./...
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

Apache 2.0 License - see [LICENSE](LICENSE) file for details.

## References

- [UCAN Specification](https://ucan.xyz/)
- [Capability-Based Security](https://en.wikipedia.org/wiki/Capability-based_security)
- [JWT (JSON Web Tokens)](https://jwt.io/) 
