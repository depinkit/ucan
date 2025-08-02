# UCAN Go Library

A Go implementation of UCAN (User Controlled Authorization Networks) providing decentralized authorization tokens with capability-based security.

## Overview

UCAN (User Controlled Authorization Networks) is a specification for decentralized authorization tokens that enable secure, capability-based access control. This library provides a complete implementation for creating, delegating, and verifying UCAN tokens in Go applications.

To see UCAN in action, please check the [actor](https://github.com/depinkint/actor) implementation that relies on UCAN for security.
## Features

- **Decentralized Authorization**: Self-contained authorization tokens
- **Capability-Based Security**: Fine-grained permission control with hierarchical capabilities
- **Token Delegation**: Secure delegation of capabilities between parties
- **Revocation Support**: Secure token revocation mechanisms
- **Broadcast Tokens**: Support for pub/sub authorization patterns
- **JWT Compatible**: Familiar token format with UCAN extensions
- **Context Management**: Hierarchical capability contexts with trust anchors
- **Adversarial Testing**: Comprehensive security testing suite

## Installation

```bash
go get gitlab.com/nunet/depinkit/ucan
```

## Quick Start

### Basic Usage

```go
package main

import (
    "time"
    "gitlab.com/nunet/depinkit/ucan"
    "gitlab.com/nunet/device-management-service/lib/did"
    "gitlab.com/nunet/device-management-service/lib/crypto"
)

func main() {
    // Create a trust context
    trustCtx := did.NewTrustContext()
    
    // Create a capability context (the root authority)
    rootCtx, err := ucan.NewCapabilityContext(
        trustCtx,
        rootDID,           // Your DID
        []did.DID{},       // Trust anchors
        ucan.TokenList{},  // Required tokens
        ucan.TokenList{},  // Provided tokens
        ucan.TokenList{},  // Revocation tokens
    )
    if err != nil {
        panic(err)
    }
    
    // Start the garbage collector
    rootCtx.Start(5 * time.Minute)
    defer rootCtx.Stop()
}
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

## Usage Examples

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
