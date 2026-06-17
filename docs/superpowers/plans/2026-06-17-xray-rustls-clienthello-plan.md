# Xray Rustls ClientHello Customization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Milestone 1 and Milestone 2 ClientHello customization hooks on top of upstream `rustls 0.23.40` while keeping the crate named `rustls` and default behavior unchanged.

**Architecture:** Add a generic optional `ClientHelloCustomizer` to `ClientConfig`; each connection asks it for a `ClientHelloPlan`. Milestone 1 applies fixed random/session id and raw capture around the existing ClientHello construction path. Milestone 2 adds fixed X25519 key share material, key share observation, and custom extension ordering without adding Xray or REALITY concepts to rustls.

**Tech Stack:** Rust, rustls workspace at tag `v/0.23.40`, built-in rustls client tests, a small `tokio-rustls 0.26.4` smoke package, `cargo test`, `cargo check`.

---

## Scope Check

The approved design covers one subsystem: generic ClientHello customization in the `rustls` fork. It has two milestones, but Milestone 2 depends directly on Milestone 1's plan plumbing, so this uses one sequential plan.

GREASE placeholder support is not implemented in this plan because no selected first downstream profile has required it yet. The API should not expose GREASE controls until a real profile requires them.

## File Structure

- `rustls/src/client/client_hello.rs`: New public generic customization API. Owns `ClientHelloCustomizer`, `ClientHelloContext`, `ClientHelloPlan`, bounded public wrapper types, capture/observer traits, and validation helpers.
- `rustls/src/client/client_conn.rs`: Adds `ClientConfig::client_hello_customizer`, includes the field in `ClientConfig` defaults, and exposes a setter/getter.
- `rustls/src/client/builder.rs`: Initializes `client_hello_customizer: None` in all normal builder paths.
- `rustls/src/client/hs.rs`: Builds the per-connection `ClientHelloPlan`, applies fixed random/session id, sends fixed key share to TLS 1.3 setup, invokes raw capture at the exact emission point, and applies custom extension order.
- `rustls/src/client/tls13.rs`: Accepts an optional planned X25519 key share and returns the planned `ActiveKeyExchange` when selected.
- `rustls/src/crypto/aws_lc_rs/x25519.rs`: New aws-lc-backed fixed X25519 `ActiveKeyExchange` implementation for raw 32-byte private keys.
- `rustls/src/crypto/aws_lc_rs/mod.rs`: Exposes the new fixed X25519 helper internally.
- `rustls/src/msgs/handshake.rs`: Adds optional custom extension order support to `ClientExtensions` while preserving PSK/ECH final-position rules.
- `rustls/src/client/test.rs`: Adds byte-level customizer tests for fixed random, fixed session id, raw capture, extension ordering, negative validation, and fixed X25519 public key.
- `tokio-rustls-smoke/Cargo.toml`: New workspace smoke package proving `tokio-rustls 0.26.4` compiles against the fork.
- `tokio-rustls-smoke/src/lib.rs`: Basic async client/server handshake through `tokio_rustls::TlsConnector` and `TlsAcceptor`.
- `Cargo.toml`: Adds `tokio-rustls-smoke` as a non-default workspace member.

## Task 1: Start The `0.23.40` Branch

**Files:**
- Read: `docs/superpowers/specs/2026-06-17-xray-rustls-clienthello-design.md`
- Read: `docs/superpowers/plans/2026-06-17-xray-rustls-clienthello-plan.md`
- Modify through git: current branch metadata

- [ ] **Step 1: Confirm the working tree before switching**

Run:

```bash
git status --short
git tag --list 'v/0.23.40'
```

Expected: `v/0.23.40` is present. The only untracked file may be `xray-rustls-agent-brief.md`.

- [ ] **Step 2: Record the design and plan commits**

Run:

```bash
DESIGN_COMMIT=$(git log --format=%H -- docs/superpowers/specs/2026-06-17-xray-rustls-clienthello-design.md | head -1)
PLAN_COMMIT=$(git log --format=%H -- docs/superpowers/plans/2026-06-17-xray-rustls-clienthello-plan.md | head -1)
printf '%s\n%s\n' "$DESIGN_COMMIT" "$PLAN_COMMIT"
```

Expected: two non-empty commit hashes.

- [x] **Step 3: Use the approved `main` baseline from upstream rustls 0.23.40**

The user approved working directly in `main`. Current `main` has been reset to
`v/0.23.40`, and the previous `main` tip is preserved at
`backup/main-before-xray-v0.23`.

Verify:

```bash
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD~2
git rev-parse v/0.23.40
git rev-parse backup/main-before-xray-v0.23
```

Expected: branch is `main`, `HEAD~2` equals `v/0.23.40`, the backup branch
exists, and `rustls/Cargo.toml` says `version = "0.23.40"` and package
`name = "rustls"`.

- [x] **Step 4: Carry the design and plan docs onto `main`**

Already done by cherry-picking the design and plan commits onto the `main`
baseline.

Verify:

```bash
git log --oneline -3
```

Expected: the two docs commits are present above `Prepare 0.23.40`.

- [x] **Step 5: Commit checkpoint**

No new commit is needed here if the cherry-picks created commits. Run:

```bash
git status --short
```

Expected: no tracked changes.

## Task 2: Add Milestone 1 Failing Tests

**Files:**
- Modify: `rustls/src/client/test.rs`

- [ ] **Step 1: Add imports and test helpers**

Add these imports near the existing imports in `rustls/src/client/test.rs`:

```rust
use std::sync::{Arc as StdArc, Mutex};

use crate::client::{
    ClientHelloContext, ClientHelloCustomizer, ClientHelloPlan, ClientHelloSessionId,
};
use crate::msgs::enums::ExtensionType;
```

Add these helpers above `client_hello_sent_for_config`:

```rust
#[derive(Debug)]
struct StaticClientHelloCustomizer {
    plan: Option<ClientHelloPlan>,
}

impl ClientHelloCustomizer for StaticClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, Error> {
        Ok(self.plan.clone())
    }
}

#[derive(Debug)]
struct RecordingClientHelloCapture {
    bytes: StdArc<Mutex<Vec<u8>>>,
}

impl crate::client::CapturesClientHello for RecordingClientHelloCapture {
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), Error> {
        *self.bytes.lock().unwrap() = bytes.to_vec();
        Ok(())
    }
}

fn client_hello_record_bytes_for_config(config: ClientConfig) -> Result<Vec<u8>, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    match Message::try_from(message).unwrap() {
        Message {
            payload: MessagePayload::Handshake { encoded, .. },
            ..
        } => Ok(encoded.into_vec()),
        other => panic!("unexpected message {other:?}"),
    }
}
```

- [ ] **Step 2: Add fixed random and fixed session id tests**

Add these tests inside the existing `#[macro_rules_attribute::apply(test_for_each_provider)] mod tests` module:

```rust
    #[test]
    fn client_hello_customizer_can_fix_random() {
        let fixed_random = [0x42u8; 32];
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Some(ClientHelloPlan::new().with_random(fixed_random)),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(ch.random, Random::from(fixed_random));
    }

    #[test]
    fn client_hello_customizer_can_fix_session_id() {
        let session_id = vec![0x11, 0x22, 0x33, 0x44];
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Some(
                ClientHelloPlan::new()
                    .with_session_id(ClientHelloSessionId::try_from(session_id.clone()).unwrap()),
            ),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(ch.session_id.as_ref(), session_id.as_slice());
    }
```

- [ ] **Step 3: Add raw capture and negative validation tests**

Add these tests inside the same test module:

```rust
    #[test]
    fn client_hello_customizer_captures_raw_client_hello() {
        let captured = StdArc::new(Mutex::new(Vec::new()));
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Some(ClientHelloPlan::new().with_capture(StdArc::new(
                RecordingClientHelloCapture {
                    bytes: captured.clone(),
                },
            ))),
        }));

        let emitted = client_hello_record_bytes_for_config(config).unwrap();

        assert_eq!(*captured.lock().unwrap(), emitted);
    }

    #[test]
    fn client_hello_session_id_rejects_long_values() {
        let too_long = vec![0xaau8; 33];

        let err = ClientHelloSessionId::try_from(too_long).unwrap_err();

        assert!(matches!(err, Error::General(message) if message.contains("session id")));
    }
```

- [ ] **Step 4: Run the focused tests and verify they fail to compile**

Run:

```bash
cargo test -p rustls --lib client_hello_customizer --features aws_lc_rs
```

Expected: compile failure because `ClientHelloCustomizer`, `ClientHelloPlan`, `ClientHelloSessionId`, and `CapturesClientHello` do not exist yet.

- [ ] **Step 5: Commit failing tests**

Run:

```bash
git add rustls/src/client/test.rs
git commit -m "test: add clienthello customizer milestone 1 coverage"
```

Expected: one test-only commit.

## Task 3: Add The Public Customizer API

**Files:**
- Create: `rustls/src/client/client_hello.rs`
- Modify: `rustls/src/lib.rs`
- Modify: `rustls/src/client/client_conn.rs`
- Modify: `rustls/src/client/builder.rs`

- [ ] **Step 1: Create the public API module**

Create `rustls/src/client/client_hello.rs`:

```rust
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::fmt;

use pki_types::ServerName;

use crate::crypto::CryptoProvider;
use crate::sync::Arc;
use crate::{Error, SupportedProtocolVersion};

/// Builds an optional per-connection ClientHello customization plan.
pub trait ClientHelloCustomizer: fmt::Debug + Send + Sync {
    /// Return `Ok(None)` to use upstream rustls ClientHello behavior.
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, Error>;
}

/// Generic information available while rustls is constructing a ClientHello.
#[derive(Clone, Copy, Debug)]
pub struct ClientHelloContext<'a> {
    pub server_name: &'a ServerName<'static>,
    pub alpn_protocols: &'a [Vec<u8>],
    pub versions: &'a [&'static SupportedProtocolVersion],
    pub crypto_provider: &'a Arc<CryptoProvider>,
    pub is_quic: bool,
}

/// Receives the exact encoded ClientHello handshake message.
pub trait CapturesClientHello: fmt::Debug + Send + Sync {
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), Error>;
}

/// Receives the X25519 key share material used in the ClientHello.
pub trait ObservesX25519KeyShare: fmt::Debug + Send + Sync {
    fn observe_x25519_key_share(&self, public_key: &[u8; 32]) -> Result<(), Error>;
}

/// A bounded legacy session id for ClientHello customization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloSessionId(Vec<u8>);

impl ClientHelloSessionId {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for ClientHelloSessionId {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > 32 {
            return Err(Error::General(
                "ClientHello session id cannot exceed 32 bytes".into(),
            ));
        }
        Ok(Self(value))
    }
}

impl AsRef<[u8]> for ClientHelloSessionId {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A TLS extension type represented by its IANA u16 value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientHelloExtensionType(pub u16);

/// Explicit order for all non-forced ClientHello extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloExtensionOrder(Vec<ClientHelloExtensionType>);

impl ClientHelloExtensionOrder {
    pub fn as_slice(&self) -> &[ClientHelloExtensionType] {
        &self.0
    }
}

impl TryFrom<Vec<u16>> for ClientHelloExtensionOrder {
    type Error = Error;

    fn try_from(value: Vec<u16>) -> Result<Self, Self::Error> {
        let mut seen = BTreeSet::new();
        for extension in &value {
            if !seen.insert(*extension) {
                return Err(Error::General(
                    "ClientHello extension order contains a duplicate extension".into(),
                ));
            }
        }

        Ok(Self(
            value
                .into_iter()
                .map(ClientHelloExtensionType)
                .collect(),
        ))
    }
}

/// Fixed X25519 key share material.
#[derive(Clone, Debug)]
pub struct FixedX25519KeyShare {
    private_key: [u8; 32],
    observer: Option<Arc<dyn ObservesX25519KeyShare>>,
}

impl FixedX25519KeyShare {
    pub fn new(private_key: [u8; 32]) -> Self {
        Self {
            private_key,
            observer: None,
        }
    }

    pub fn with_observer(mut self, observer: Arc<dyn ObservesX25519KeyShare>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub(crate) fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    pub(crate) fn observer(&self) -> Option<&Arc<dyn ObservesX25519KeyShare>> {
        self.observer.as_ref()
    }
}

/// Per-connection ClientHello customization plan.
#[derive(Clone, Debug, Default)]
pub struct ClientHelloPlan {
    pub(crate) random: Option<[u8; 32]>,
    pub(crate) session_id: Option<ClientHelloSessionId>,
    pub(crate) capture: Option<Arc<dyn CapturesClientHello>>,
    pub(crate) fixed_x25519: Option<FixedX25519KeyShare>,
    pub(crate) extension_order: Option<ClientHelloExtensionOrder>,
}

impl ClientHelloPlan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_random(mut self, random: [u8; 32]) -> Self {
        self.random = Some(random);
        self
    }

    pub fn with_session_id(mut self, session_id: ClientHelloSessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_capture(mut self, capture: Arc<dyn CapturesClientHello>) -> Self {
        self.capture = Some(capture);
        self
    }

    pub fn with_fixed_x25519(mut self, key_share: FixedX25519KeyShare) -> Self {
        self.fixed_x25519 = Some(key_share);
        self
    }

    pub fn with_extension_order(mut self, order: ClientHelloExtensionOrder) -> Self {
        self.extension_order = Some(order);
        self
    }
}
```

- [ ] **Step 2: Export the module from `rustls/src/lib.rs`**

Change the `pub mod client` block in `rustls/src/lib.rs`:

```rust
pub mod client {
    pub(super) mod builder;
    mod client_conn;
    mod client_hello;
    mod common;
```

Update the `pub use client_conn` and client exports:

```rust
    pub use client_conn::{
        ClientConfig, ClientConnectionData, ClientSessionStore, EarlyDataError, ResolvesClientCert,
        Resumption, Tls12Resumption, UnbufferedClientConnection,
    };
    pub use client_hello::{
        CapturesClientHello, ClientHelloContext, ClientHelloCustomizer,
        ClientHelloExtensionOrder, ClientHelloExtensionType, ClientHelloPlan,
        ClientHelloSessionId, FixedX25519KeyShare, ObservesX25519KeyShare,
    };
```

- [ ] **Step 3: Add the config field**

In `rustls/src/client/client_conn.rs`, add an import:

```rust
use super::client_hello::ClientHelloCustomizer;
```

Add this field to `ClientConfig` after `alpn_protocols`:

```rust
    /// Optional generic ClientHello customizer.
    ///
    /// If this is `None`, rustls emits the same ClientHello it would emit upstream.
    pub client_hello_customizer: Option<Arc<dyn ClientHelloCustomizer>>,
```

Add this accessor in `impl ClientConfig`:

```rust
    /// Return the configured ClientHello customizer, if any.
    pub fn client_hello_customizer(&self) -> Option<&Arc<dyn ClientHelloCustomizer>> {
        self.client_hello_customizer.as_ref()
    }
```

- [ ] **Step 4: Initialize the config field**

In `rustls/src/client/builder.rs`, add the field to `ClientConfig { ... }` in `with_client_cert_resolver`:

```rust
            client_hello_customizer: None,
```

- [ ] **Step 5: Run tests and verify Milestone 1 tests still fail behaviorally**

Run:

```bash
cargo test -p rustls --lib client_hello_customizer --features aws_lc_rs
```

Expected: compile succeeds far enough to show assertion failures for fixed random/session id/capture, because the plan is not wired into `hs.rs` yet.

- [ ] **Step 6: Commit API skeleton**

Run:

```bash
git add rustls/src/client/client_hello.rs rustls/src/lib.rs rustls/src/client/client_conn.rs rustls/src/client/builder.rs
git commit -m "feat: add clienthello customizer api"
```

## Task 4: Wire Milestone 1 Random, Session Id, And Raw Capture

**Files:**
- Modify: `rustls/src/client/hs.rs`
- Modify: `rustls/src/msgs/handshake.rs`

- [ ] **Step 1: Add a conversion from public session id to internal session id**

In `rustls/src/msgs/handshake.rs`, add this method to `impl SessionId`:

```rust
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidMessage> {
        if bytes.len() > 32 {
            return Err(InvalidMessage::TrailingData("SessionID"));
        }

        let mut data = [0u8; 32];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            len: bytes.len(),
            data,
        })
    }
```

- [ ] **Step 2: Build and store the plan in `ClientHelloInput`**

In `rustls/src/client/hs.rs`, add imports:

```rust
use crate::client::{ClientHelloContext, ClientHelloPlan};
use crate::versions;
```

Add a `plan` field to `ClientHelloInput`:

```rust
    pub(super) plan: Option<ClientHelloPlan>,
```

In `ClientHelloInput::new`, after `let hello = ClientHelloDetails::new(...)`, build the plan:

```rust
        let versions: Vec<_> = versions::ALL_VERSIONS
            .iter()
            .copied()
            .filter(|version| config.supports_version(version.version))
            .collect();
        let plan = match config.client_hello_customizer.as_ref() {
            Some(customizer) => customizer.build_client_hello_plan(ClientHelloContext {
                server_name: &server_name,
                alpn_protocols: extra_exts.protocols.as_deref().unwrap_or_default(),
                versions: &versions,
                crypto_provider: &config.provider,
                is_quic: cx.common.is_quic(),
            })?,
            None => None,
        };
```

Replace the `random` and `session_id` values used in `Ok(Self { ... })`:

```rust
        let random = plan
            .as_ref()
            .and_then(|plan| plan.random)
            .map(Random::from)
            .unwrap_or(Random::new(config.provider.secure_random)?);

        let session_id = match plan
            .as_ref()
            .and_then(|plan| plan.session_id.as_ref())
        {
            Some(custom_session_id) => SessionId::from_bytes(custom_session_id.as_slice())
                .map_err(|_| Error::General("invalid ClientHello session id".into()))?,
            None => session_id,
        };
```

Add `plan` to the returned struct:

```rust
            plan,
```

- [ ] **Step 3: Invoke raw capture at the exact emission point**

In `emit_client_hello_for_retry`, after `let ch = Message { ... };` and before `trace!("Sending ClientHello {ch:#?}");`, add:

```rust
    if let Some(capture) = input
        .plan
        .as_ref()
        .and_then(|plan| plan.capture.as_ref())
    {
        capture.capture_client_hello(&ch.get_encoding())?;
    }
```

- [ ] **Step 4: Preserve plan through TLS 1.2 destructuring**

In `rustls/src/client/tls12.rs`, any destructuring of `ClientHelloInput` must ignore `plan` explicitly:

```rust
                plan: _,
```

Use `cargo test` compile errors to find each `ClientHelloInput { ... }` pattern and add the field.

- [ ] **Step 5: Run Milestone 1 focused tests**

Run:

```bash
cargo test -p rustls --lib client_hello_customizer --features aws_lc_rs
```

Expected: all Milestone 1 customizer tests pass.

- [ ] **Step 6: Commit Milestone 1 wiring**

Run:

```bash
git add rustls/src/client/hs.rs rustls/src/client/tls12.rs rustls/src/msgs/handshake.rs
git commit -m "feat: wire clienthello random session id capture"
```

## Task 5: Add The Tokio Rustls Smoke Package

**Files:**
- Modify: `Cargo.toml`
- Create: `tokio-rustls-smoke/Cargo.toml`
- Create: `tokio-rustls-smoke/src/lib.rs`

- [ ] **Step 1: Add workspace member**

In the root `Cargo.toml`, add the package to `members` near `connect-tests`:

```toml
  # tokio-rustls compatibility smoke test
  "tokio-rustls-smoke",
```

Do not add it to `default-members`.

- [ ] **Step 2: Create smoke package manifest**

Create `tokio-rustls-smoke/Cargo.toml`:

```toml
[package]
name = "tokio-rustls-smoke"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
rcgen = { workspace = true }
rustls = { path = "../rustls" }
tokio = { version = "1.52.3", features = ["io-util", "macros", "rt"] }
tokio-rustls = "0.26.4"
```

- [ ] **Step 3: Create async handshake smoke test**

Create `tokio-rustls-smoke/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
    use rustls::{
        ClientConfig, DigitallySignedStruct, Error, RootCertStore, ServerConfig,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[derive(Debug)]
    struct AcceptAnyServerCert;

    impl ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    #[tokio::test]
    async fn tokio_rustls_connector_uses_local_rustls_fork() -> io::Result<()> {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_chain = vec![CertificateDer::from(cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            signing_key.serialize_der(),
        ));

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();

        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let connector = TlsConnector::from(Arc::new(client_config));
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let mut stream = acceptor.accept(server_io).await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut client = connector
            .connect(ServerName::try_from("localhost").unwrap(), client_io)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        server.await.unwrap();
        Ok(())
    }
}
```

- [ ] **Step 4: Run the smoke test**

Run:

```bash
cargo test -p tokio-rustls-smoke
```

Expected: test passes and `Cargo.lock` records `tokio-rustls 0.26.4`.

- [ ] **Step 5: Commit smoke package**

Run:

```bash
git add Cargo.toml Cargo.lock tokio-rustls-smoke
git commit -m "test: add tokio rustls compatibility smoke"
```

## Task 6: Add Milestone 2 Fixed X25519 Failing Tests

**Files:**
- Modify: `rustls/src/client/test.rs`

- [ ] **Step 1: Add key share observer helper**

Add this helper near `RecordingClientHelloCapture`:

```rust
#[derive(Debug)]
struct RecordingX25519KeyShare {
    public_key: StdArc<Mutex<Option<[u8; 32]>>>,
}

impl crate::client::ObservesX25519KeyShare for RecordingX25519KeyShare {
    fn observe_x25519_key_share(&self, public_key: &[u8; 32]) -> Result<(), Error> {
        *self.public_key.lock().unwrap() = Some(*public_key);
        Ok(())
    }
}
```

- [ ] **Step 2: Add fixed X25519 public key test**

Add this test inside the existing test module:

```rust
    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_customizer_can_fix_x25519_key_share() {
        let private_key = hex::decode(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let expected_public = hex::decode(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        )
        .unwrap();
        let observed_public = StdArc::new(Mutex::new(None));
        let mut config =
            ClientConfig::builder_with_provider(x25519_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Some(ClientHelloPlan::new().with_fixed_x25519(
                crate::client::FixedX25519KeyShare::new(private_key).with_observer(StdArc::new(
                    RecordingX25519KeyShare {
                        public_key: observed_public.clone(),
                    },
                )),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        let key_share = ch
            .extensions
            .key_shares
            .as_ref()
            .unwrap()
            .iter()
            .find(|share| share.group == NamedGroup::X25519)
            .unwrap();
        assert_eq!(key_share.payload.0.as_slice(), expected_public.as_slice());
        assert_eq!(
            observed_public.lock().unwrap().unwrap().as_slice(),
            expected_public.as_slice()
        );
    }
```

- [ ] **Step 3: Add transcript-continuity smoke through a full handshake**

Add this test inside the same module:

```rust
    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn fixed_x25519_key_share_completes_tls13_handshake() {
        let private_key = [7u8; 32];
        let provider = x25519_provider();
        let mut client_config =
            ClientConfig::builder_with_provider(provider.clone().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        client_config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Some(
                ClientHelloPlan::new()
                    .with_fixed_x25519(crate::client::FixedX25519KeyShare::new(private_key)),
            ),
        }));
        let server_config = rustls_test::make_server_config(rustls_test::KeyType::Rsa, &provider);
        let (mut client, mut server) =
            rustls_test::make_pair_for_configs(client_config, server_config);

        rustls_test::do_handshake(&mut client, &mut server);

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }
```

- [ ] **Step 4: Add unsupported provider negative test**

Add this test outside provider-specific helpers if the crate is built with `ring`:

```rust
    #[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
    #[test]
    fn fixed_x25519_without_aws_lc_fails_loudly() {
        let mut config =
            ClientConfig::builder_with_provider(x25519_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Some(
                ClientHelloPlan::new()
                    .with_fixed_x25519(crate::client::FixedX25519KeyShare::new([1u8; 32])),
            ),
        }));

        let err = ClientConnection::new(
            config.into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap_err();

        assert!(matches!(err, Error::General(message) if message.contains("X25519")));
    }
```

- [ ] **Step 5: Run focused tests and verify they fail**

Run:

```bash
cargo test -p rustls --lib fixed_x25519 --features aws_lc_rs
```

Expected: compile failure or test failure because fixed X25519 key share is not wired yet.

- [ ] **Step 6: Commit failing Milestone 2 tests**

Run:

```bash
git add rustls/src/client/test.rs
git commit -m "test: add fixed x25519 clienthello coverage"
```

## Task 7: Implement Fixed X25519 Key Share

**Files:**
- Create: `rustls/src/crypto/aws_lc_rs/x25519.rs`
- Modify: `rustls/src/crypto/aws_lc_rs/mod.rs`
- Modify: `rustls/src/client/tls13.rs`
- Modify: `rustls/src/client/hs.rs`

- [ ] **Step 1: Add aws-lc fixed X25519 implementation**

Create `rustls/src/crypto/aws_lc_rs/x25519.rs`:

```rust
use alloc::boxed::Box;

use crate::crypto::{ActiveKeyExchange, FfdheGroup, SharedSecret};
use crate::msgs::enums::NamedGroup;
use crate::{Error, PeerMisbehaved};

use super::ring_like::agreement;

pub(crate) fn start_fixed_x25519(
    private_key: &[u8; 32],
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let private_key =
        agreement::PrivateKey::from_private_key(&agreement::X25519, private_key)
            .map_err(super::unspecified_err)?;
    let public_key = private_key
        .compute_public_key()
        .map_err(super::unspecified_err)?;

    Ok(Box::new(FixedX25519 {
        private_key,
        public_key: public_key.as_ref().try_into().map_err(|_| {
            Error::General("aws-lc X25519 public key was not 32 bytes".into())
        })?,
    }))
}

struct FixedX25519 {
    private_key: agreement::PrivateKey,
    public_key: [u8; 32],
}

impl ActiveKeyExchange for FixedX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != 32 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }

        let peer_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_pub_key);
        agreement::agree(
            &self.private_key,
            &peer_key,
            (),
            |secret| Ok(SharedSecret::from(secret)),
        )
        .map_err(|_| PeerMisbehaved::InvalidKeyShare.into())
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
```

- [ ] **Step 2: Expose the helper internally**

In `rustls/src/crypto/aws_lc_rs/mod.rs`, add:

```rust
pub(crate) mod x25519;
```

- [ ] **Step 3: Accept planned key share in TLS 1.3 setup**

In `rustls/src/client/tls13.rs`, change `initial_key_share` to accept a plan:

```rust
pub(super) fn initial_key_share(
    config: &ClientConfig,
    server_name: &ServerName<'_>,
    kx_state: &mut KxState,
    plan: Option<&ClientHelloPlan>,
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
```

After selecting `group`, before `*kx_state = KxState::Start(group);`, add:

```rust
    if let Some(fixed_x25519) = plan.and_then(|plan| plan.fixed_x25519.as_ref()) {
        if group.name() != NamedGroup::X25519 {
            return Err(Error::General(
                "fixed X25519 key share requires X25519 to be the selected group".into(),
            ));
        }

        #[cfg(feature = "aws_lc_rs")]
        {
            let key_exchange =
                crate::crypto::aws_lc_rs::x25519::start_fixed_x25519(fixed_x25519.private_key())?;
            let public_key: &[u8; 32] = key_exchange.pub_key().try_into().map_err(|_| {
                Error::General("fixed X25519 public key was not 32 bytes".into())
            })?;
            if let Some(observer) = fixed_x25519.observer() {
                observer.observe_x25519_key_share(public_key)?;
            }
            *kx_state = KxState::Start(group);
            return Ok(key_exchange);
        }

        #[cfg(not(feature = "aws_lc_rs"))]
        {
            return Err(Error::General(
                "fixed X25519 key share requires the aws_lc_rs feature".into(),
            ));
        }
    }
```

- [ ] **Step 4: Pass the plan from `ClientHelloInput::start_handshake`**

In `rustls/src/client/hs.rs`, update the `tls13::initial_key_share` call:

```rust
            Some(tls13::initial_key_share(
                &self.config,
                &self.server_name,
                &mut cx.common.kx_state,
                self.plan.as_ref(),
            )?)
```

- [ ] **Step 5: Run fixed X25519 tests**

Run:

```bash
cargo test -p rustls --lib fixed_x25519 --features aws_lc_rs
```

Expected: fixed X25519 public key and full TLS 1.3 handshake tests pass.

- [ ] **Step 6: Commit fixed X25519 support**

Run:

```bash
git add rustls/src/crypto/aws_lc_rs/x25519.rs rustls/src/crypto/aws_lc_rs/mod.rs rustls/src/client/tls13.rs rustls/src/client/hs.rs
git commit -m "feat: add fixed x25519 clienthello key share"
```

## Task 8: Add Extension Order Customization

**Files:**
- Modify: `rustls/src/client/test.rs`
- Modify: `rustls/src/client/hs.rs`
- Modify: `rustls/src/msgs/handshake.rs`

- [ ] **Step 1: Add failing extension-order test**

Add this test inside `rustls/src/client/test.rs` test module:

```rust
    #[test]
    fn client_hello_customizer_can_fix_extension_order() {
        let order = crate::client::ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::SupportedGroups),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
        ])
        .unwrap();
        let mut config =
            ClientConfig::builder_with_provider(x25519_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Some(ClientHelloPlan::new().with_extension_order(order)),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(
            ch.extensions.used_extensions_in_encoding_order(),
            vec![
                ExtensionType::SupportedVersions,
                ExtensionType::ServerName,
                ExtensionType::SignatureAlgorithms,
                ExtensionType::SupportedGroups,
                ExtensionType::ECPointFormats,
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::StatusRequest,
                ExtensionType::KeyShare,
                ExtensionType::PSKKeyExchangeModes,
            ]
        );
    }
```

- [ ] **Step 2: Add internal field and validation to `ClientExtensions`**

In the `ClientExtensions` extra fields block in `rustls/src/msgs/handshake.rs`, add:

```rust
        /// Optional full order for extensions that are not forced to the final positions.
        pub(crate) custom_order: Option<Vec<ExtensionType>>,
```

Carry `custom_order` through `into_owned`.

Add this method in `impl ClientExtensions<'_>`:

```rust
    pub(crate) fn set_custom_order(&mut self, order: Vec<ExtensionType>) -> Result<(), Error> {
        let mut required = self.collect_used();
        required.retain(|ext| {
            !matches!(
                ext,
                ExtensionType::PreSharedKey
                    | ExtensionType::EncryptedClientHello
                    | ExtensionType::EncryptedClientHelloOuterExtensions
            )
        });
        required.sort();

        let mut provided = order.clone();
        provided.sort();

        if required != provided {
            return Err(Error::General(
                "ClientHello extension order must contain every non-final emitted extension exactly once".into(),
            ));
        }

        self.custom_order = Some(order);
        Ok(())
    }
```

Add `use crate::Error;` near the top of `handshake.rs`.

Update `used_extensions_in_encoding_order`:

```rust
        let mut exts = match &self.custom_order {
            Some(order) => order.clone(),
            None => self.order_insensitive_extensions_in_random_order(),
        };
```

- [ ] **Step 3: Apply plan extension order after all extensions are known**

In `rustls/src/client/hs.rs`, after ECH/GREASE mutation and before `input.hello.sent_extensions = chp_payload.collect_used();`, add:

```rust
    if let Some(order) = input
        .plan
        .as_ref()
        .and_then(|plan| plan.extension_order.as_ref())
    {
        let order = order
            .as_slice()
            .iter()
            .map(|extension| ExtensionType::from(extension.0))
            .collect();
        chp_payload.extensions.set_custom_order(order)?;
    }
```

- [ ] **Step 4: Run extension-order test**

Run:

```bash
cargo test -p rustls --lib client_hello_customizer_can_fix_extension_order --features aws_lc_rs
```

Expected: test passes.

- [ ] **Step 5: Commit extension order support**

Run:

```bash
git add rustls/src/client/test.rs rustls/src/client/hs.rs rustls/src/msgs/handshake.rs
git commit -m "feat: add clienthello extension order control"
```

## Task 9: Final Verification

**Files:**
- Read: all modified files

- [ ] **Step 1: Run focused rustls tests**

Run:

```bash
cargo test -p rustls --lib client_hello_customizer --features aws_lc_rs
cargo test -p rustls --lib fixed_x25519 --features aws_lc_rs
cargo test -p rustls --lib client_hello_customizer_can_fix_extension_order --features aws_lc_rs
```

Expected: all pass.

- [ ] **Step 2: Run tokio smoke**

Run:

```bash
cargo test -p tokio-rustls-smoke
```

Expected: async `tokio_rustls::TlsConnector` and `TlsAcceptor` handshake passes.

- [ ] **Step 3: Run broader package tests**

Run:

```bash
cargo test -p rustls --features aws_lc_rs
```

Expected: rustls package tests pass.

- [ ] **Step 4: Check package identity**

Run:

```bash
rg -n '^name = "rustls"|^version = "0.23.40"' rustls/Cargo.toml
```

Expected:

```text
name = "rustls"
version = "0.23.40"
```

- [ ] **Step 5: Review default-path impact**

Run:

```bash
git diff v/0.23.40 -- rustls/src/client/client_conn.rs rustls/src/client/hs.rs rustls/src/msgs/handshake.rs
```

Expected: all behavior changes are behind `client_hello_customizer`, `ClientHelloPlan`, or `custom_order: Some`.

- [ ] **Step 6: Final commit if verification fixes were needed**

If verification required small fixes, commit them:

```bash
git add rustls tokio-rustls-smoke Cargo.toml Cargo.lock
git commit -m "fix: polish clienthello customizer verification"
```

Expected: either no changes to commit or one focused fix commit.

## Self-Review Notes

- Spec coverage: Milestone 1 is covered by Tasks 2-5. Milestone 2 is covered by Tasks 6-8. Baseline `0.23.40` is covered by Task 1. Tokio compatibility is covered by Task 5.
- Default behavior: the plan stores `None` by default and only checks custom behavior when a customizer returns `Some(ClientHelloPlan)`.
- Xray separation: no public type mentions Xray, REALITY, VLESS, or fingerprint names.
- Type consistency: the API names introduced in Task 3 are the same names used by all tests and wiring tasks.
- Known implementation risk: the fixed X25519 implementation uses the public `aws_lc_rs::agreement::PrivateKey::from_private_key` and `aws_lc_rs::agreement::agree` APIs. Keep all backend-specific code private to `rustls/src/crypto/aws_lc_rs/x25519.rs`.
