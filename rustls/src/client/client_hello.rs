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
    /// The server name for this connection.
    pub server_name: &'a ServerName<'static>,
    /// ALPN protocols configured for this connection.
    pub alpn_protocols: &'a [Vec<u8>],
    /// Protocol versions enabled for this connection.
    pub versions: &'a [&'static SupportedProtocolVersion],
    /// Crypto provider used for this connection.
    pub crypto_provider: &'a Arc<CryptoProvider>,
    /// Whether this connection is using QUIC.
    pub is_quic: bool,
}

/// Receives the exact encoded ClientHello handshake message.
pub trait CapturesClientHello: fmt::Debug + Send + Sync {
    /// Captures the encoded ClientHello handshake message.
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), Error>;
}

/// Receives the X25519 key share material used in the ClientHello.
pub trait ObservesX25519KeyShare: fmt::Debug + Send + Sync {
    /// Observes the encoded X25519 public key.
    fn observe_x25519_key_share(&self, public_key: &[u8; 32]) -> Result<(), Error>;
}

/// A bounded legacy session id for ClientHello customization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloSessionId(Vec<u8>);

impl ClientHelloSessionId {
    /// Return the encoded session id bytes.
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
    /// Return the ordered extension types.
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
///
/// Using a fixed key share disables the normal forward secrecy properties
/// provided by generating fresh ephemeral key material for each handshake.
/// This type retains the private key material in memory and is intended only
/// for specialized compatibility and testing scenarios.
#[derive(Clone)]
pub struct FixedX25519KeyShare {
    #[allow(dead_code)]
    private_key: [u8; 32],
    observer: Option<Arc<dyn ObservesX25519KeyShare>>,
}

impl fmt::Debug for FixedX25519KeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedX25519KeyShare")
            .field("private_key", &"<redacted>")
            .field("observer_present", &self.observer.is_some())
            .finish()
    }
}

impl FixedX25519KeyShare {
    /// Create a fixed X25519 key share from private key material.
    ///
    /// This disables the normal forward secrecy properties provided by fresh
    /// ephemeral key shares and retains the private key material in memory.
    /// It is intended only for specialized compatibility and testing
    /// scenarios.
    pub fn new(private_key: [u8; 32]) -> Self {
        Self {
            private_key,
            observer: None,
        }
    }

    /// Register an observer for the public key derived from this key share.
    pub fn with_observer(mut self, observer: Arc<dyn ObservesX25519KeyShare>) -> Self {
        self.observer = Some(observer);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    #[allow(dead_code)]
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
    /// Create an empty customization plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use fixed ClientHello random bytes.
    pub fn with_random(mut self, random: [u8; 32]) -> Self {
        self.random = Some(random);
        self
    }

    /// Use a fixed legacy session id.
    pub fn with_session_id(mut self, session_id: ClientHelloSessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Capture the encoded ClientHello.
    pub fn with_capture(mut self, capture: Arc<dyn CapturesClientHello>) -> Self {
        self.capture = Some(capture);
        self
    }

    /// Use fixed X25519 key share material.
    pub fn with_fixed_x25519(mut self, key_share: FixedX25519KeyShare) -> Self {
        self.fixed_x25519 = Some(key_share);
        self
    }

    /// Use an explicit ClientHello extension order.
    pub fn with_extension_order(mut self, order: ClientHelloExtensionOrder) -> Self {
        self.extension_order = Some(order);
        self
    }
}
