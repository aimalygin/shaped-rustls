#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc as StdArc, Mutex};

use pki_types::{CertificateDer, ServerName};

use crate::client::{
    ClientConfig, ClientConnection, ClientHelloContext, ClientHelloCustomizer,
    ClientHelloExtensionOrder, ClientHelloPlan, ClientHelloSessionId, Resumption, Tls12Resumption,
};
use crate::crypto::CryptoProvider;
use crate::enums::{CipherSuite, ProtocolVersion, SignatureScheme};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::Reader;
use crate::msgs::enums::{Compression, ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, EncryptedClientHello, HandshakeMessagePayload,
    HandshakePayload, HelloRetryRequest, Random, ServerHelloPayload, SessionId,
    SupportedEcPointFormats,
};
use crate::msgs::message::{Message, MessagePayload, OutboundOpaqueMessage};
use crate::sync::Arc;
use crate::{Error, PeerIncompatible, PeerMisbehaved, RootCertStore};

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use std::sync::OnceLock;

    use super::super::*;
    use crate::client::AlwaysResolvesClientRawPublicKeys;
    use crate::crypto::cipher::MessageEncrypter;
    use crate::crypto::tls13::OkmBlock;
    use crate::enums::CertificateType;
    use crate::msgs::base::PayloadU8;
    use crate::msgs::enums::ECCurveType;
    use crate::msgs::handshake::{
        CertificateChain, EcParameters, HelloRetryRequestExtensions, KeyShareEntry,
        ServerEcdhParams, ServerExtensions, ServerKeyExchange, ServerKeyExchangeParams,
        ServerKeyExchangePayload,
    };
    use crate::msgs::message::PlainMessage;
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{PrivateKeyDer, UnixTime};
    #[cfg(feature = "aws_lc_rs")]
    use crate::server::{ServerConfig, ServerConnection};
    use crate::sign::CertifiedKey;
    use crate::tls13::key_schedule::{derive_traffic_iv, derive_traffic_key};
    use crate::verify::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use crate::{DigitallySignedStruct, DistinguishedName, KeyLog, version};

    /// Tests that session_ticket(35) extension
    /// is not sent if the client does not support TLS 1.2.
    #[test]
    fn test_no_session_ticket_request_on_tls_1_3() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.resumption = Resumption::in_memory_sessions(128)
            .tls12_resumption(Tls12Resumption::SessionIdOrTickets);
        let ch = client_hello_sent_for_config(config).unwrap();
        assert!(ch.extensions.session_ticket.is_none());
    }

    #[test]
    fn test_no_renegotiation_scsv_on_tls_1_3() {
        let ch = client_hello_sent_for_config(
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth(),
        )
        .unwrap();
        assert!(
            !ch.cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        );
    }

    #[test]
    fn test_client_does_not_offer_sha1() {
        for version in crate::ALL_VERSIONS {
            let config =
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots())
                    .with_no_client_auth();
            let ch = client_hello_sent_for_config(config).unwrap();
            assert!(
                !ch.extensions
                    .signature_schemes
                    .as_ref()
                    .unwrap()
                    .contains(&SignatureScheme::RSA_PKCS1_SHA1),
                "sha1 unexpectedly offered"
            );
        }
    }

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
            plan: Mutex::new(Some(ClientHelloPlan::new().with_random(fixed_random))),
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
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_session_id(ClientHelloSessionId::try_from(session_id.clone()).unwrap()),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(ch.session_id.as_ref(), session_id.as_slice());
    }

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
            plan: Mutex::new(Some(ClientHelloPlan::new().with_capture(StdArc::new(
                RecordingClientHelloCapture {
                    bytes: captured.clone(),
                },
            )))),
        }));

        let emitted = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(*captured.lock().unwrap(), emitted);
    }

    #[test]
    fn client_hello_customizer_can_fix_extension_order() {
        let order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_extension_order(order))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(
            ch.extensions
                .used_extensions_in_encoding_order(),
            vec![
                ExtensionType::SupportedVersions,
                ExtensionType::ServerName,
                ExtensionType::SignatureAlgorithms,
                ExtensionType::EllipticCurves,
                ExtensionType::ECPointFormats,
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::StatusRequest,
                ExtensionType::KeyShare,
                ExtensionType::PSKKeyExchangeModes,
            ]
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_missing_emitted_extension() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());
        extensions.ec_point_formats = Some(SupportedEcPointFormats::default());

        assert!(
            extensions
                .set_custom_order(vec![ExtensionType::ExtendedMasterSecret])
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_extra_non_emitted_extension() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());

        assert!(
            extensions
                .set_custom_order(vec![
                    ExtensionType::ExtendedMasterSecret,
                    ExtensionType::ECPointFormats,
                ])
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_duplicate_extension() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());

        assert!(
            extensions
                .set_custom_order(vec![
                    ExtensionType::ExtendedMasterSecret,
                    ExtensionType::ExtendedMasterSecret,
                ])
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_forced_final_extension() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());
        extensions.encrypted_client_hello = Some(EncryptedClientHello::Inner);

        assert!(
            extensions
                .set_custom_order(vec![
                    ExtensionType::ExtendedMasterSecret,
                    ExtensionType::EncryptedClientHello,
                ])
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_contiguous_extension_and_appends_it_once() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());
        extensions.ec_point_formats = Some(SupportedEcPointFormats::default());
        extensions
            .contiguous_extensions
            .push(ExtensionType::ECPointFormats);

        assert!(
            extensions
                .set_custom_order(vec![
                    ExtensionType::ExtendedMasterSecret,
                    ExtensionType::ECPointFormats,
                ])
                .is_err()
        );
        extensions
            .set_custom_order(vec![ExtensionType::ExtendedMasterSecret])
            .unwrap();

        assert_eq!(
            extensions.used_extensions_in_encoding_order(),
            vec![
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::ECPointFormats,
            ]
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_customizer_can_set_fixed_x25519_key_share() {
        let private_key =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let observed_public = StdArc::new(Mutex::new(None));
        let mut config = ClientConfig::builder_with_provider(aws_lc_x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_fixed_x25519(
                crate::client::FixedX25519KeyShare::new(private_key).with_observer(StdArc::new(
                    RecordingX25519KeyShare {
                        public_key: observed_public.clone(),
                    },
                )),
            ))),
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
            observed_public
                .lock()
                .unwrap()
                .unwrap()
                .as_slice(),
            expected_public.as_slice()
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn fixed_x25519_key_share_completes_tls13_handshake() {
        let private_key =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let observed_public = StdArc::new(Mutex::new(None));
        let provider = aws_lc_x25519_provider();
        let mut client_config = ClientConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        client_config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_fixed_x25519(
                    crate::client::FixedX25519KeyShare::new(private_key).with_observer(
                        StdArc::new(RecordingX25519KeyShare {
                            public_key: observed_public.clone(),
                        }),
                    ),
                ),
            )),
        }));
        let server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();
        let mut client = ClientConnection::new(
            client_config.into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(server_config.into()).unwrap();

        do_handshake(&mut client, &mut server);

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert_eq!(
            observed_public
                .lock()
                .unwrap()
                .unwrap()
                .as_slice(),
            expected_public.as_slice()
        );
    }

    #[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
    #[test]
    fn fixed_x25519_without_aws_lc_fails_loudly() {
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_fixed_x25519(crate::client::FixedX25519KeyShare::new([1u8; 32])),
            )),
        }));

        let err = ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
            .unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("X25519"));
        assert!(message.contains("aws_lc_rs") || message.contains("aws-lc"));
    }

    #[test]
    fn client_hello_customizer_session_id_rejects_long_values() {
        let too_long = vec![0xaau8; 33];

        assert!(ClientHelloSessionId::try_from(too_long).is_err());
    }

    #[test]
    fn test_client_rejects_hrr_with_varied_session_id() {
        let config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        // server replies with HRR, but does not echo `session_id` as required.
        let hrr = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: HelloRetryRequestExtensions {
                        cookie: Some(PayloadU16::new(vec![1, 2, 3, 4])),
                        ..HelloRetryRequestExtensions::default()
                    },
                }),
            )),
        };

        conn.read_tls(&mut hrr.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId.into()
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        if config.provider.fips() {
            assert!(config.require_ems);
        } else {
            config.require_ems = true;
        }

        let config = Arc::new(config);
        let mut conn =
            ClientConnection::new(config.clone(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random::new(config.provider.secure_random).unwrap(),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions::default()),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets(),
            Err(PeerIncompatible::ExtendedMasterSecretExtensionRequired.into())
        );
    }

    #[test]
    fn cas_extension_in_client_hello_if_server_verifier_requests_it() {
        let cas_sending_server_verifier =
            ServerVerifierWithAuthorityNames(vec![DistinguishedName::from(b"hello".to_vec())]);

        for (protocol_version, cas_extension_expected) in
            [(&version::TLS12, false), (&version::TLS13, true)]
        {
            let client_hello = client_hello_sent_for_config(
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[protocol_version])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(cas_sending_server_verifier.clone()))
                    .with_no_client_auth(),
            )
            .unwrap();
            assert_eq!(
                client_hello
                    .extensions
                    .certificate_authority_names
                    .is_some(),
                cas_extension_expected
            );
        }
    }

    /// Regression test for <https://github.com/seanmonstar/reqwest/issues/2191>
    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_with_custom_verifier_can_accept_ecdsa_sha1_signatures() {
        let verifier = Arc::new(ExpectSha1EcdsaVerifier::default());
        let config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0u8; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        extended_master_secret_ack: Some(()),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let cert = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::Certificate(CertificateChain(vec![CertificateDer::from(
                    &b"does not matter"[..],
                )])),
            )),
        };
        conn.read_tls(&mut cert.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_kx = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Known(
                    ServerKeyExchange {
                        dss: DigitallySignedStruct::new(
                            SignatureScheme::ECDSA_SHA1_Legacy,
                            b"also does not matter".to_vec(),
                        ),
                        params: ServerKeyExchangeParams::Ecdh(ServerEcdhParams {
                            curve_params: EcParameters {
                                curve_type: ECCurveType::NamedCurve,
                                named_group: NamedGroup::X25519,
                            },
                            public: PayloadU8::new(vec![0xab; 32]),
                        }),
                    },
                )),
            )),
        };
        conn.read_tls(&mut server_kx.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_done = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHelloDone,
            )),
        };
        conn.read_tls(&mut server_done.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        assert!(
            verifier
                .seen_sha1_signature
                .load(Ordering::SeqCst)
        );
    }

    #[derive(Debug, Default)]
    struct ExpectSha1EcdsaVerifier {
        seen_sha1_signature: AtomicBool,
    }

    impl ServerCertVerifier for ExpectSha1EcdsaVerifier {
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
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            assert_eq!(dss.scheme, SignatureScheme::ECDSA_SHA1_Legacy);
            self.seen_sha1_signature
                .store(true, Ordering::SeqCst);
            Ok(HandshakeSignatureValid::assertion())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_SHA1_Legacy]
        }
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions::default()),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::X509),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::X509),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_accepts_rpk_server() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::RawPublicKey),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Ok(())
        );
    }

    fn client_requiring_rpk_receives_server_ee(
        encrypted_extensions: ServerExtensions<'_>,
    ) -> Result<(), Error> {
        let fake_server_crypto = Arc::new(FakeServerCrypto::new());
        let mut conn = ClientConnection::new(
            client_config_for_rpk(fake_server_crypto.clone()).into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_3,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        key_share: Some(KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(vec![0xaa; 32]),
                        }),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let ee = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::EncryptedExtensions(Box::new(encrypted_extensions)),
            )),
        };

        let mut encrypter = fake_server_crypto.server_handshake_encrypter();
        let enc_ee = encrypter
            .encrypt(PlainMessage::from(ee).borrow_outbound(), 0)
            .unwrap();
        conn.read_tls(&mut enc_ee.encode().as_slice())
            .unwrap();
        conn.process_new_packets().map(|_| ())
    }

    fn client_config_for_rpk(key_log: Arc<dyn KeyLog>) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerVerifierRequiringRpk))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(Arc::new(
                client_certified_key(),
            ))));
        config.key_log = key_log;
        config
    }

    fn client_certified_key() -> CertifiedKey {
        let key = super::provider::default_provider()
            .key_provider
            .load_private_key(client_key())
            .unwrap();
        let public_key_as_cert = vec![CertificateDer::from(
            key.public_key()
                .unwrap()
                .as_ref()
                .to_vec(),
        )];
        CertifiedKey::new(public_key_as_cert, key)
    }

    fn client_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/client.key").as_slice(),
        )
        .unwrap()
    }

    fn x25519_provider() -> CryptoProvider {
        // ensures X25519 is offered irrespective of cfg(feature = "fips"), which eases
        // creation of fake server messages.
        CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    fn aws_lc_x25519_provider() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![crate::crypto::aws_lc_rs::kx_group::X25519],
            ..crate::crypto::aws_lc_rs::default_provider()
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    fn server_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/end.key").as_slice(),
        )
        .unwrap()
    }

    #[cfg(feature = "aws_lc_rs")]
    fn server_cert() -> Vec<CertificateDer<'static>> {
        vec![
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/end.der")[..]),
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/inter.der")[..]),
        ]
    }

    #[cfg(feature = "aws_lc_rs")]
    fn do_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
        while client.is_handshaking() || server.is_handshaking() {
            transfer_client_to_server(client, server);
            server.process_new_packets().unwrap();
            transfer_server_to_client(server, client);
            client.process_new_packets().unwrap();
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    fn transfer_client_to_server(client: &mut ClientConnection, server: &mut ServerConnection) {
        let mut buf = [0u8; 262144];

        while client.wants_write() {
            let sz = client
                .write_tls(&mut &mut buf[..])
                .unwrap();
            if sz == 0 {
                return;
            }

            let mut offs = 0;
            while offs < sz {
                offs += server
                    .read_tls(&mut &buf[offs..sz])
                    .unwrap();
            }
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    fn transfer_server_to_client(server: &mut ServerConnection, client: &mut ClientConnection) {
        let mut buf = [0u8; 262144];

        while server.wants_write() {
            let sz = server
                .write_tls(&mut &mut buf[..])
                .unwrap();
            if sz == 0 {
                return;
            }

            let mut offs = 0;
            while offs < sz {
                offs += client
                    .read_tls(&mut &buf[offs..sz])
                    .unwrap();
            }
        }
    }

    #[derive(Clone, Debug)]
    struct ServerVerifierWithAuthorityNames(Vec<DistinguishedName>);

    impl ServerCertVerifier for ServerVerifierWithAuthorityNames {
        fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
            Some(self.0.as_slice())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }
    }

    #[derive(Debug)]
    struct ServerVerifierRequiringRpk;

    impl ServerCertVerifier for ServerVerifierRequiringRpk {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct FakeServerCrypto {
        server_handshake_secret: OnceLock<Vec<u8>>,
    }

    impl FakeServerCrypto {
        fn new() -> Self {
            Self {
                server_handshake_secret: OnceLock::new(),
            }
        }

        fn server_handshake_encrypter(&self) -> Box<dyn MessageEncrypter> {
            let cipher_suite = super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap();

            let secret = self
                .server_handshake_secret
                .get()
                .unwrap();

            let expander = cipher_suite
                .hkdf_provider
                .expander_for_okm(&OkmBlock::new(secret));

            // Derive Encrypter
            let key = derive_traffic_key(expander.as_ref(), cipher_suite.aead_alg);
            let iv = derive_traffic_iv(expander.as_ref());
            cipher_suite.aead_alg.encrypter(key, iv)
        }
    }

    impl KeyLog for FakeServerCrypto {
        fn will_log(&self, _label: &str) -> bool {
            true
        }

        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
                self.server_handshake_secret
                    .set(secret.to_vec())
                    .unwrap();
            }
        }
    }
}

// invalid with fips, as we can't offer X25519 separately
#[cfg(all(
    feature = "aws-lc-rs",
    feature = "prefer-post-quantum",
    not(feature = "fips")
))]
#[test]
fn hybrid_kx_component_share_offered_if_supported_separately() {
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(crate::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 2);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
    assert_eq!(key_shares[1].group, NamedGroup::X25519);
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn hybrid_kx_component_share_not_offered_unless_supported_separately() {
    use crate::crypto::aws_lc_rs;
    let provider = CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    };
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 1);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
}

#[derive(Debug)]
struct StaticClientHelloCustomizer {
    plan: Mutex<Option<ClientHelloPlan>>,
}

impl ClientHelloCustomizer for StaticClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, Error> {
        Ok(self.plan.lock().unwrap().take())
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

#[cfg(feature = "aws_lc_rs")]
#[derive(Debug)]
struct RecordingX25519KeyShare {
    public_key: StdArc<Mutex<Option<[u8; 32]>>>,
}

#[cfg(feature = "aws_lc_rs")]
impl crate::client::ObservesX25519KeyShare for RecordingX25519KeyShare {
    fn observe_x25519_key_share(&self, public_key: &[u8; 32]) -> Result<(), Error> {
        *self.public_key.lock().unwrap() = Some(*public_key);
        Ok(())
    }
}

fn client_hello_encoded_bytes_for_config(config: ClientConfig) -> Result<Vec<u8>, Error> {
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

fn client_hello_sent_for_config(config: ClientConfig) -> Result<ClientHelloPayload, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    match Message::try_from(message).unwrap() {
        Message {
            payload:
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
                    ..
                },
            ..
        } => Ok(ch),
        other => panic!("unexpected message {other:?}"),
    }
}

fn roots() -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(CertificateDer::from_slice(include_bytes!(
        "../../../test-ca/rsa-2048/ca.der"
    )))
    .unwrap();
    r
}
