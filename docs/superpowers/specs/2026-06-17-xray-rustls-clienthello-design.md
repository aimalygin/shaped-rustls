# xray-rustls ClientHello Customization Design

Date: 2026-06-17

## Context

This repository will become a maintained `rustls` fork for `xray-rust`.
The fork repository may be named `xray-rustls`, but the Cargo package and
library crate must remain named `rustls` so downstream crates such as
`tokio-rustls` keep using the same Rust types.

The implementation line must start from upstream `rustls 0.23.40`, not the
current `0.24.0-dev.0` checkout. The target downstream versions are:

```toml
tokio = "1.52.3"
tokio-rustls = "0.26.4"
rustls = "0.23.40"
```

The fork must stay a drop-in replacement for upstream `rustls`. All ClientHello
custom behavior is opt-in. Without a customizer, emitted ClientHello bytes and
normal handshake behavior must match upstream.

## Goals

- Add a small generic ClientHello customization surface inside `rustls`.
- Keep Xray, REALITY, fingerprint names, VLESS, routing, and JSON config outside
  this fork.
- Preserve `tokio-rustls 0.26.4` compatibility without forking `tokio-rustls`.
- Support per-connection planning instead of storing a finished ClientHello in
  `ClientConfig`.
- Prove the architecture through Milestone 1 first, then extend it for
  Milestone 2.

## Non-Goals

- Implementing Xray-core fingerprint registries in this repository.
- Encoding names such as `chrome`, `hellochrome_120`, or `safari` in `rustls`.
- Rewriting the TLS state machine or certificate verification.
- Adding BoringSSL, Go uTLS, Go helper processes, or a custom TLS engine.
- Making ClientHello customization active by default.

## Recommended Approach

Start a branch from upstream `rustls v0.23.40`, for example `xray/v0.23`.
Port only the brief and design work needed for this fork onto that baseline.
Then implement Milestone 1 and Milestone 2 in order.

This avoids building a prototype on `0.24.0-dev.0` that would have to be
reconciled with the `0.23.x` API line targeted by `tokio-rustls 0.26.4`.

## Public API Shape

Add a generic opt-in customizer to `ClientConfig`:

```rust
pub trait ClientHelloCustomizer: Send + Sync {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, Error>;
}
```

`None` means use the upstream rustls path exactly.

`ClientHelloContext` should expose only generic handshake construction inputs:

- server name,
- ALPN protocols selected for this connection,
- configured protocol version support,
- configured crypto provider information when needed,
- whether the connection is TCP or QUIC.

`ClientHelloPlan` should start small and grow only when Milestone 2 requires it.
For Milestone 1 it includes:

- optional fixed ClientHello random as `[u8; 32]`,
- optional fixed legacy session id as a public bounded `ClientHelloSessionId`
  type that rejects values longer than 32 bytes,
- optional fallible raw ClientHello capture callback.

For Milestone 2 it extends to:

- optional fixed X25519 key share private material,
- a way to expose the corresponding key share public material to the consumer,
- extension ordering controls needed by the first downstream profile,
- explicit errors for unsupported or inconsistent plans.

The public API should avoid exposing internal `rustls` message structs such as
`Random`, `SessionId`, or `ClientHelloPayload` directly. Public byte-oriented
types keep the API smaller and easier to preserve while rebasing on upstream.

## Internal Integration

Planning happens once per connection during client handshake construction.
The natural integration points are:

- `ClientConfig`: stores `Option<Arc<dyn ClientHelloCustomizer>>`.
- `ClientConnection::new` / connection builder path: keeps the existing public
  call pattern used by `tokio-rustls`.
- `ClientHelloInput::new`: applies Milestone 1 plan overrides for random and
  session id after upstream values are chosen.
- ClientHello emission path: invokes raw capture after PSK binder and ECH-related
  mutations have produced the exact emitted ClientHello, and before that exact
  message is added to the handshake transcript and written to the transport.
- TLS 1.3 key share construction: Milestone 2 adds a narrow path for fixed
  X25519 private material while preserving upstream generation by default.

The same encoded ClientHello bytes observed by the capture callback must be the
bytes added to the transcript.

## Milestone 1

Milestone 1 proves the extension point works without implementing the full
REALITY surface.

Tasks:

- Create the maintained branch from upstream `rustls v0.23.40`.
- Keep `rustls/Cargo.toml` package name as `rustls`.
- Add the optional `ClientHelloCustomizer` field to `ClientConfig`.
- Add `ClientHelloContext` and `ClientHelloPlan` with random, session id, and
  raw capture support.
- Wire the customizer into the client handshake path.
- Preserve default behavior when no customizer is configured.
- Add tests for fixed ClientHello random.
- Add tests for fixed session id.
- Add tests for raw ClientHello capture.
- Add a smoke test proving `tokio-rustls 0.26.4` compiles and performs a basic
  client connection using this fork.

## Milestone 2

Milestone 2 proves the hook surface can support downstream REALITY construction
without adding REALITY concepts to `rustls`.

Tasks:

- Add fixed X25519 key share private material support.
- Expose enough key share material for downstream REALITY auth derivation.
- Add tests proving the emitted ClientHello is the transcript ClientHello.
- Add extension ordering customization needed by the first downstream profile.
- Add negative tests for unsupported groups, malformed session ids, and
  inconsistent plan combinations.
- Add GREASE placeholder support only if required by the selected first
  downstream profile.

## Error Handling

Customizer failures return hard errors during connection construction or
ClientHello emission. A requested plan must not silently fall back to a different
ClientHello.

Milestone 1 errors include:

- session id longer than 32 bytes,
- capture callback failure,
- plan fields unsupported for the current protocol mode.

Milestone 2 errors include:

- fixed key share material for a group that is not offered,
- fixed X25519 material with non-X25519 group selection,
- extension order that references missing or duplicate extensions,
- plan combinations that would make PSK binder or transcript calculation
  inconsistent.

## Testing Strategy

Run focused tests during development and the broader upstream suite before
integration.

Required custom tests:

- no customizer keeps ClientHello behavior unchanged,
- fixed random appears in the emitted ClientHello,
- fixed session id appears in the emitted ClientHello,
- raw capture bytes match the encoded emitted ClientHello,
- `tokio-rustls 0.26.4` can use this fork through a normal `ClientConfig`,
- fixed X25519 key share produces the expected public key,
- transcript continuity uses the exact emitted ClientHello,
- unsupported plans fail loudly.

Downstream `xray-rust` remains responsible for:

- Xray JSON parsing,
- REALITY field handling,
- Xray-core fingerprint name mapping,
- uTLS/Xray byte fixtures,
- REALITY interop tests.

## Maintenance Notes

Keep the fork boring and easy to rebase:

- isolate custom code into small modules where practical,
- minimize edits to upstream handshake code,
- avoid new heavy dependencies,
- avoid unsafe code,
- keep default code paths simple,
- document every public customizer field as generic TLS behavior, not Xray
  policy.

If an implementation change introduces Xray-specific names or behavior into the
`rustls` crate, move that logic to `xray-rust` instead.
