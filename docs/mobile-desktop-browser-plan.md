# Flutter, browser extension, and browser roadmap

> **Status: architecture and delivery plan only.** The Flutter app, browser extension, and Rust/Ruby browser are not implemented in this repository yet. This document deliberately distinguishes planned work from the existing, tested Node.js/WireGuard gateway manager.

## Existing foundation

The current service manages a real WireGuard interface on Linux. Its admin API is protected by one administrator bearer token and can provision peers by generating a client keypair on the server for its existing web-admin workflow. A separate enrollment API now lets an administrator create a ten-minute, single-use invitation; the native client submits a locally generated public key and receives only tunnel metadata. The invitation secret is stored as a hash, and the client private key is never sent to the server on this enrollment path. There are still no user accounts or device-specific session credentials.

## Recommended product architecture

Keep WireGuard as the only tunnel protocol. Do not implement VPN cryptography, packet tunneling, or route control in Dart, JavaScript, Rust, or Ruby. Reuse the maintained WireGuard implementations and platform network-extension APIs.

### Flutter application: Android, iOS, and Windows

Build one Flutter UI with native tunnel adapters per operating system:

| Platform | Tunnel integration | Platform requirements |
|---|---|---|
| Android | WireGuard GoBackend through Android `VpnService` | VPN consent screen, foreground service, notification, Android signing/build setup |
| iOS | WireGuardKit inside an Apple `NEPacketTunnelProvider` | Network Extension entitlement, App Group, provisioning profile, Apple signing and device testing |
| Windows | WireGuard for Windows tunnel service / WireGuardNT | Installed or bundled licensed WireGuard components, elevated service installation, Windows signing/testing |

A Flutter plugin alone cannot grant these OS VPN capabilities. Each adapter must be implemented and tested on its platform. For an early usable release, the safer alternative is profile management/export and handoff to the official WireGuard app; that does not mean the Snapper app itself starts the tunnel.

### Enrollment API status

Do **not** embed the admin token in a consumer app. Anyone extracting it would gain administrator access to every managed peer. A separate invitation-based enrollment API is now implemented:

- `POST /api/invitations` requires the admin bearer token and returns a random invitation with a ten-minute expiry. Only the invitation hash is persisted.
- `POST /api/enroll` accepts `{ "name", "publicKey", "invitation" }` over HTTPS without admin credentials. Invitations are single-use; retries from the same public key are idempotent during the invitation window.
- The server allocates an address and installs the public key in the live and persistent WireGuard configuration. It never receives the client private key on this path.
- The client must generate and keep its private key in OS-protected storage, then use the native tunnel adapter.

This is an enrollment primitive, not a user-account system. Per-device session credentials and user identity are not implemented; revocation remains an administrator operation. Never expose the admin token to a distributed client.

### Browser extension (requested: OS control plus proxy control)

A browser extension cannot create a WireGuard interface or transparently capture all browser traffic. The requested extension therefore has two distinct modes:

1. **OS VPN control (primary):** a Chrome/Firefox desktop companion reports state and sends connect/disconnect requests to the installed desktop app over a narrowly scoped native-messaging host. The OS WireGuard tunnel remains the traffic path. On Android/iOS, users connect with the Flutter app; mobile browser extensions are not assumed to exist.
2. **Browser proxy control (optional):** an explicit per-browser proxy mode is possible only after deploying a maintained proxy (for example, Squid) bound to the VPN-side interface and reachable only through an active WireGuard peer. The extension can set/clear supported browser proxy settings. It must not claim full-device VPN coverage; WebRTC/UDP, DNS behavior, direct fallback, and browser-specific bypasses require a separate leak test. If the proxy is unavailable, the mode must fail closed instead of silently going direct.

Neither mode may contain the server administrator token. The proxy listener and extension proxy controls are **not implemented yet**; a home-grown open proxy is not an acceptable substitute.

### Rust/Ruby browser

A secure general-purpose browser is not a small wrapper around a language runtime. It requires a maintained browser engine, sandboxing, updates, certificate handling, permissions, and a substantial security response process. A practical first version would be a **Rust WebView shell** (for example, platform WebView2/WebKit) that uses the operating system's already-connected WireGuard tunnel; it would not be a new browser engine and would not provide VPN protection on its own.

Rust is the selected language for the requested browser shell. Ruby is not a VPN protocol or browser engine. The planned scope is an explicitly labeled Rust WebView shell, not a Chromium/WebKit fork; OS WireGuard must be connected independently, because embedding a WebView does not create a VPN.

## Delivery sequence and acceptance gates

1. **Enrollment/API (foundation now added):** invitations, local client public-key enrollment, recovery on restart, and hash-only invitation persistence are implemented. Still verify end-to-end on a real Linux WireGuard gateway and add API abuse/rate-limit testing before public distribution. Admin credentials must never enter a client bundle.
2. **Flutter foundation:** server pairing/enrollment, local key storage, profile lifecycle, platform-aware status/error handling, no sample devices or simulated tunnel state.
3. **Tunnel adapters:** Android, iOS, and Windows each get real connect/disconnect/status tests on supported hardware/OS. A platform is not “working” until its native tunnel, DNS behavior, route behavior, and revocation are verified.
4. **Browser extension:** native messaging install and origin/host allowlists for OS tunnel control; optional proxy-mode controls only after deploying and leak-testing a VPN-side proxy. Never fall back silently to direct traffic.
5. **Rust WebView shell:** supported OS and WebView engine documented, external links/downloads/permissions handled safely, and all traffic tested while the system tunnel is active.

## Build and verification constraints

The current development environment has Node.js but does not have Flutter/Dart, Rust/Cargo, or Ruby installed. Android SDK/Gradle, Xcode signing, Windows toolchains, and real platform devices are also unavailable here. Consequently, platform builds, OS VPN permission flows, store signing, and real tunnel integration cannot be honestly claimed as tested from this workspace. Install the relevant toolchain and test on each target OS before publishing binaries.
