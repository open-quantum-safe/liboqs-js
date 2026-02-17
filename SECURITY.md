# Security Policy

## Supported Versions

We support the latest release and provide security updates for critical vulnerabilities.

| Version | Supported          |
| ------- | ------------------ |
| 0.15.x  | :white_check_mark: |
| < 0.15  | :x:                |

## Scope of This Library

This library (@oqs/liboqs-js) is a **JavaScript/WebAssembly wrapper** for the native [LibOQS library](https://github.com/open-quantum-safe/liboqs). Security issues can originate from:

1. **This wrapper library** - JavaScript/TypeScript code, WASM bindings, memory management, API design
2. **The underlying LibOQS library** - Native cryptographic implementations compiled to WASM
3. **Emscripten toolchain** - WASM compilation and runtime environment

## Determining Where to Report

### Report to This Repository (liboqs-js)

Report security issues **to this repository** if they involve the JavaScript/WASM wrapper:

- ✅ Memory safety issues in the JavaScript wrapper (buffer overflows, incorrect buffer sizing)
- ✅ WASM function call vulnerabilities (incorrect parameter passing, type confusion)
- ✅ WASM module loading vulnerabilities (path traversal, malicious module injection)
- ✅ Incorrect handling of LibOQS error codes from WASM functions
- ✅ Resource cleanup failures (WASM memory leaks, pointer leaks)
- ✅ Thread-safety issues in the JavaScript wrapper
- ✅ API misuse that could lead to insecure usage patterns
- ✅ Documentation errors that could lead to insecure implementations
- ✅ Build system vulnerabilities (malicious dependencies, compromised builds)
- ✅ Random number generation issues in JavaScript/browser environments

**Examples:**
- "The `destroy()` method doesn't free WASM memory properly"
- "WASM module loader is vulnerable to path traversal attacks"
- "Race condition in concurrent `generateKeyPair()` calls"
- "TypeScript definitions allow unsafe type coercion"

### Report to LibOQS Upstream

Report to the [LibOQS project](https://github.com/open-quantum-safe/liboqs/security) if they involve:

- ❌ Cryptographic implementation bugs (incorrect algorithm behavior)
- ❌ Side-channel vulnerabilities in native code (even when compiled to WASM)
- ❌ Timing attacks in algorithm implementations
- ❌ Issues with specific algorithms (ML-KEM, ML-DSA, etc.)
- ❌ Bugs in the LibOQS C source code
- ❌ OpenSSL integration vulnerabilities in LibOQS

**Examples:**
- "ML-KEM-768 produces incorrect shared secrets"
- "Timing side-channel in Falcon signature verification"
- "Buffer overflow in Classic-McEliece implementation"

**Note:** Issues with build scripts (`build.sh`, Emscripten configuration) or the WASM binaries should be reported to this repository, not upstream LibOQS.

See the [LibOQS security policy](https://github.com/open-quantum-safe/liboqs/blob/main/SECURITY.md) for their reporting process.

### Report to Emscripten

Report to [Emscripten](https://github.com/emscripten-core/emscripten/security) if they involve:

- ❌ WASM runtime vulnerabilities
- ❌ JavaScript glue code generation bugs
- ❌ Memory model issues in compiled WASM
- ❌ Browser API integration vulnerabilities

## Reporting a Vulnerability

For wrapper-related security issues, use one of the following methods **on this repository**:

### GitHub Security Advisories (Preferred)

1. Go to the [Security Advisories page](https://github.com/open-quantum-safe/liboqs-js/security/advisories)
2. Click "Report a vulnerability"
3. Fill out the vulnerability details

### GitHub Issues

For lower-severity issues that don't require coordinated disclosure, you can open a [GitHub Issue](https://github.com/open-quantum-safe/liboqs-js/issues) directly.

Please include:
- **Description**: Clear explanation of the vulnerability
- **Affected Components**: Which parts of the wrapper are affected (JavaScript code, WASM bindings, build system)
- **Steps to Reproduce**: Minimal code example demonstrating the issue (Node.js and/or browser)
- **Environment**: Node.js version, browser version, operating system

## Security Updates

Security updates are released as:
- **Patch versions** (0.15.x) for the current major/minor version
- **Security advisories** on GitHub
- **Release notes** highlighting the CVE or vulnerability ID
- **npm package updates** with security fixes

Subscribe to:
- [GitHub Security Advisories](https://github.com/open-quantum-safe/liboqs-js/security/advisories) for notifications
- [Releases page](https://github.com/open-quantum-safe/liboqs-js/releases) for update announcements

## Threat Model

### In Scope

Our threat model covers:

- ✅ **Memory safety**: Proper cleanup of sensitive data (keys, secrets) from WASM memory
- ✅ **WASM interop safety**: Correct marshalling between JavaScript and WASM
- ✅ **Resource management**: Prevention of leaks and use-after-free in WASM
- ✅ **API safety**: Preventing misuse that leads to insecure configurations
- ✅ **Module integrity**: WASM module validation and loading security
- ✅ **Browser security**: Safe operation in browser sandboxes
- ✅ **Dependency integrity**: NPM package and build dependency security

### Out of Scope

The following are **outside our threat model** (deferred to LibOQS or browser vendors):

- ❌ Cryptographic algorithm correctness
- ❌ Side-channel attacks in WASM implementations (timing, cache, speculative execution)
- ❌ Physical attacks (power analysis, fault injection)
- ❌ Browser vulnerabilities (V8 bugs, WebAssembly VM vulnerabilities)
- ❌ Operating system vulnerabilities
- ❌ Attacks requiring same-origin access in browsers
- ❌ Supply chain attacks on upstream dependencies (npm, Emscripten, LibOQS)

For issues outside our scope, please refer to:
- [LibOQS threat model](https://github.com/open-quantum-safe/liboqs/blob/main/SECURITY.md#threat-model)
- [Browser security policies](https://www.chromium.org/Home/chromium-security/)
- [Node.js security policy](https://github.com/nodejs/node/security/policy)

## Best Practices for Users

To use this library securely:

1. **Keep Updated**: Always use the latest version for security fixes (library version tracks bundled LibOQS version)
2. **Dispose Properly**: Call `destroy()` to free WASM resources (though JavaScript can't zero WASM memory)
3. **Use NIST Algorithms**: Prefer hybrid ML-KEM and ML-DSA for production use
4. **Validate Inputs**: Don't trust cryptographic material from untrusted sources without validation
5. **Follow Hybrid Patterns**: Consider combining with classical cryptography during transition period
6. **Monitor Advisories**: Subscribe to security advisories for this library, LibOQS, and Node.js/browsers
7. **Verify Package Integrity**: Check npm package signatures and checksums when installing
8. **Avoid localStorage**: Never store secret keys in browser localStorage or sessionStorage
9. **Use Secure Contexts**: Only deploy in HTTPS contexts (browsers require this for WebCrypto RNG)
10. **Audit Dependencies**: Regularly audit your `node_modules` for known vulnerabilities

## Known Limitations

### JavaScript/WASM Specific

- **No memory zeroing**: JavaScript cannot reliably zero WASM memory containing secret keys (V8 optimization limitation)
- **Limited timing attack resistance**: JavaScript timing APIs are coarse-grained; WASM may still leak timing information
- **No hardware RNG access**: Random numbers come from `crypto.randomBytes()` or `crypto.getRandomValues()`, not direct hardware
- **Bundle tampering**: WASM modules embedded in `.min.js` files could be modified by malicious actors (verify npm package integrity)

### Platform Coverage

- **Node.js**: Requires v22+ for WASM SIMD support
- **Browsers**: Requires modern browsers with WebAssembly support (Chrome 91+, Firefox 89+, Safari 16.4+, Edge 91+)
- **Testing**: Our testing primarily covers mainstream platforms and browsers

### Algorithm Support

- **103 algorithms available**: All algorithms listed in `algorithms.json` (plus eFrodoKEM variants sharing FrodoKEM WASM modules) have JavaScript wrappers, TypeScript definitions, and test coverage
- **Algorithm stability**: Only NIST-standardized algorithms (ML-KEM, ML-DSA, SLH-DSA) have stable names; other algorithm names may change as standardization progresses

## Security Testing

We employ:
- ✅ Comprehensive unit tests (1400+ tests across 103 algorithms via Vitest)
- ✅ Memory leak detection via WASM memory monitoring
- ✅ Code analysis with ESLint strict rules
- ✅ Cross-platform CI/CD testing (Node.js + browsers)
- ✅ Disposal pattern verification
- ✅ TypeScript strict mode for type safety

## Build Security

### WASM Module Integrity

All WASM modules are:
- **Built from source**: Compiled from verified LibOQS sources using Emscripten
- **Single-algorithm**: Each module contains only one algorithm (attack surface reduction)
- **Closure-optimized**: Minified and optimized to prevent tampering detection

## Random Number Generation

This library relies on platform-provided entropy:

**Node.js:**
- Uses `crypto.randomBytes()` (Node.js CSPRNG)
- Backed by OS entropy sources (urandom, CryptGenRandom, etc.)
- No additional configuration needed

**Browsers:**
- Uses `crypto.getRandomValues()` (Web Crypto API)
- Backed by browser's CSPRNG (OS entropy + browser mixing)
- Requires secure context (HTTPS)

**Security Notes:**
- No custom RNG implementation (reduces attack surface)
- Emscripten's `getentropy()` polyfill handles platform differences
- LibOQS `OQS_randombytes_system` calls into Emscripten's entropy

If you suspect RNG issues, report them to [this repository](https://github.com/open-quantum-safe/liboqs-js/issues) (if JavaScript-side) or Node.js/browser vendors (if platform-side).

## Acknowledgments

We follow security best practices inspired by:
- [LibOQS security policy](https://github.com/open-quantum-safe/liboqs/blob/main/SECURITY.md)
- [Node.js security policy](https://github.com/nodejs/node/security/policy)
- [npm security best practices](https://docs.npmjs.com/policies/security)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## Questions?

For non-security questions, please use:
- [GitHub Discussions](https://github.com/open-quantum-safe/liboqs-js/discussions)
- [GitHub Issues](https://github.com/open-quantum-safe/liboqs-js/issues)

For security concerns, always use the reporting channels described above.

---

**Remember**: This library is for research and experimentation. Follow the LibOQS project's guidance: **"WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA."**
