# The Windows host build needs NASM — analysis and plan

Running the CLI (`dart run litert_crypto ...`) or `flutter test` on a
**Windows x64 host** fails without NASM installed. This document records why,
what was verified in the dependency's source, which fixes are structurally
possible, and the order we intend to pursue them. For the one-line user-facing
answer (`winget install nasm`), see the
[README](../README.md#windows-the-first-run-may-ask-for-nasm).

## Why it happens

litert_crypto has no native code of its own; AES-256-GCM comes from BoringSSL
through `package:webcrypto` (see [design.md](design.md)). webcrypto ships
BoringSSL as source and compiles it with a Dart **build hook**
(`hook/build.dart`), which runs whenever a Dart program in the dependency
graph is built for a host target — `dart run`, `flutter test` on the host VM.
App builds are untouched: Gradle/NDK and Xcode assemble BoringSSL's assembly
themselves, so Android/iOS/macOS binaries never need NASM.

On Windows the hook's CMake build requires NASM unconditionally:

- `webcrypto-0.6.1/src/CMakeLists.txt` calls `enable_language(ASM_NASM)`
  inside `if(WIN32)` (line 126) — there is no probe for whether NASM exists.
- BoringSSL's portable-C path (`OPENSSL_NO_ASM`, line 97) is only taken when
  no assembly sources are listed for the platform/arch at all; it is not a
  switch a user can flip.
- webcrypto's `hook/build.dart` passes a fixed `defines` map to
  `CMakeBuilder` and accepts no user-defines, so a dependent package has no
  channel to inject `OPENSSL_NO_ASM` from the outside.

A successful build is cached under `.dart_tool/hooks_runner`, so day-to-day
runs never touch NASM again. It is needed only when a `clean` or a webcrypto
upgrade forces a rebuild — by then everyone has forgotten NASM was ever
involved, so the failure looks like a regression caused by whatever was just
done.

## What `OPENSSL_NO_ASM` would mean

It compiles BoringSSL's portable C implementations instead of hand-written
assembly. Functionally identical — same algorithms, same output bytes, same
LRTC files; it is a configuration BoringSSL itself supports and tests. The
cost is speed: hardware AES/GHASH is reached through the assembly path, so
AES-GCM can be several times slower without it.

For this package that cost lands nowhere that matters. The host build only
serves the **build-time CLI** (encrypt a model once) and tests; app runtime
decryption uses the NDK/Xcode-built library and keeps its assembly fast path
regardless. A NASM-less fallback to `OPENSSL_NO_ASM` on the host would be
strictly better than failing the build.

## What the package cannot do

- **Auto-install NASM from a hook.** The failure happens inside *webcrypto's*
  hook, and hooks run dependencies-first — a hook added to litert_crypto runs
  after webcrypto's, too late to intervene. `bin/` code runs later still, so
  even a `doctor` command would die in the same place before its first line.
  And a pub package's build silently running `winget install` would be the
  wrong kind of surprise even if the ordering allowed it.
- **Pass `OPENSSL_NO_ASM` through.** No user-define channel exists in
  webcrypto 0.6.1, as verified above.
- **Dodge the hook with a webcrypto-free CLI entrypoint in this package.**
  Build hooks run for every package in the dependency graph regardless of
  what the entrypoint imports; only a separate package without the dependency
  escapes them.

## The plan

1. **Document (done).** The README's Windows note in the CLI section walks
   error → cause → fix (`No CMAKE_ASM_NASM_COMPILER could be found` →
   BoringSSL's Windows build assembles with NASM → `winget install nasm`),
   and the CHANGELOG names the requirement; this file holds the depth.
2. **Upstream to webcrypto.** Propose that the Windows CMake path probe for
   NASM (`find_program`) and, when absent, warn and fall back to
   `OPENSSL_NO_ASM` instead of failing — or expose a user-define that forces
   it. Host-tooling consumers lose nothing but speed they don't need. This
   fixes the problem for every dependent, not just us.
   *Status: not yet filed.*
3. **Only if friction proves real: a webcrypto-free CLI package.** A separate
   `litert_crypto_cli` using pure-Dart AES-256-GCM would drop the C-toolchain
   requirement for hosts entirely. It doubles the crypto implementations
   (round-trip tests against the BoringSSL codec would have to guarantee LRTC
   compatibility) and the publishing surface, so it stays a last resort.

An interim softener ships in the repository (done):
[`tool/setup.ps1`](../tool/setup.ps1) checks for NASM, installs it through
winget when missing, and repairs PATH — referenced from the README's Windows
note and run explicitly by the user, never implicitly by a hook.
