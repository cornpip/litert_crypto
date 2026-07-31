# Issue draft — filed

- Filed as: https://github.com/dart-lang/sdk/issues/63933 (2026-07-31)
- Target: `dart-lang/sdk`, "Report a general issue" template

---

## Title

Concurrent `dart run` races on native-asset staging (crash on Windows)

## Body

`dart run <package>` stages code assets into the project's shared
`.dart_tool/lib` (delete → copy) before running `main()`. When several
`dart run` processes start concurrently in the same project — e.g. Flutter
asset transformers, one process per asset — the staging races. Two failure
modes observed on Windows: an invocation dies deleting a DLL that another
invocation has loaded (`PathAccessException`, pre-`main`), or it loads a
DLL that another invocation is mid-copy (`%1 is not a valid Win32
application`, error 193).

### Repro

https://github.com/cornpip/litert_crypto/tree/repro/dll-race

```
cd example
flutter clean
flutter run   # any target/build works — the crash is in the host-side transformer processes
```

The example registers 11 assets with an asset transformer whose dependency
graph contains `package:webcrypto` (build hook → code asset). Crashed on 3
of 4 runs with these 4 KB assets; real-sized models widen the race window.

### Actual result

```
Transformer process terminated with non-zero exit code: 255
Transformer package: litert_crypto
Full command: C:\...\dart-sdk\bin\dart.exe run litert_crypto --input=C:\...\Temp\flutter_tools.cedd711d\c4ba9dd0\demo_model_7.bin-transformOutput0.bin --output=C:\...\Temp\flutter_tools.cedd711d\c4ba9dd0\demo_model_7.bin-transformOutput1.bin
stdout:

stderr:
Running build hooks...Running build hooks...Unhandled exception:
Invalid argument(s): Couldn't resolve native function 'webcrypto_lookup_symbol' in 'package:webcrypto/webcrypto.dart' : Failed to load dynamic library 'C:\...\example\.dart_tool\lib\webcrypto.dll': Failed to load dynamic library 'C:\...\example\.dart_tool\lib\webcrypto.dll': %1 is not a valid Win32 application.
 (error code: 193).
#0      Native._ffi_resolver.#ffiClosure0 (dart:ffi-patch/ffi_patch.dart)
#1      Native._ffi_resolver_function (dart:ffi-patch/ffi_patch.dart:1943:20)
#2      _nativeWebcryptoLookupSymbol (package:webcrypto/src/boringssl/lookup/lookup.dart)
...
```

Another run, same repro, dies pre-`main` on the delete instead:

```
Transformer process terminated with non-zero exit code: 1
Transformer package: litert_crypto
Full command: C:\...\dart-sdk\bin\dart.exe run litert_crypto --input=C:\...\Temp\flutter_tools.287bcb50\3099527f\demo_model_3.bin-transformOutput0.bin --output=C:\...\Temp\flutter_tools.287bcb50\3099527f\demo_model_3.bin-transformOutput1.bin
stdout:
stderr:
Running build hooks...Running build hooks...PathAccessException: Cannot delete file, path = 'C:\...\example\.dart_tool\lib\webcrypto.dll' (OS Error: Access is denied., errno = 5)
#0      _checkForErrorResponse (dart:io/common.dart:58)
#1      _File._delete.<anonymous closure> (dart:io/file_impl.dart:349)
<asynchronous suspension>
#2      _extension#2.copyTo (package:dartdev/src/native_assets_bundling.dart:163)
<asynchronous suspension>
#3      Future.wait.<anonymous closure> (dart:async/future.dart:546)
<asynchronous suspension>
#4      _copyAssets (package:dartdev/src/native_assets_bundling.dart:87)
<asynchronous suspension>
#5      bundleNativeAssets (package:dartdev/src/native_assets_bundling.dart:27)
```

Flutter 3.44.8. `dart info`:

```
- Dart 3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on "windows_x64"
- on windows / "Windows 11 Home" 10.0 (Build 26200)
```

### Expected result

Staging is safe under concurrent invocations of the same project.
