# Java Bytecode Crypto Scanner

Parses compiled Java artifacts and extracts crypto algorithm literals from
the class-file constant pool.

## Scope

- `.class` — single class file; reads `CONSTANT_Utf8` entries (JVM §4.4)
- `.jar`, `.war`, `.ear` — ZIP archives; iterates `*.class` entries

## What's detected

Literals passed to JCA APIs remain in the constant pool even after
`javac` compilation and most obfuscators (ProGuard, R8) preserve them
because reflection-based crypto calls (`Cipher.getInstance("AES/GCM/NoPadding")`)
need the literal at runtime.

Registry covers ~80 entries: JCA standard names, BouncyCastle aliases,
NIST PQC (ML-KEM, ML-DSA, SLH-DSA, FN-DSA), and provider-identification
strings (BC, BCFIPS, BCPQC).

## Profile + tier

- Comprehensive profile only (heavy — parses every class)
- Pro+ license tier only

## What's NOT detected

- Keys dynamically constructed from `String.concat` / `StringBuilder`
- Algorithm names loaded from runtime config files (those are caught by `config.go`)
- Provider-internal APIs that bypass the JCA layer
- Classes inside encrypted/signed JARs where the attacker stripped the pool

## Limitations

- Only literal strings are matched. `getInstance(myAlgoVar)` is opaque to
  this scanner and caught (if at all) by source scanning.
- ProGuard's `-repackage` does not affect constant pool literals, so the
  scanner still works on obfuscated JARs.
