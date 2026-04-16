# Python AST + Import-Graph Scanner

**Date:** 2026-04-16
**Branch:** `feat/python-ast-scanner`
**Scope:** New scanner module for Python crypto discovery via AST parsing with import-graph reachability

## Background

Triton has two existing layers of Python coverage:
- `deps_ecosystems.go` — manifest parsing (requirements.txt, pyproject.toml, etc.) identifies 17 crypto packages as "direct" dependencies
- `script.go` — regex pattern matching in .py files detects 14 crypto patterns (hashlib, ssl, bcrypt, etc.)

Neither does AST-level analysis. There is no import graph, no function-call-level crypto detection, and no reachability classification (direct/transitive/unreachable). The Go scanner (`deps.go`) provides all of this for Go code. This module brings Python to Go parity.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Parser | Pure Go, no Python dependency | Triton scans filesystems, not running environments. Python may not be installed. |
| CGO | None | Line-by-line parser, stdlib only |
| Registry scope | Core only (~30 entries) | stdlib + `cryptography` + `pycryptodome` covers 90%+ of real-world Python crypto |
| Module relationship | Standalone, coexists with script.go + deps_ecosystems | Higher confidence AST findings complement lower confidence regex. No breaking changes. |
| Architecture | Internal package + module + registry | Follows Java bytecode / .NET IL / TLS observer pattern |

## Package Layout

```
pkg/scanner/internal/pyimport/
  types.go           ImportInfo, ModuleNode, ImportGraph, FileImports types
  parser.go          Line-by-line Python import + function call parser
  parser_test.go     Parser unit tests
  graph.go           Import graph builder with BFS reachability classification
  graph_test.go      Graph traversal tests
  resolve.go         Module name to filesystem path resolution
  resolve_test.go    Resolution tests

pkg/scanner/python_ast.go          PythonASTModule implementation
pkg/scanner/python_ast_test.go     Module unit tests

pkg/crypto/python_algorithms.go    Python crypto algorithm registry
```

## Module 1: Python Import Parser (`internal/pyimport/`)

### Parser

Pure Go, line-by-line parser that extracts import statements and function calls from `.py` files.

**Import statements handled:**
- `import hashlib` -> `ImportInfo{Module: "hashlib"}`
- `import hashlib as hl` -> `ImportInfo{Module: "hashlib", Alias: "hl"}`
- `from cryptography.hazmat.primitives import hashes` -> `ImportInfo{Module: "cryptography.hazmat.primitives", Names: ["hashes"]}`
- `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms` -> multiple names
- `from . import utils` -> relative import (resolved against package path)
- `from ..crypto import aes` -> parent relative import
- Multi-line imports with `()` continuation

**Function call extraction:**
- `hashlib.sha256(data)` -> call to `hashlib.sha256`
- `algorithms.AES(key)` -> call to `algorithms.AES`
- `Fernet(key)` -> call to `Fernet` (resolved via import alias tracking)

**Not handled (intentionally):**
- Dynamic imports (`__import__()`, `importlib.import_module()`)
- Conditional imports inside `try/except`
- String-based exec/eval
- Type annotations without runtime usage

### Import Graph

Mirrors Go's `deps.go` BFS approach:

1. **Entry points:** All `.py` files in scan targets
2. **For each file:** Parse imports -> resolve to filesystem paths -> add edges
3. **BFS from entry points:** Classify each crypto import:
   - **direct** (confidence 0.95) — entry-point file directly imports crypto module
   - **transitive** (confidence 0.75) — entry-point imports module A which imports crypto
   - **unreachable** (confidence 0.50) — crypto package in requirements.txt but never imported in source. Migration priority halved.
4. **Shortest path** stored in `CryptoAsset.DependencyPath`

### Module Resolution

Maps Python import names to filesystem paths:
- `import hashlib` -> stdlib (flagged, no path needed)
- `from myapp.utils import encrypt` -> look for `myapp/utils.py` or `myapp/utils/__init__.py`
- Project root detected by presence of `setup.py`, `pyproject.toml`, `setup.cfg`, or `__init__.py` in parent dirs
- Stdlib vs third-party: hardcoded stdlib module list for crypto-relevant modules
- Anything not stdlib and not found in scanned tree -> classified as "third-party"

## Module 2: Python Crypto Registry (`pkg/crypto/python_algorithms.go`)

### Entry format

```go
type PythonCryptoEntry struct {
    Algorithm string // canonical name for ClassifyCryptoAsset
    Function  string // crypto function category
    KeySize   int    // default key size (0 = varies)
}
```

### Registry (~30 entries across 3 sources)

**stdlib:**

| Import path | Algorithm | Function |
|---|---|---|
| `hashlib.md5` | MD5 | Hash |
| `hashlib.sha1` | SHA-1 | Hash |
| `hashlib.sha256` | SHA-256 | Hash |
| `hashlib.sha384` | SHA-384 | Hash |
| `hashlib.sha512` | SHA-512 | Hash |
| `hashlib.sha3_256` | SHA3-256 | Hash |
| `hashlib.sha3_512` | SHA3-512 | Hash |
| `hashlib.blake2b` | BLAKE2b | Hash |
| `hashlib.blake2s` | BLAKE2s | Hash |
| `hmac.new` | HMAC | MAC |
| `ssl.create_default_context` | TLS | Protocol |
| `secrets.token_bytes` | CSPRNG | Random |

**`cryptography` library:**

| Import path | Algorithm | Function |
|---|---|---|
| `cryptography.hazmat.primitives.ciphers.algorithms.AES` | AES | Symmetric encryption |
| `cryptography.hazmat.primitives.ciphers.algorithms.TripleDES` | 3DES | Symmetric encryption |
| `cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20` | ChaCha20 | Symmetric encryption |
| `cryptography.hazmat.primitives.ciphers.algorithms.Blowfish` | Blowfish | Symmetric encryption |
| `cryptography.hazmat.primitives.hashes.SHA256` | SHA-256 | Hash |
| `cryptography.hazmat.primitives.hashes.SHA384` | SHA-384 | Hash |
| `cryptography.hazmat.primitives.hashes.SHA512` | SHA-512 | Hash |
| `cryptography.hazmat.primitives.hashes.SHA1` | SHA-1 | Hash |
| `cryptography.hazmat.primitives.hashes.MD5` | MD5 | Hash |
| `cryptography.hazmat.primitives.asymmetric.rsa` | RSA | Asymmetric encryption |
| `cryptography.hazmat.primitives.asymmetric.ec.SECP256R1` | ECDSA-P256 | Digital signature |
| `cryptography.hazmat.primitives.asymmetric.ec.SECP384R1` | ECDSA-P384 | Digital signature |
| `cryptography.hazmat.primitives.asymmetric.ed25519` | Ed25519 | Digital signature |
| `cryptography.hazmat.primitives.asymmetric.ed448` | Ed448 | Digital signature |
| `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC` | PBKDF2 | Key derivation |
| `cryptography.hazmat.primitives.kdf.scrypt.Scrypt` | scrypt | Key derivation |
| `cryptography.hazmat.primitives.kdf.hkdf.HKDF` | HKDF | Key derivation |
| `cryptography.fernet.Fernet` | AES-128-CBC | Symmetric encryption |
| `cryptography.x509` | X.509 | Certificate |

**`pycryptodome` (Crypto/Cryptodome prefixes):**

| Import path | Algorithm | Function |
|---|---|---|
| `Crypto.Cipher.AES` | AES | Symmetric encryption |
| `Crypto.Cipher.DES3` | 3DES | Symmetric encryption |
| `Crypto.Cipher.DES` | DES | Symmetric encryption |
| `Crypto.Cipher.Blowfish` | Blowfish | Symmetric encryption |
| `Crypto.Cipher.ChaCha20` | ChaCha20 | Symmetric encryption |
| `Crypto.Hash.SHA256` | SHA-256 | Hash |
| `Crypto.Hash.SHA1` | SHA-1 | Hash |
| `Crypto.Hash.MD5` | MD5 | Hash |
| `Crypto.PublicKey.RSA` | RSA | Asymmetric encryption |
| `Crypto.PublicKey.ECC` | ECDSA | Digital signature |
| `Crypto.PublicKey.DSA` | DSA | Digital signature |

`Cryptodome.*` entries mirror `Crypto.*` entries (pycryptodome namespace-safe install).

### Lookup strategy

1. Exact match on full import path + name
2. Prefix match for module-level imports
3. Alias resolution via parser's import tracking

## Module 3: Scanner (`python_ast.go`)

### Interface

```go
func (m *PythonASTModule) Name() string { return "python_ast" }
func (m *PythonASTModule) Category() model.ModuleCategory { return model.CategoryPassiveCode }
func (m *PythonASTModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
```

Implements `FileReaderAware` and `FileMetrics`.

### Scan flow

1. `walkTarget` with `matchFile: isPythonFile` (.py extension)
2. **Phase 1 — Parse:** For each .py file, extract imports and function calls via `pyimport.ParseFile()`. Accumulate into in-memory `[]pyimport.FileImports`.
3. **Phase 2 — Graph:** After all files parsed, build import graph via `pyimport.BuildGraph()`.
4. **Phase 3 — Classify:** Walk graph, match imports against `python_algorithms.go` registry.
5. **Phase 4 — Emit:** For each crypto match, emit finding with reachability, confidence, and dependency path.

### Two-phase scan rationale

Import graph requires seeing all files before classifying reachability. First pass collects; second pass classifies and emits. Same approach as `deps.go`.

### Findings emitted

Per crypto import discovered:
- Category: 6 (source code analysis)
- Source.Type: "file"
- Source.DetectionMethod: "python-ast"
- CryptoAsset: Algorithm, Function, Library, Language="Python", Reachability, DependencyPath
- Confidence: 0.95 (direct), 0.75 (transitive), 0.50 (unreachable)
- Module: "python_ast"

## Profile/Tier

| Module | Profile | Tier | Privileges |
|--------|---------|------|------------|
| `python_ast` | standard | Pro+ | None |

## Testing Strategy

### Unit tests

| Package/File | Key cases |
|---|---|
| `pyimport/parser_test.go` | `import X`, `from X import Y`, `from X import Y as Z`, relative imports, multi-line `()` imports, comments/strings ignored, continuation lines, nested function calls |
| `pyimport/graph_test.go` | Direct chain, transitive 3-hop, unreachable, diamond dependency, circular import handling, shortest path |
| `pyimport/resolve_test.go` | Package vs module, `__init__.py` detection, relative imports, stdlib detection, project root detection |
| `python_ast_test.go` | Single file hashlib, two-file transitive chain, no crypto = 0 findings, pycryptodome, mixed stdlib + third-party |

### Coverage target

- `pyimport/`: >85%
- Module: >80%

## New Dependencies

None. Pure Go stdlib only.

## Deferred

- Dynamic imports (`__import__()`, `importlib.import_module()`)
- Conditional imports inside `try/except` blocks
- Extended registry (pynacl, bcrypt, paramiko, etc.)
- Python virtual environment detection (site-packages resolution)
- `.pyi` stub file parsing
- Jupyter notebook `.ipynb` cell parsing
