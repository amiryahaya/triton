# keyquality testdata

## Debian blocklist files

The committed `blocklist-*.gz` files are **stubs** containing one synthetic
fingerprint each. To replace with real Debian weak-key data, install the
Debian `openssl-blacklist` package (or download from
https://packages.debian.org/openssl-blacklist), then:

```bash
# Each raw file contains SHA-1 fingerprints, one per line.
gzip -c /usr/share/openssl-blacklist/blacklist.RSA-1024 > pkg/crypto/keyquality/testdata/blocklist-rsa-1024.gz
gzip -c /usr/share/openssl-blacklist/blacklist.RSA-2048 > pkg/crypto/keyquality/testdata/blocklist-rsa-2048.gz
gzip -c /usr/share/openssl-blacklist/blacklist.DSA-1024 > pkg/crypto/keyquality/testdata/blocklist-dsa-1024.gz
gzip -c /usr/share/openssl-blacklist/blacklist.DSA-2048 > pkg/crypto/keyquality/testdata/blocklist-dsa-2048.gz
```

## ROCA test vector

`roca-vuln-modulus.hex` is a placeholder. Replace with a real Infineon-
produced modulus (from the `crocs-muni/roca` repo test vectors) to exercise
the positive-case test.
