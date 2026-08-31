# Captured APT format contracts

These sanitized fixtures were captured on 2026-08-31 from the official
`debian:12`, `debian:13`, `ubuntu:22.04`, `ubuntu:24.04`, and `ubuntu:26.04`
container images after populating their package indexes. They preserve the
native C-locale output shape used by the collector while omitting unrelated
package and component records.

The policy fixtures deliberately include equal versions, exact-candidate
security/update ties, an epoch-bearing version, and a Debian security-only
candidate. Every HTTP source line in `policy.txt` has a matching binary
`Packages` target in `indextargets.txt`.

Capture commands:

```text
LC_ALL=C LANG=C apt-get indextargets
LC_ALL=C LANG=C dpkg-query --show --showformat=${binary:Package}|${Architecture}|${Version}|${db:Status-Status}\n ...
LC_ALL=C LANG=C apt-cache policy package:architecture ...
```
