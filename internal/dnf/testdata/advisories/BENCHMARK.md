# DNF4 advisory command gate

Captured on 2026-08-31 from the official Rocky Linux container images after
running `dnf makecache`. Versions were DNF 4.7.0 (EL8), 4.14.0 (EL9), and
4.20.0 (EL10). Every invocation was capped at 30 seconds and wrote its full
output to a bounded temporary file before measuring bytes.

The candidate commands were:

```text
dnf --assumeno -q '--setopt=*.skip_if_unavailable=False' updateinfo list --updates --security
dnf --assumeno -q '--setopt=*.skip_if_unavailable=False' updateinfo info --updates --security
```

| Target | List cold | List warm | List bytes | Info cold | Info warm | Info bytes |
|---|---:|---:|---:|---:|---:|---:|
| EL8 / DNF 4.7 | timed out at 30,006 ms | 29,777 ms after interrupted refresh | 8,763 | 23,679 ms | 719 ms | 93,901 |
| EL9 / DNF 4.14 | 25,920 ms | 211 ms | 2,759 | 22,875 ms | 233 ms | 35,593 |
| EL10 / DNF 4.20 | 28,842 ms | 143 ms | 1,167 | 15,561 ms | 150 ms | 17,581 |

## Gate decision

DNF4 uses exactly one `updateinfo list` command. The detail command is not
enabled because list plus detail cannot stay below the hard 30-second deadline
on every target and the cold EL8 list itself reached the cap. DNF4 therefore
ships advisory ID, severity, and applicable package relationships while title,
CVE, and vendor-date completeness are explicitly false.

DNF5 uses its two fixed JSON commands. No strategy performs a subprocess per
advisory.
