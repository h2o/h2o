## Curve25519 on Cortex-M0 shootout
Implementation | Optimisation | Cycles    | Code size | Stack usage
-------------- | ------------ | --------- | --------- | -----------
donna          | `-Os`        | 15748K    | 7.4KB     | 3148B
donna          | `-O2`        | 15218K    | 7.9KB     | 3148B
donna          | `-O3`        | 12907K    | 16KB      | 3380B
naclref        | `-Os`        | 47813K    | 3.2KB     | 4012B
naclref        | `-O2`        | 34309K    | 3.5KB     | 4036B
naclref        | `-O3`        | 35059K    | 4.1KB     | 4044B
tweetnacl      | `-Os`        | 75979K    | 2.8KB     | 2244B
tweetnacl      | `-O2`        | 68876K    | 3.0KB     | 2268B
tweetnacl      | `-O3`        | 69622K    | 8.9KB     | 2900B

naclref at -O2 seems to give a good balance.  If you can spare the flash,
donna is quite significantly quicker.

