# ESE test databases

`SRUDB.dat.gz` is the SRUM database from the test suite of
[dissect.esedb](https://github.com/fox-it/dissect.esedb) (`tests/_data/SRUDB.dat.gz`),
released by Fox-IT (part of NCC Group) under the Apache License 2.0. It holds 220
records in six provider tables and is in the "clean shutdown" state.

The same repository has a 33 MB `Windows.edb`. It is too large to vendor here; the
tests that use it run only when `MULDER_ESE_SAMPLES` points to a directory holding
an uncompressed copy.
