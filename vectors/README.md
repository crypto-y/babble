# Vectors test

The testing vectors are taken from three other implementations of the noise protocol framework, a total of 1048 tests are used for checking babble's implementation. These tests are,

- [noise-c](https://github.com/rweather/noise-c), which provides 480 tests.
- [cacophony](https://github.com/centromere/cacophony), a haskell implementation, which provides 944 tests.
- [snow](https://github.com/mcginty/snow), a rust implementation, which provides 408 tests.

The tests are extracted and cleaned using the [python script](data/clean_vector_data.py) according to the [test vectors file format](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors).



### Credit

The [`vectors.go`](vectors.go) is taken from https://github.com/Yawning/nyquist/tree/master/vectors.

