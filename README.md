# Simple Crypto library

This is a work in progress. The intention is to provide c++ interface to most of the crypto hashing algorithms that are safe, fast and easy to use.

The code is not all mine, most of it is C code written by other people. I am trying to rewrite parts of the code to use modern c++ features and constructs.

## Currently available:
- BLAKE3
- BLAKE3 keyed hash
- BLAKE3 key derivation
- SHA-256
- SHA-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- Keccak-224
- Keccak-256
- Keccak-384
- Keccak-512
- HMAC SHA-256
- HMAC SHA-512
- PBKDF2 SHA-256
- PBKDF2 SHA-512
- RIPEMD 160
- Base 58

## Build

```sh
mkdir build && cd build
cmake .. && make
```

OR

```sh
make dbg #debug build
make bench #benchmarks
```

## Usage

//TODO: Add a separate usage doc

### SHA-256 / SHA-512

```cpp
#include "sha256.h"
//...
std::string data = "my data";
std::vector<uint8_t> sha256(data);
//you can also use vector or other std:: data structures
std::vector<uint8_t> data = {...};
std::vector<uint8_t> hash = sha256(data)
```

## LICENSE

MIT

## Credits

Most of the code comes from trezor-crypto libraries.
TODO: update this part
