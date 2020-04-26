# Simple Crypto library

This is a work in progress. The intention is to provide most of the crypto algorithms that are safe, fast and easy to use. Moreover, I want to make the files independent of each other so that if someone wants only one thing for e.g., sha256, they only need to use the 'sha256.h' and not link against the whole library.

The code is not all mine, most of it is C code written by other people. I am trying to rewrite parts of the code to use modern c++ features and constructs.

## Currently available:
- SHA-256
- SHA-512
- HMAC SHA-256
- HMAC SHA-512
- PBKDF2 SHA-256
- PBKDF2 SHA-512
- Base 58
- RIPEMD 160 (ready, basically c code)

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
