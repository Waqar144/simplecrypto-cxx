# Simple Crypto library

This is a work in progress. The intention is to provide most of the crypto algorithms that are safe, fast and easy to use. Moreover, I want to make the files independent of each other so that if someone wants only one thing for e.g., sha256, they only need to use the 'sha256.h' and not link against the whole library.

The code is not all mine, most of it is C code written by other people. I am trying to rewrite parts of the code to use modern c++ features and constructs.

## Currently available:
- SHA 256
- SHA 512 (ready, but the code still needs to be modernized)
- base 58
- RIPEMD 169 (ready, basically c code)

## Build

```sh
mkdir build && cd build
cmake .. && make
```

# LICENSE

MIT
