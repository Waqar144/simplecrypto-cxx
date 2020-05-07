#include <iostream>
#include <string>
#include <vector>

#include "hmac.h"
#include "sha224.h"
#include "sha512.h"

#include "pbkdf2.h"

#include "blake3.h"

template <typename T> std::string HexStr(const T itbegin, const T itend)
{
    std::string rv;
    static const char hexmap[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    auto sz = std::distance(itbegin, itend) * 2;
    rv.reserve(sz);
    for (T it = itbegin; it < itend; ++it) {
        unsigned char val = (unsigned char)(*it);
        rv.push_back(hexmap[val >> 4]);
        rv.push_back(hexmap[val & 15]);
    }
    return rv;
}

int main()
{
    std::string s = "";
    std::string s1 = "abc";
    //    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    std::string key = "whats the Elvish word for friend";

    std::vector<uint8_t> out(SHA224_RAW_BYTES_LENGTH);
    //    std::array<uint8_t, BLAKE3_OUT_LEN> out;
    //    hashBlake3(s, out);
    out = sha224(s1);
    std::cout << HexStr(out.begin(), out.end());
    return 0;
}
