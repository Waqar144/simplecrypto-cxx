#include <iostream>
#include <string>
#include <vector>

#include "hmac512.h"
#include "sha512.h"

#include "pbkdf2.h"

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
    std::string s = "abc";
    std::string s1 = "abc";
    //    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    std::vector<uint8_t> out(32);
    //    pbkdf2_hmac_sha512(
    //        reinterpret_cast<const uint8_t*>(s.c_str()),
    //        s.length(),
    //        reinterpret_cast<const uint8_t*>(s1.c_str()),
    //        s1.length(),
    //        1000,
    //        &out[0]);
    out = pbkdf2_sha512(s, s1, 1000, 32);
    //    sha512(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
    //    hmac_sha256(
    //        reinterpret_cast<const uint8_t*>(s1.c_str()),
    //        s1.length(),
    //        reinterpret_cast<const uint8_t*>(s.c_str()),
    //        s.length(),
    //        &out[0]);
    //    std::vector<char> o(65);
    //    sha256HexString(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &o[0]);
    std::cout << HexStr(out.begin(), out.end());
    //    std::cout << "Output: " << std::string{o.data()} << " \nsiz: " << std::string(o.data()).size()
    //              << std::endl;
    return 0;
}
