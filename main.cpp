#include <iostream>
#include <vector>

//#include "simplecrypto-cxx/sha2.hpp"
//#include "simplecrypto-cxx/sha256.h"
#include "sha512.h"

template <typename T> std::string HexStr(const T itbegin, const T itend)
{
    std::string rv;
    static const char hexmap[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    rv.reserve(std::distance(itbegin, itend) * 2);
    for (T it = itbegin; it < itend; ++it) {
        unsigned char val = (unsigned char)(*it);
        rv.push_back(hexmap[val >> 4]);
        rv.push_back(hexmap[val & 15]);
    }
    return rv;
}

int main()
{
    std::string s = "hello";
    std::vector<uint8_t> out(SHA512_DIGEST_LENGTH);
    sha512(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
    //    std::vector<char> o(65);
    //    sha256HexString(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &o[0]);
    std::cout << HexStr(out.begin(), out.end());
    //    std::cout << "Output: " << std::string{o.data()} << " \nsiz: " << std::string(o.data()).size()
    //              << std::endl;
    return 0;
}
