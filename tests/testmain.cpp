#include "sha256.h"
#include <gtest/gtest.h>

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

TEST(sha256Test, sha256)
{
    std::string s = "hello";
    std::vector<uint8_t> out(SHA256_RAW_BYTES_LENGTH);
    sha256(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
    std::string expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}


int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
