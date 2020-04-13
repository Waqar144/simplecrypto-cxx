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
    std::string s1 = "019283109238ksla;jdxcv0z98cv012;lkk;asdjfkjxcv08091823091283kljvl;kxcj";
    std::string s2 = "--123-0909-0123*(*";
    std::string s3 = "@#)*()(*)!(@*0";
    std::vector<uint8_t> out(SHA256_RAW_BYTES_LENGTH);
    sha256(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
    std::string expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

    sha256(reinterpret_cast<const uint8_t*>(s1.c_str()), s1.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "72465a5cb8c6818bc0687921da19efac30f9e12e1c7d6f8c69b91cc236958105");

    sha256(reinterpret_cast<const uint8_t*>(s2.c_str()), s2.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "5fc0f1b7b069aaca7137fd6c9980cb4162cc32f34c3ef3960b9b097940646537");

    sha256(reinterpret_cast<const uint8_t*>(s3.c_str()), s3.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "8d93a9972afbd63f943826fa6b1ec0e04e9526c7a168abeda69af63fa7abee18");
}


int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}