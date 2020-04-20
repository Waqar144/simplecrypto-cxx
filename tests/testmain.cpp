#include "ripemd160.h"
#include "sha256.h"
#include "sha512.h"

#include <gtest/gtest.h>

/**
 * Test vectors are taken from https://www.di-mgt.com.au/sha_testvectors.html
 */

template <typename T>
std::string HexStr(const T itbegin, const T itend)
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

TEST(simplecrypto_cxx, sha256Test)
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

    /** template test using string and vector as inputs */

    auto output = sha256(s);
    expected = HexStr(output.begin(), output.end());
    EXPECT_EQ(expected, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

    output = sha256(std::vector<uint8_t>(s.begin(), s.end()));
    expected = HexStr(output.begin(), output.end());
    EXPECT_EQ(expected, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST(simplecrypto_cxx, sha512Test)
{
    std::string s = "abc";
    std::string s1 = "";
    std::string s2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    std::string s3 =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    std::vector<uint8_t> out(SHA512_RAW_BYTES_LENGTH);
    sha512(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
    std::string expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        expected,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3"
        "feebbd454d4423643ce80e2a9ac94fa54ca49f");

    sha512(reinterpret_cast<const uint8_t*>(s1.c_str()), s1.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        expected,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d287"
        "7eec2f63b931bd47417a81a538327af927da3e");

    sha512(reinterpret_cast<const uint8_t*>(s2.c_str()), s2.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        expected,
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57"
        "789ca031ad85c7a71dd70354ec631238ca3445");

    sha512(reinterpret_cast<const uint8_t*>(s3.c_str()), s3.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        expected,
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4"
        "b5433ac7d329eeb6dd26545e96e55b874be909");

    std::string millionA;
    millionA.resize(1000000, 'a');
    sha512(reinterpret_cast<const uint8_t*>(millionA.c_str()), millionA.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        expected,
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce5"
        "77c31beb009c5c2c49aa2e4eadb217ad8cc09b");

    /** template test using string and vector as inputs */

    auto output = sha512(millionA);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        expected,
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce5"
        "77c31beb009c5c2c49aa2e4eadb217ad8cc09b");

    output = sha512(s);
    expected = HexStr(output.begin(), output.end());
    EXPECT_EQ(
        expected,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3"
        "feebbd454d4423643ce80e2a9ac94fa54ca49f");

    output = sha512(std::vector<uint8_t>(s.begin(), s.end()));
    expected = HexStr(output.begin(), output.end());
    EXPECT_EQ(
        expected,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3"
        "feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST(simplecrypto_cxx, ripemd160Test)
{
    std::string s = "hello";
    std::string s1 = "019283109238ksla;jdxcv0z98cv012;lkk;asdjfkjxcv08091823091283kljvl;kxcj";
    std::string s2 = "--123-0909-0123*(*";
    std::string s3 = "@#)*()(*)!(@*0";
    std::vector<uint8_t> out(RIPEMD160_DIGEST_LENGTH);
    ripemd160(reinterpret_cast<const uint8_t*>(s.c_str()), s.length(), &out[0]);
    std::string expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "108f07b8382412612c048d07d13f814118445acd");

    ripemd160(reinterpret_cast<const uint8_t*>(s1.c_str()), s1.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "402e30059b6f307ce40a61e9115af9f8b788014f");

    ripemd160(reinterpret_cast<const uint8_t*>(s2.c_str()), s2.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "a94acb6dc6685b0d48a8b7761cc766a6dd7f6247");

    ripemd160(reinterpret_cast<const uint8_t*>(s3.c_str()), s3.length(), &out[0]);
    expected = HexStr(out.begin(), out.end());
    EXPECT_EQ(expected, "901b4e3a8601b2465039e78fae054b88333f30ff");
}


int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
