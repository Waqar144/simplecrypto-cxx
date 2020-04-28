#ifndef SHA3_TESTS_CPP
#define SHA3_TESTS_CPP

#include "sha3.h"
#include "test_utils.h"

#include <gtest/gtest.h>

/** Test vectors are from
 * https://www.di-mgt.com.au/sha_testvectors.html
 */

TEST(simplecrypto_cxx, sha3_256_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(32);
    sha3_256(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    s = "";
    sha3_256(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha3_256(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    sha3_256(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");

    std::string millionA;
    millionA.resize(1000000, 'a');
    sha3_256(reinterpret_cast<const uint8_t*>(millionA.c_str()), millionA.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");

    // disabled as it takes too much time

    //    std::string x;
    //    for (int i = 0; i < 16777216; ++i) {
    //        x += "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    //    }
    //    sha3_256(reinterpret_cast<const uint8_t*>(x.c_str()), x.size(), &out[0]);
    //    result = HexStr(out.begin(), out.end());
    //    EXPECT_EQ(result, "ecbbc42cbf296603acb2c6bc0410ef4378bafb24b710357f12df607758b33e2b");
}

TEST(simplecrypto_cxx, sha3_512_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(64);
    sha3_512(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d"
        "884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

    s = "";
    sha3_512(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c"
        "3ac558f500199d95b6d3e301758586281dcd26");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha3_512(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc7"
        "8c086346b533b49c030d99a27daf1139d6e75e");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    sha3_512(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e8"
        "2e2189ed0fb440d187f382270cb455f21dd185");

    std::string millionA;
    millionA.resize(1000000, 'a');
    sha3_512(reinterpret_cast<const uint8_t*>(millionA.c_str()), millionA.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee6"
        "89b266a8aa18ace8282a0e0db596c90b0a7b87");
}

TEST(simplecrypto_cxx, keccak_256_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(32);
    keccak_256(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

    s = "";
    keccak_256(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    keccak_256(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    keccak_256(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67");
}

TEST(simplecrypto_cxx, keccak_512_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(64);
    keccak_512(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac964"
        "2629379540c17e2a65b19d77aa511a9d00bb96");

    s = "";
    keccak_512(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe0"
        "6713b435f091ef2769fb160cdab33d3670680e");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    keccak_512(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "6aa6d3669597df6d5a007b00d09c20795b5c4218234e1698a944757a488ecdc09965435d97ca32c3cfed7201ff"
        "30e070cd947f1fc12b9d9214c467d342bcba5d");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    keccak_512(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "ac2fb35251825d3aa48468a9948c0a91b8256f6d97d8fa4160faff2dd9dfcc24f3f1db7a983dad13d53439ccac"
        "0b37e24037e7b95f80f59f37a2f683c4ba4682");
}

#endif // SHA3_TESTS_CPP
