#ifndef SHA3_TESTS_CPP
#define SHA3_TESTS_CPP

#include "sha3.h"
#include "test_utils.h"

#include <gtest/gtest.h>

/** Test vectors are from
 * https://www.di-mgt.com.au/sha_testvectors.html
 */

TEST(simplecrypto_cxx, sha3_224_test)
{
    std::string s = "abc";
    auto out = sha3<224>(std::vector<uint8_t>{s.begin(), s.end()});
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");

    s = "";
    out = sha3<224>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    out = sha3<224>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    out = sha3<224>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc");
}

TEST(simplecrypto_cxx, sha3_384_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(48);
    out = sha3<384>(std::vector<uint8_t>{s.begin(), s.end()});
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228"
        "376d25");

    s = "";
    out = sha3<384>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058"
        "d5f004");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    out = sha3<384>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0"
        "657c22");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    out = sha3<384>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179"
        "aa7fc7");
}


TEST(simplecrypto_cxx, sha3_256_test)
{
    std::string s = "abc";
    auto out = sha3<256>(std::vector<uint8_t>{s.begin(), s.end()});
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    s = "";
    out = sha3<256>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    out = sha3<256>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    out = sha3<256>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");

    std::string millionA;
    millionA.resize(1000000, 'a');
    out = sha3<256>(std::vector<uint8_t>{millionA.begin(), millionA.end()});
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
    auto out = sha3<512>(std::vector<uint8_t>{s.begin(), s.end()});
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d"
        "884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

    s = "";
    out = sha3<512>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c"
        "3ac558f500199d95b6d3e301758586281dcd26");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    out = sha3<512>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc7"
        "8c086346b533b49c030d99a27daf1139d6e75e");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    out = sha3<512>(std::vector<uint8_t>{s.begin(), s.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e8"
        "2e2189ed0fb440d187f382270cb455f21dd185");

    std::string millionA;
    millionA.resize(1000000, 'a');
    out = sha3<512>(std::vector<uint8_t>{millionA.begin(), millionA.end()});
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee6"
        "89b266a8aa18ace8282a0e0db596c90b0a7b87");
}

TEST(simplecrypto_cxx, keccak_224_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(28);
    keccak<224>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8");

    s = "";
    keccak<224>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    keccak<224>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "e51faa2b4655150b931ee8d700dc202f763ca5f962c529eae55012b6");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    keccak<224>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "344298994b1b06873eae2ce739c425c47291a2e24189e01b524f88dc");
}

TEST(simplecrypto_cxx, keccak_256_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(32);
    keccak<256>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

    s = "";
    keccak<256>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    keccak<256>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    keccak<256>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67");
}

TEST(simplecrypto_cxx, keccak_384_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(48);
    keccak<384>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763"
        "e3c28e");

    s = "";
    keccak<384>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b51591"
        "1957ff");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    keccak<384>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "b41e8896428f1bcbb51e17abd6acc98052a3502e0d5bf7fa1af949b4d3c855e7c4dc2c390326b3f3e74c7b1e2b"
        "9a3657");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    keccak<384>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "cc063f34685135368b34f7449108f6d10fa727b09d696ec5331771da46a923b6c34dbd1d4f77e595689c1f3800"
        "681c28");
}

TEST(simplecrypto_cxx, keccak_512_test)
{
    std::string s = "abc";
    std::vector<uint8_t> out(64);
    keccak<512>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    std::string result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac964"
        "2629379540c17e2a65b19d77aa511a9d00bb96");

    s = "";
    keccak<512>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe0"
        "6713b435f091ef2769fb160cdab33d3670680e");

    s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    keccak<512>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "6aa6d3669597df6d5a007b00d09c20795b5c4218234e1698a944757a488ecdc09965435d97ca32c3cfed7201ff"
        "30e070cd947f1fc12b9d9214c467d342bcba5d");

    s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlm"
        "nopqrsmnopqrstnopqrstu";
    keccak<512>(reinterpret_cast<const uint8_t*>(s.c_str()), s.size(), &out[0]);
    result = HexStr(out.begin(), out.end());
    EXPECT_EQ(
        result,
        "ac2fb35251825d3aa48468a9948c0a91b8256f6d97d8fa4160faff2dd9dfcc24f3f1db7a983dad13d53439ccac"
        "0b37e24037e7b95f80f59f37a2f683c4ba4682");
}

#endif // SHA3_TESTS_CPP
