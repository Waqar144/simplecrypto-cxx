#ifndef BLAKE3_TESTS_H
#define BLAKE3_TESTS_H

#include "blake3.h"
#include "test_utils.h"

#include <gtest/gtest.h>

void fillVectorWithBytes0to250(std::vector<uint8_t>& in, unsigned int bytes)
{
    int i = 0;
    in.clear();
    in.reserve(bytes);
    while (in.size() < bytes) {
        in.push_back(static_cast<uint8_t>(i));
        i = (i + 1) % 251;
    }
}

TEST(simplecrypto_cxx, BLAKE3)
{
    std::string s = "";
    std::vector<uint8_t> out;
    hashBlake3(s, out);
    auto result = HexStr(out.begin(), out.end());
    EXPECT_EQ(result, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");

    std::vector<uint8_t> in;
    in.emplace_back(0);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    std::string expected =
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a"
        "5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886b"
        "a42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 1023);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11a182d27a591b05592b15607500"
        "e1e8dd56bc6c7fc063715b7a1d737df5bad3339c56778957d870eb9717b57ea3d9fb68d1b55127bba6a906a4a2"
        "4bbd5acb2d123a37b28f9e9a81bbaae360d58f85e5fc9d75f7c370a0cc09b6522d9c8d822f2f28f485";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 1024);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fc"
        "ec83a98a6a96ea5109d2c179c47a387ffbb404756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b"
        "7c93d465efc57f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9afa684e";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 1025);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52"
        "bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d"
        "16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 2048);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec9eea6698cd"
        "537939fad4749edd484cb541aced55cd9bf54764d063f23f6f1e32e12958ba5cfeb1bf618ad094266d4fc3c968"
        "c2088f677454c288c67ba0dba337b9d91c7e1ba586dc9a5bc2d5e90c14f53a8863ac75655461cea8f9";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 2049);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303096de31d71d74103403822a2e0b"
        "c1eb193e7aecc9643a76b7bbc0c9f9c52e8783aae98764ca468962b5c2ec92f0c74eb5448d519713e094137194"
        "31c802f948dd5d90425a4ecdadece9eb178d80f26efccae630734dff63340285adec2aed3b51073ad3";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 3072);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd29a3f6b0b978d6608335c09dc94"
        "ccf682f9951cdfc501bfe47b9c9189a6fc7b404d120258506341a6d802857322fbd20d3e5dae05b95c88793fa8"
        "3db1cb08e7d8008d1599b6209d78336e24839724c191b2a52a80448306e0daa84a3fdb566661a37e11";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 3073);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd39a27ae3b79d68d89da9bf25bc2"
        "7139ae65a324918a5f9b7828181e52cf373c84f35b639b7fccbb985b6f2fa56aea0c18f531203497b8bbd3a07c"
        "eb5926f1cab74d14bd66486d9a91eba99059a98bd1cd25876b2af5a76c3e9eed554ed72ea952b603bf";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 4096);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e9690289e9409ddb1b99768eafe162"
        "3da896faf7e1114bebeadc1be30829b6f8af707d85c298f4f0ff4d9438aef948335612ae921e76d411c3a9111d"
        "f62d27eaf871959ae0062b5492a0feb98ef3ed4af277f5395172dbe5c311918ea0074ce0036454f620";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 4097);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb99505f91b0b5600a11251652eacfa"
        "9497b31cd3c409ce2e45cfe6c0a016967316c426bd26f619eab5d70af9a418b845c608840390f361630bd497b1"
        "ab44019316357c61dbe091ce72fc16dc340ac3d6e009e050b3adac4b5b2c92e722cffdc46501531956";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 5120);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833acc61c8fdc114a2010ce8038c8"
        "53e121e1544985133fccdd0a2d507e8e615e611e9a0ba4f47915f49e53d721816a9198e8b30f12d20ec3689989"
        "175f1bf7a300eee0d9321fad8da232ece6efb8e9fd81b42ad161f6b9550a069e66b11b40487a5f5059";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 5121);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff96adaab0613a6146cdaabe498c"
        "3a94e529d3fc1da2bd08edf54ed64d40dcd6777647eac51d8277d70219a9694334a68bc8f0f23e20b0ff70ada6"
        "f844542dfa32cd4204ca1846ef76d811cdb296f65e260227f477aa7aa008bac878f72257484f2b6c95";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 6144);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca2054d742022da6fdda444ebc384b0"
        "4a54c3ac5839b49da7d39f6d8a9db03deab32aade156c1c0311e9b3435cde0ddba0dce7b26a376cad121294b68"
        "9193508dd63151603c6ddb866ad16c2ee41585d1633a2cea093bea714f4c5d6b903522045b20395c839";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 6145);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f18a2cfdd73c6e39dd75ce7c1c6"
        "e3ef238fd54465f053b25d21044ccb2093beb015015532b108313b5829c3621ce324b8e14229091b7c93f32db2"
        "e4e63126a377d2a63a3597997d4f1cba59309cb4af240ba70cebff9a23d5e3ff0cdae2cfd54e070022";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 7168);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a5707c321c83361793b9af62a40"
        "f43b523df1c8633cecb4cd14d00bdc79c78fca5165b863893f6d38b02ff7236c5a9a8ad2dba87d24c547cab046"
        "c29fc5bc1ed142e1de4763613bb162a5a538e6ef05ed05199d751f9eb58d332791b8d73fb74e4fce95";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 7169);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e781798a8b20534be1ca9eb2ae2df3f"
        "ae2ea60e48c6fb0b850b1385b5de0fe460dbe9d9f9b0d8db4435da75c601156df9d047f4ede008732eb17adc05"
        "d96180f8a73548522840779e6062d643b79478a6e8dbce68927f36ebf676ffa7d72d5f68f050b119c8";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 8192);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a635fe51a27db045a567c1ad51be5"
        "aa34c01c6651c4d9b5b5ac5d0fd58cf18dd61a47778566b797a8c67df7b1d60b97b19288d2d877bb2df417ace0"
        "09dcb0241ca1257d62712b6a4043b4ff33f690d849da91ea3bf711ed583cb7b7a7da2839ba71309bbf";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 8193);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3bb2282aa69be089359ea1154b9a"
        "9286c4a56af4de975a9aa4a5c497654914d279bea60bb6d2cf7225a2fa0ff5ef56bbe4b149f3ed15860f78b4e2"
        "ad04e158e375c1e0c0b551cd7dfc82f1b155c11b6b3ed51ec9edb30d133653bb5709d1dbd55f4e1ff6";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 16384);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde49d764c270176e53e97bdffa58d"
        "549073f2c660be0e81293767ed4e4929f9ad34bbb39a529334c57c4a381ffd2a6d4bfdbf1482651b172aa883cc"
        "13408fa67758a3e47503f93f87720a3177325f7823251b85275f64636a8f1d599c2e49722f42e93893";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 31744);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47860cc51f2b0c28a7b77304bd55"
        "fe73af663c02d3f52ea053ba43431ca5bab7bfea2f5e9d7121770d88f70ae9649ea713087d1914f7f312147e24"
        "7f87eb2d4ffef0ac978bf7b6579d57d533355aa20b8b77b13fd09748728a5cc327a8ec470f4013226f";
    EXPECT_EQ(result, expected.substr(0, 64));

    fillVectorWithBytes0to250(in, 102400);
    hashBlake3(in, out);
    result = HexStr(out.begin(), out.end());
    expected =
        "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b81694"
        "1a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23"
        "d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e";
    EXPECT_EQ(result, expected.substr(0, 64));
}

#endif    // BLAKE3_TESTS_H
