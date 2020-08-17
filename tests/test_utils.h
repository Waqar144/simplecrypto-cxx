#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <string>

template <typename T>
std::string HexStr(const T itbegin, const T itend)
{
    std::string rv;
    static const char hexmap[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    auto pos = static_cast<size_t>(std::distance(itbegin, itend));
    rv.reserve(pos * 2ul);
    for (T it = itbegin; it < itend; ++it) {
        unsigned char val = static_cast<unsigned char>(*it);
        rv.push_back(hexmap[val >> 4]);
        rv.push_back(hexmap[val & 15]);
    }
    return rv;
}

#endif // TEST_UTILS_H
