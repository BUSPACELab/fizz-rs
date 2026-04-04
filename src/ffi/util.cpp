#include "ffi/util.h"

#include <cstdio>

std::string bytes_to_hex_lower(folly::ByteRange data) {
    std::string out;
    out.reserve(data.size() * 2);
    for (size_t i = 0; i < data.size(); ++i) {
        char buf[3];
        std::snprintf(
            buf,
            sizeof(buf),
            "%02x",
            static_cast<unsigned char>(data[i]));
        out += buf;
    }
    return out;
}
