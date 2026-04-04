#pragma once

#include <folly/Range.h>
#include <string>

/// Lowercase hex encoding of raw bytes (two hex digits per byte), no separators.
std::string bytes_to_hex_lower(folly::ByteRange data);
