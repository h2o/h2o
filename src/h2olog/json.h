#ifndef H2OLOG_JSON_UTILS_H
#define H2OLOG_JSON_UTILS_H

#include <cstdio>
#include <cstdint>
#include "h2olog.h"
extern "C" {
#include "quicly.h"
}

// "_n" suffix means "with no heading comma"
// "_c" suffix means "with a heading comma"

void json_write_pair_n(std::FILE *out, const char *name, size_t name_len, const char *value, std::size_t value_len);
void json_write_pair_c(std::FILE *out, const char *name, size_t name_len, const char *value, std::size_t value_len);
void json_write_pair_c(std::FILE *out, const char *name, size_t name_len, const void *value, std::size_t value_len);
void json_write_pair_c(std::FILE *out, const char *name, size_t name_len, const std::int64_t value);
void json_write_pair_c(std::FILE *out, const char *name, size_t name_len, const std::uint64_t value);
void json_write_pair_c(std::FILE *out, const char *name, size_t name_len, const std::int32_t value);
void json_write_pair_c(std::FILE *out, const char *name, size_t name_len, const std::uint32_t value);
void json_write_pair_c(std::FILE *out, const char *name, size_t name_len, const quicly_address_t &value);
void json_write_pair_c(std::FILE *out, const char *name, size_t name_len, const void *value);

#endif
