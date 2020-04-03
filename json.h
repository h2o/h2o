#ifndef H2OLOG_JSON_UTILS_H
#define H2OLOG_JSON_UTILS_H

#include <cstdio>
#include <cstdint>

void json_write_pair(std::FILE *out, bool comma, const char* name, const char* value);
void json_write_pair(std::FILE *out, bool comma, const char* name, const void* value, std::size_t len);
void json_write_pair(std::FILE *out, bool comma, const char* name, const std::int64_t value);
void json_write_pair(std::FILE *out, bool comma, const char* name, const std::uint64_t value);
void json_write_pair(std::FILE *out, bool comma, const char* name, const std::int32_t value);
void json_write_pair(std::FILE *out, bool comma, const char* name, const std::uint32_t value);

#endif