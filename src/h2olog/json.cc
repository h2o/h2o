#include "json.h"
#include <string.h>
#include <inttypes.h>

#define FPUTS_LIT(s, out) fwrite(s, 1, strlen(s), out)

static bool json_need_escape(char c)
{
    return static_cast<unsigned char>(c) < 0x20 || c == 0x7f;
}

static void json_write_str_value(FILE *out, const char *str)
{
    fputc('"', out);
    while (*str) {
        switch (*str) {
        case '\"':
            FPUTS_LIT("\\\"", out);
            break;
        case '\\':
            FPUTS_LIT("\\\\", out);
            break;
        case '\b':
            FPUTS_LIT("\\b", out);
            break;
        case '\f':
            FPUTS_LIT("\\f", out);
            break;
        case '\n':
            FPUTS_LIT("\\n", out);
            break;
        case '\r':
            FPUTS_LIT("\\r", out);
            break;
        case '\t':
            FPUTS_LIT("\\t", out);
            break;
        default:
            if (!json_need_escape(*str)) {
                fputc(*str, out);
            } else {
                auto u8 = static_cast<uint8_t>(*str);
                fprintf(out, "\\u%04x", u8);
            }
            break;
        }
        str++;
    }
    fputc('"', out);
}

static void json_write_name_value(FILE *out, const char *name, size_t name_len)
{
    fputc('"', out);
    fwrite(name, 1, name_len, out);
    fputc('"', out);
    fputc(':', out);
}

void json_write_pair_n(FILE *out, const char *name, size_t name_len, const char *value)
{
    json_write_name_value(out, name, name_len);
    json_write_str_value(out, value);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, const char *value)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    json_write_str_value(out, value);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, const void *value, size_t len)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    fputc('"', out);
    const uint8_t *bin = static_cast<const uint8_t *>(value);
    for (size_t i = 0; i < len; i++) {
        fputc("0123456789abcdef"[bin[i] >> 4], out);
        fputc("0123456789abcdef"[bin[i] & 0xf], out);
    }
    fputc('"', out);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, int32_t value)
{
    json_write_pair_c(out, name, name_len, static_cast<int64_t>(value));
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, uint32_t value)
{
    json_write_pair_c(out, name, name_len, static_cast<uint64_t>(value));
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, int64_t value)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    fprintf(out, "%" PRId64, value);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, uint64_t value)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    fprintf(out, "%" PRIu64, value);
}
