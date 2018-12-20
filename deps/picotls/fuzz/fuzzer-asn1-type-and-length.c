#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "picotls/asn1.h"

static struct feeder {
    const uint8_t *data;
    size_t size;
} feeder;

static void feeder_init(const uint8_t *orig_data, size_t orig_size)
{
    feeder.data = orig_data;
    feeder.size = orig_size;
}

static uint8_t feeder_next_byte(void)
{
    if (feeder.size == 0) {
        return 0;
    }
    uint8_t byte = *feeder.data;
    --feeder.size;
    ++feeder.data;
    return byte;
}

void count_printf(void *ctx, const char *format, ...)
{
    int *c = ctx;
    va_list argptr;
    va_start(argptr, format);
    c += vsnprintf(NULL, 0, format, argptr);
    va_end(argptr);
    return;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    int i, counter, indefinite_length, decode_error;
    ptls_minicrypto_log_ctx_t ctx = {&counter, count_printf};
    uint8_t *bytes, expected_type;
    size_t last_byte, bytes_max, byte_index;
    uint32_t length;

    feeder_init(Data, Size);
    bytes_max = ((size_t)feeder_next_byte() << 16) + (feeder_next_byte() << 8) + feeder_next_byte();
    if (bytes_max == 0)
        return 0;
    byte_index = ((size_t)feeder_next_byte() << 16) + (feeder_next_byte() << 8) + feeder_next_byte();
    byte_index = byte_index % bytes_max;
    bytes = malloc(bytes_max);
    for (i = 0; i < bytes_max; i++) {
        bytes[i] = feeder_next_byte();
    }
    expected_type = feeder_next_byte();
    ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, expected_type, &length, &indefinite_length, &last_byte,
                                           &decode_error, &ctx);
    free(bytes);
    return 0;
}
