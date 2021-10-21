#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "picotls.h"
#include "picotls/asn1.h"
#include "picotls/minicrypto.h"

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
    c++;
    return;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    int i, counter, indefinite_length, decode_error;
    ptls_minicrypto_log_ctx_t ctx = {&counter, count_printf};
    uint8_t *bytes, expected_type;
    size_t last_byte, bytes_max, byte_index;
    uint32_t length;
    uint8_t ret;

    feeder_init(Data, Size);

    bytes_max = (feeder_next_byte() << 8) + feeder_next_byte();
    if (bytes_max == 0)
        return 0;

    /* fill the test buffer */
    bytes = malloc(bytes_max);
    for (i = 0; i < bytes_max; i++) {
        bytes[i] = feeder_next_byte();
    }

    ret = feeder_next_byte() % 4;
    /* fuzz either ptls_asn1_validation or ptls_asn1_get_expected_type_and_length */
    if (ret == 0) {
        ptls_asn1_validation(bytes, bytes_max, &ctx);
    } else if (ret == 1) {
        byte_index = (feeder_next_byte() << 8) + feeder_next_byte();
        byte_index = byte_index % bytes_max;
        expected_type = feeder_next_byte();
        ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, expected_type, &length, &indefinite_length, &last_byte,
                &decode_error, &ctx);
    } else if (ret == 2 || ret == 3) {
        ptls_context_t ctx = {};
        char fname[] = "/tmp/XXXXXXXX";
        int fd, ret;
        fd = mkstemp(fname);
        if (fd < 0) {
            goto out;
        }
        ret = write(fd, bytes, bytes_max);
        if (ret != bytes_max) {
            goto out2;
        }
        ctx.random_bytes = ptls_minicrypto_random_bytes;
        ctx.get_time = &ptls_get_time;
        ctx.key_exchanges = ptls_minicrypto_key_exchanges;
        ctx.cipher_suites = ptls_minicrypto_cipher_suites;

	    if (ret == 2) {
            ptls_load_certificates(&ctx, fname);
            if (ctx.certificates.list) {
                for (i = 0; i < ctx.certificates.count; i++) {
                    if (ctx.certificates.list[i].base)
                        free(ctx.certificates.list[i].base);
                }
                free(ctx.certificates.list);

            }
        } else {
            ptls_minicrypto_load_private_key(&ctx, fname);
        }
out2:
        close(fd);
        unlink(fname);
    }
out:
    free(bytes);
    return 0;
}
