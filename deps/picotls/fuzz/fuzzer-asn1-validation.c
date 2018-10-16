#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "picotls/asn1.h"

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
    int counter;
    ptls_minicrypto_log_ctx_t ctx = {&counter, count_printf};
    ptls_asn1_validation(Data, Size, &ctx);
    return 0;
}
