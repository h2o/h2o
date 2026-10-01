/*
 * Copyright (c) 2026 Fastly, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef h2o__quic_stream_h
#define h2o__quic_stream_h

#include <stdint.h>
#include "quicly.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Resets the send side of a stream by RESET_STREAM unless it has already been reset or its transfer is complete. quicly asserts
 * against resetting a stream twice, and resets on STOP_SENDING before calling `on_send_stop`, even after a FIN has been sent. A
 * pending reliable reset is downgraded with its own error code, which quicly requires to remain the same; `err` is then ignored.
 */
static inline void h2o_quic_reset_stream(quicly_stream_t *qs, quicly_error_t err)
{
    if (quicly_sendstate_eos_type(&qs->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET ||
        quicly_sendstate_transfer_complete(&qs->sendstate))
        return;
    if (qs->sendstate.app_error_code != UINT64_MAX)
        err = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(qs->sendstate.app_error_code);
    quicly_reset_stream(qs, err);
}

#ifdef __cplusplus
}
#endif

#endif
