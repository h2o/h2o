/*
 * Copyright (c) 2021 Fastly, Inc.
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

#ifndef quicly_mock_h
#define quicly_mock_h

#ifdef __cplusplus
extern "C" {
#endif

/* non-standard quicly interfaces useful for quicly mockup (`m` stands from mockup) */

/**
 * open a new stream over conn.
 * can simulate a remote-initiated stream open.
 */
int mquicly_open_stream(quicly_conn_t *conn, quicly_stream_t **stream, int is_remote_initiated, int unidirectional);

/**
 * simulate a connection close event from remote
 */
int mquicly_closed_by_remote(quicly_conn_t *conn, int err, uint64_t frame_type, ptls_iovec_t reason_phrase);

#ifdef __cplusplus
}
#endif

#endif
