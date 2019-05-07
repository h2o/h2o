/*
 * Copyright (c) 2019 Fastly, Kazuho Oku
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

/**
 * Providers of quicly. Name of the arguments are important - they are used as the names of JSON fields when the dtrace script is
 * generated.
 */
provider quicly {
    probe quicly_connect(struct st_quicly_conn_t *conn, int64_t at, const char *dcid, const char *scid, uint32_t version);
    probe quicly_accept(struct st_quicly_conn_t *conn, int64_t at, const char *dcid, const char *scid);
    probe quicly_free(struct st_quicly_conn_t *conn, int64_t at);
    probe quicly_send(struct st_quicly_conn_t *conn, int64_t at, int state);
    probe quicly_receive(struct st_quicly_conn_t *conn, int64_t at, const char *dcid, const char *scid, uint8_t first_octet,
                         const void *bytes, size_t num_bytes);
    probe quicly_version_switch(struct st_quicly_conn_t *conn, int64_t at, uint32_t new_version);
    probe quicly_idle_timeout(struct st_quicly_conn_t *conn, int64_t at);
    probe quicly_stateless_reset_receive(struct st_quicly_conn_t *conn, int64_t now);

    probe quicly_crypto_decrypt(struct st_quicly_conn_t *conn, int64_t at, uint64_t pn, const void *decrypted,
                                size_t decrypted_len);
    probe quicly_crypto_handshake(struct st_quicly_conn_t *conn, int64_t at, int ret);
    probe quicly_crypto_update_secret(struct st_quicly_conn_t *conn, int64_t at, int is_enc, uint8_t epoch, const char *label,
                                      const char *secret);

    probe quicly_packet_prepare(struct st_quicly_conn_t *conn, int64_t at, uint8_t first_octet, const char *dcid);
    probe quicly_packet_commit(struct st_quicly_conn_t *conn, int64_t at, uint64_t pn, size_t len, int ack_only);
    probe quicly_packet_acked(struct st_quicly_conn_t *conn, int64_t at, uint64_t pn, int newly_acked);
    probe quicly_packet_lost(struct st_quicly_conn_t *conn, int64_t at, uint64_t pn);

    probe quicly_pto(struct st_quicly_conn_t *conn, int64_t at, size_t inflight, uint32_t cwnd, int8_t pto_count);
    probe quicly_cc_ack_received(struct st_quicly_conn_t *conn, int64_t at, uint64_t largest_acked, size_t bytes_acked,
                                 uint32_t cwnd, size_t inflight);
    probe quicly_cc_congestion(struct st_quicly_conn_t *conn, int64_t at, uint64_t max_lost_pn, size_t inflight, uint32_t cwnd);

    probe quicly_transport_close_send(struct st_quicly_conn_t *conn, int64_t at, uint64_t error_code, uint64_t frame_type,
                                      const char *reason_phrase);
    probe quicly_transport_close_receive(struct st_quicly_conn_t *conn, int64_t at, uint64_t error_code, uint64_t frame_type,
                                         const char *reason_phrase);
    probe quicly_application_close_send(struct st_quicly_conn_t *conn, int64_t at, uint64_t error_code, const char *reason_phrase);
    probe quicly_application_close_receive(struct st_quicly_conn_t *conn, int64_t at, uint64_t error_code,
                                           const char *reason_phrase);

    probe quicly_stream_send(struct st_quicly_conn_t *conn, int64_t at, struct st_quicly_stream_t *stream, uint64_t off, size_t len,
                             int is_fin);
    probe quicly_stream_receive(struct st_quicly_conn_t *conn, int64_t at, struct st_quicly_stream_t *stream, uint64_t off,
                                size_t len);
    probe quicly_stream_acked(struct st_quicly_conn_t *conn, int64_t at, int64_t stream_id, uint64_t off, size_t len);
    probe quicly_stream_lost(struct st_quicly_conn_t *conn, int64_t at, int64_t stream_id, uint64_t off, size_t len);

    probe quicly_max_data_send(struct st_quicly_conn_t *conn, int64_t at, uint64_t limit);
    probe quicly_max_data_receive(struct st_quicly_conn_t *conn, int64_t at, uint64_t limit);

    probe quicly_max_streams_send(struct st_quicly_conn_t *conn, int64_t at, uint64_t limit, int is_unidirectional);
    probe quicly_max_streams_receive(struct st_quicly_conn_t *conn, int64_t at, uint64_t limit, int is_unidirectional);

    probe quicly_max_stream_data_send(struct st_quicly_conn_t *conn, int64_t at, struct st_quicly_stream_t *stream, uint64_t limit);
    probe quicly_max_stream_data_receive(struct st_quicly_conn_t *conn, int64_t at, int64_t stream_id, uint64_t limit);

    probe quicly_streams_blocked_send(struct st_quicly_conn_t *conn, int64_t at, uint64_t limit, int is_unidirectional);
    probe quicly_streams_blocked_receive(struct st_quicly_conn_t *conn, int64_t at, uint64_t limit, int is_unidirectional);

    probe quicly_data_blocked_receive(struct st_quicly_conn_t *conn, int64_t at, uint64_t off);

    probe quicly_stream_data_blocked_receive(struct st_quicly_conn_t *conn, int64_t at, int64_t stream_id, uint64_t limit);

    probe quicly_quictrace_sent(struct st_quicly_conn_t *conn, int64_t at, uint64_t pn, size_t len, uint8_t packet_type);
    probe quicly_quictrace_recv(struct st_quicly_conn_t *conn, int64_t at, uint64_t pn, size_t len, uint8_t enc_level);
    probe quicly_quictrace_send_stream(struct st_quicly_conn_t *conn, int64_t at, struct st_quicly_stream_t *stream,
                                       uint64_t off, size_t len, int fin);
    probe quicly_quictrace_recv_stream(struct st_quicly_conn_t *conn, int64_t at, int64_t stream_id, uint64_t off, size_t len,
                                       int fin);
    probe quicly_quictrace_recv_ack(struct st_quicly_conn_t *conn, int64_t at, uint64_t ack_block_begin, uint64_t ack_block_end);
    probe quicly_quictrace_lost(struct st_quicly_conn_t *conn, int64_t at, uint64_t pn);
    probe quicly_quictrace_cc_ack(struct st_quicly_conn_t *conn, int64_t at, uint32_t min_rtt, uint32_t smoothed_rtt,
                                  uint32_t latest_rtt, uint32_t cwnd, size_t inflight);
    probe quicly_quictrace_cc_lost(struct st_quicly_conn_t *conn, int64_t at, uint32_t min_rtt, uint32_t smoothed_rtt,
                                   uint32_t latest_rtt, uint32_t cwnd, size_t inflight);
};
