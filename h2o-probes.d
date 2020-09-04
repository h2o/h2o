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

provider h2o {
    /**
     * HTTP-level event, indicating that a request has been received.
     */
    probe receive_request(uint64_t conn_id, uint64_t req_id, int http_version);
    /**
     * HTTP-level event, indicating the request header fields being received.
     */
    probe receive_request_header(uint64_t conn_id, uint64_t req_id, const char *name, size_t name_len, const char *value,
                                 size_t value_len);
    /**
     * HTTP-level event, indicating that a response has been sent.
     */
    probe send_response(uint64_t conn_id, uint64_t req_id, int status);
    /**
     * HTTP-level event, indicating the response header fields being sent.
     */
    probe send_response_header(uint64_t conn_id, uint64_t req_id, const char *name, size_t name_len, const char *value,
                               size_t value_len);

    /**
     * HTTP/1 server-level event, indicating that a connection has been accepted.
     */
    probe h1_accept(uint64_t conn_id, struct st_h2o_socket_t *sock, struct st_h2o_conn_t *conn);
    /**
     * HTTP/1 server-level event, indicating that a connection has been closed.
     */
    probe h1_close(uint64_t conn_id);

    /**
     * HTTP/2 server-level event, indicating that a frame of unknown type has been received.
     */
    probe h2_unknown_frame_type(uint64_t conn_id, uint8_t frame_type);

    /**
     * HTTP/3 server-level event, indicating that a new connection has been accepted
     */
    probe h3s_accept(uint64_t conn_id, struct st_h2o_conn_t *conn, struct st_quicly_conn_t *quic);
    /**
     * HTTP/3 server-level event, indicating that a connection has been destroyed
     */
    probe h3s_destroy(uint64_t conn_id);
    /**
     * HTTP/3 server-level event, indicating that a state of a request stream has been altered
     */
    probe h3s_stream_set_state(uint64_t conn_id, uint64_t req_id, unsigned state);

    /**
     * HTTP/3 event, indicating that a H3 frame has been received. `bttes` is available except when frame_type is DATA.
     */
    probe h3_frame_receive(uint64_t frame_type, const void *bytes, size_t bytes_len);
    /**
     * HTTP/3 event, indicating that a QUIC packet has been received.
     */
    probe h3_packet_receive(struct sockaddr *dest, struct sockaddr *src, const void *bytes, size_t bytes_len);
    /**
     * HTTP/3 event, indicating that a QUIC packet has been forwarded.
     */
    probe h3_packet_forward(struct sockaddr *dest, struct sockaddr *src, size_t num_packets, size_t num_bytes, int fd);

};
