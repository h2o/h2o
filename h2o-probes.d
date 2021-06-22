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

/* @appdata
{
    "receive_request_header": ["name", "value"],
    "send_response_header": ["name", "value"],
    "h3_frame_receive": ["bytes"],
    "tunnel_on_read": ["bytes"],
    "tunnel_write": ["bytes"]
}
*/

provider h2o {
    /**
     * When a new connection is accepted, h2o invokes this probe to obtain the flags to be associated to the new connection. The
     * probe MUST write the result into the h2o_return map; see ebpf.h for details. `original_flags` contain the flags that will be
     * associated when the probe is not attached.
     *
     * Do not use it for a tracing event.
     */
    probe _private_socket_lookup_flags(pid_t tid, uint64_t original_flags, struct st_h2o_ebpf_map_key_t *info);
    /**
     * Same as `_private_socket_lookup_flags`, expect that this probe is invoked when SNI is being obtained.
     */
    probe _private_socket_lookup_flags_sni(pid_t tid, uint64_t original_flags, const char *server_name, size_t server_name_len);

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
    probe send_response(uint64_t conn_id, uint64_t req_id, int status, struct st_h2o_tunnel_t *tunnel);
    /**
     * HTTP-level event, indicating the response header fields being sent.
     */
    probe send_response_header(uint64_t conn_id, uint64_t req_id, const char *name, size_t name_len, const char *value,
                               size_t value_len);

    /**
     * HTTP/1 server-level event, indicating that a connection has been accepted.
     */
    probe h1_accept(uint64_t conn_id, struct st_h2o_socket_t *sock, struct st_h2o_conn_t *conn, const char *conn_uuid);
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
    probe h3s_accept(uint64_t conn_id, struct st_h2o_conn_t *conn, struct st_quicly_conn_t *quic, const char *conn_uuid);
    /**
     * HTTP/3 server-level event, indicating that a connection has been destroyed
     */
    probe h3s_destroy(uint64_t conn_id);
    /**
     * HTTP/3 server-level event, indicating that a state of a request stream has been altered
     */
    probe h3s_stream_set_state(uint64_t conn_id, uint64_t req_id, unsigned state);

    /**
     * HTTP/3 event, indicating that a H3 frame has been received. `bytes` is available except when frame_type is DATA.
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
    /**
     * HTTP/3 event, indicating that a QUIC packet forwarding to another node is triggered but ignored.
     */
    probe h3_packet_forward_to_node_ignore(uint64_t node_id);
    /**
     * HTTP/3 event, indicating that a QUIC packet forwarding to another thread is triggered but ignored.
     */
    probe h3_packet_forward_to_thread_ignore(uint32_t thread_id);
    /**
     * HTTP/3 event, indicating that a forwarded QUIC packet has been received.
     */
    probe h3_forwarded_packet_receive(struct sockaddr *dest, struct sockaddr *src, size_t num_bytes);

    /**
     * FIXME define probes for http3client, aligning the arguments of `h2o_tunnel_create`
     */
    probe h3c_tunnel_create(struct st_h2o_tunnel_t *tunnel);

    probe tunnel_on_destroy(struct st_h2o_tunnel_t *tunnel);
    probe tunnel_on_read(struct st_h2o_tunnel_t *tunnel, const char *err, const void *bytes, size_t bytes_len);
    probe tunnel_proceed_read(struct st_h2o_tunnel_t *tunnel);
    probe tunnel_write(struct st_h2o_tunnel_t *tunnel, const void *bytes, size_t bytes_len);
    probe tunnel_on_write_complete(struct st_h2o_tunnel_t *tunnel, const char *err);

    probe socket_tunnel_create(struct st_h2o_tunnel_t *tunnel);
    probe socket_tunnel_start(struct st_h2o_tunnel_t *tunnel, size_t bytes_to_consume);
};
