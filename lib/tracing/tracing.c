#include "h2o.h"
#include "h2o/tracing.h"

struct tracing_msg {
    uint64_t action;
};

uint64_t h2o_tracing_now;
uint64_t should_stop_probe;

#define IS_REMOVE_BIT_SET(x) ((x & H2O_TRACE_REMOVE_PROBE) == H2O_TRACE_REMOVE_PROBE)

static void close_connection(h2o_socket_t *sock)
{
    if (should_stop_probe != 0) {
        // disable selected probe from h2o_tracing_now
        __sync_fetch_and_and(&h2o_tracing_now, should_stop_probe);
        __sync_fetch_and_and(&should_stop_probe, 0x0);
    } else {
        // disable all probes
        __sync_fetch_and_and(&h2o_tracing_now, 0x0);
    }

    h2o_socket_close(sock);
}

static void on_tracing_message(h2o_socket_t *sock, struct tracing_msg *msg)
{
    if (IS_REMOVE_BIT_SET(msg->action)) {
        // add probe in disable list, will be removed upon closing
        uint64_t stopping = (~msg->action) & h2o_tracing_now;
        __sync_fetch_and_or(&should_stop_probe, stopping);
    } else {
        // add new probe to filter
        __sync_fetch_and_or(&h2o_tracing_now, msg->action);
    }

    h2o_buffer_consume(&sock->input, sizeof(struct tracing_msg));
}

void h2o_tracing_on_data(h2o_socket_t *sock)
{
    size_t inreqlen = sock->input->size < H2O_MAX_REQLEN ? sock->input->size : H2O_MAX_REQLEN;
    struct tracing_msg *msg;

    if (inreqlen < sizeof(*msg)) {
        return;
    }
    msg = (void *)sock->input->bytes;
    on_tracing_message(sock, msg);
}

void h2o_tracing_on_read(h2o_socket_t *sock, const char *err)
{
    if (err != NULL) {
        close_connection(sock);
    } else {
        h2o_tracing_on_data(sock);
    }
}
