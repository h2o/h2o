/*
 * Copyright (c) 2020 Fastly, Kazuho Oku
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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/http3/server.c"

struct sched_node_t {
    struct st_h2o_http3_req_scheduler_node_t super;
    unsigned id;
};

static int compare_node(struct st_h2o_http3_req_scheduler_t *sched, const struct st_h2o_http3_req_scheduler_node_t *_x,
                        const struct st_h2o_http3_req_scheduler_node_t *_y)
{
    struct sched_node_t *x = (void *)_x, *y = (void *)_y;
    if (x->id < y->id) {
        return -1;
    } else if (x->id > y->id) {
        return 1;
    } else {
        return 0;
    }
}

static struct sched_node_t *get_top_node(struct st_h2o_http3_req_scheduler_t *sched)
{
    h2o_linklist_t *anchor = &sched->active.urgencies[sched->active.smallest_urgency].high;
    if (h2o_linklist_is_empty(anchor)) {
        anchor = &sched->active.urgencies[sched->active.smallest_urgency].low;
        assert(!h2o_linklist_is_empty(anchor));
    }
    return H2O_STRUCT_FROM_MEMBER(struct sched_node_t, super.link, anchor->next);
}

static void run_once(struct st_h2o_http3_req_scheduler_t *sched)
{
    struct sched_node_t *top = get_top_node(sched);
    ++top->super.call_cnt;
    req_scheduler_setup_for_next(sched, &top->super, compare_node);
}

static void test_scheduler(void)
{
    struct st_h2o_http3_req_scheduler_t sched;

    req_scheduler_init(&sched);
    ok(sched.active.smallest_urgency == H2O_ABSPRIO_NUM_URGENCY_LEVELS);

    /* add three nodes in non-sequential order, check that they are ordered in sequence */
    struct sched_node_t node1 = {.super = {.priority = {.urgency = 1}}, .id = 1};
    struct sched_node_t node4 = {.super = {.priority = {.urgency = 1}}, .id = 4};
    struct sched_node_t node5 = {.super = {.priority = {.urgency = 1}}, .id = 5};
    req_scheduler_activate(&sched, &node1.super, compare_node);
    req_scheduler_activate(&sched, &node5.super, compare_node);
    req_scheduler_activate(&sched, &node4.super, compare_node);
    ok(get_top_node(&sched) == &node1);
    ok(get_top_node(&sched)->super.link.next == &node4.super.link);
    ok(get_top_node(&sched)->super.link.next->next == &node5.super.link);
    ok(get_top_node(&sched)->super.link.next->next->next == &sched.active.urgencies[1].high);

    /* running the top node (which is non-sequential) does not change the order */
    run_once(&sched);
    ok(get_top_node(&sched) == &node1);

    /* retire the top node, check that the id=4 is promoted */
    req_scheduler_deactivate(&sched, &node1.super);
    ok(get_top_node(&sched) == &node4);
    ok(get_top_node(&sched)->super.link.next == &node5.super.link);
    ok(get_top_node(&sched)->super.link.next->next == &sched.active.urgencies[1].high);

    /* add node2, 3 that are incremental, their initial slots will be in "high", in sequential order */
    struct sched_node_t node2 = {.super = {.priority = {.urgency = 1, .incremental = 1}}, .id = 2};
    struct sched_node_t node3 = {.super = {.priority = {.urgency = 1, .incremental = 1}}, .id = 3};
    req_scheduler_activate(&sched, &node2.super, compare_node);
    req_scheduler_activate(&sched, &node3.super, compare_node);
    ok(get_top_node(&sched) == &node2);
    ok(get_top_node(&sched)->super.link.next == &node3.super.link);
    ok(get_top_node(&sched)->super.link.next->next == &node4.super.link);
    ok(get_top_node(&sched)->super.link.next->next->next == &node5.super.link);
    ok(get_top_node(&sched)->super.link.next->next->next->next == &sched.active.urgencies[1].high);

    /* run the top node multiple times; node2, node3 are moved to lower, but node4 stays at the top */
    run_once(&sched);
    ok(get_top_node(&sched) == &node3);
    run_once(&sched);
    ok(get_top_node(&sched) == &node4);
    for (int i = 0; i < 3; ++i) {
        run_once(&sched);
        ok(get_top_node(&sched) == &node4);
    }

    /* retire the non-incremental ones, check that the incremental ones are invoked one by one */
    req_scheduler_deactivate(&sched, &node4.super);
    req_scheduler_deactivate(&sched, &node5.super);
    for (int i = 0; i < 4; ++i) {
        ok(get_top_node(&sched) == &node2);
        run_once(&sched);
        ok(get_top_node(&sched) == &node3);
        run_once(&sched);
    }
    ok(get_top_node(&sched) == &node2);

    /* node at a higher urgency level cuts in */
    struct sched_node_t node6 = {.super = {.priority = {.urgency = 0}}, .id = 6};
    req_scheduler_activate(&sched, &node6.super, compare_node);
    ok(get_top_node(&sched) == &node6);
    run_once(&sched);
    ok(get_top_node(&sched) == &node6);

    /* retire all nodes */
    req_scheduler_deactivate(&sched, &node2.super);
    req_scheduler_deactivate(&sched, &node3.super);
    req_scheduler_deactivate(&sched, &node6.super);
    ok(sched.active.smallest_urgency == H2O_ABSPRIO_NUM_URGENCY_LEVELS);
}

static int handle_input_called;

static quicly_error_t handle_input_record_call(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src,
                                               const uint8_t *src_end, int in_generator, const char **err_desc)
{
    ++handle_input_called;
    *src = src_end;
    return 0;
}

static void receive_fin_then_reset(quicly_stream_t *qs, struct st_h2o_http3_server_stream_t *stream)
{
    static const uint8_t data[10];
    size_t len;
    uint64_t bytes_missing;

    quicly_recvstate_init(&qs->recvstate);
    h2o_buffer_init(&stream->recvbuf.buf, &h2o_socket_buffer_prototype);
    stream->recvbuf.handle_input = handle_input_record_call;

    /* receive bytes 0-9 and consume them, then bytes 90-99 with FIN, then RESET_STREAM with the same final size */
    len = 10;
    ok(quicly_recvstate_update(&qs->recvstate, 0, &len, 0, 10) == 0);
    qs->recvstate.data_off = 10;
    len = 10;
    ok(quicly_recvstate_update(&qs->recvstate, 90, &len, 1, 10) == 0);
    h2o_http3_update_recvbuf(&stream->recvbuf.buf, 90 - qs->recvstate.data_off, data, len);
    ok(quicly_recvstate_reset(&qs->recvstate, 100, &bytes_missing) == 0);
    ok(quicly_recvstate_transfer_complete(&qs->recvstate));
    ok(qs->recvstate.eos == 100);
}

static void test_reset_received(void)
{
    quicly_stream_t qs = {.stream_id = 0};
    struct st_h2o_http3_server_stream_t stream = {.quic = &qs, .state = H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY};
    qs.data = &stream;

    receive_fin_then_reset(&qs, &stream);
    stream.reset_received = 1;

    handle_input_called = 0;
    handle_buffered_input(&stream, 1);
    ok(handle_input_called == 0);
    ok(get_request_stream_size(&stream) == 10);

    h2o_buffer_dispose(&stream.recvbuf.buf);
}

static void test_reset_received_close_wait(void)
{
    quicly_stream_t qs = {.stream_id = 0};
    struct st_h2o_http3_server_stream_t stream = {.quic = &qs, .state = H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT};
    qs.data = &stream;

    receive_fin_then_reset(&qs, &stream);
    on_receive_reset_close_wait(&qs, H2O_HTTP3_ERROR_REQUEST_CANCELLED);
    ok(stream.reset_received);
    ok(get_request_stream_size(&stream) == 10);

    h2o_buffer_dispose(&stream.recvbuf.buf);
}

void test_lib__http3_server(void)
{
    subtest("scheduler", test_scheduler);
    subtest("reset-received", test_reset_received);
    subtest("reset-received-close-wait", test_reset_received_close_wait);
}
