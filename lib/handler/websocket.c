/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd. Kazuho Oku
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
#include <inttypes.h>
#include <stdio.h>
#include "picohttpparser.h"
#include "h2o.h"
#include "h2o/http1.h"

#define WS_GUID "85F448E0-C9A5-47A4-B2C6-D38446D62AC1"
#define MODULE_NAME "lib/handler/websocket.c"

typedef H2O_VECTOR(h2o_iovec_t) iovec_vector_t;

struct st_wsock_context_t {
    h2o_websocket_handler_t *handler;
    h2o_timeout_t io_timeout;
};

typedef struct st_websocket_generator_t websocket_generator_t;
struct st_websocket_generator_t {
	struct st_wsock_context_t * ctx;
    h2o_req_t *req;
    h2o_socketpool_connect_request_t *connect_req;
    h2o_socket_t * pipe_socket;
    h2o_socket_t * web_socket;
    h2o_timeout_t io_timeout;
    h2o_timeout_entry_t timeout;
    h2o_mem_pool_t pool;
};

struct st_h2o_websocket_handler_t {
    h2o_handler_t super;
    h2o_socketpool_t sockpool;
    h2o_websocket_config_vars_t config;
};

static void create_accept_key(char *dst, const char *client_key)
{
    uint8_t sha1buf[20], key_src[60];

    memcpy(key_src, client_key, 24);
    memcpy(key_src + 24, WS_GUID, 36);
    SHA1(key_src, sizeof(key_src), sha1buf);
    h2o_base64_encode(dst, sha1buf, sizeof(sha1buf), 0);
    dst[28] = '\0';
}

int h2o_is_websocket_handshake(h2o_req_t *req, const char **ws_client_key, const char ** ws_protocol, h2o_websocket_config_vars_t *config)
{
    ssize_t key_header_index;

    *ws_client_key = NULL;

    /* method */
    if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("GET"))) {
        /* ok */
    } else {
        return 0;
    }

    /* upgrade header */
    if (req->upgrade.base != NULL && h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("websocket"))) {
        /* ok */
    } else {
        return 0;
    }
    /* sec-websocket-key header */
    if ((key_header_index = h2o_find_header_by_str(&req->headers, H2O_STRLIT("sec-websocket-key"), -1)) != -1) {
        if (req->headers.entries[key_header_index].value.len != 24) {
            return -1;
        }
    } else {
        return 0;
    }
    /* sec-websocket-protocol */
    if (config->accept_protocol.base != NULL) {
    	if ((key_header_index = h2o_find_header_by_str(&req->headers, H2O_STRLIT("sec-websocket-protocol"), -1)) != -1) {
    		if(strcasecmp(req->headers.entries[key_header_index].value.base, config->accept_protocol.base)){
    			return -1;
    		}
    		*ws_protocol = config->accept_protocol.base;
		} else {
			return -1;//could not find protocol
		}
    }

    *ws_client_key = req->headers.entries[key_header_index].value.base;
    return 0;
}

void send_socket_data(websocket_generator_t * generator, h2o_socket_t *sock, h2o_buffer_t **input, h2o_socket_cb cb){
	if(generator && sock){
	    size_t recSize = (*input)->size;
	    h2o_iovec_t record = h2o_iovec_init(h2o_mem_alloc_pool(&generator->pool, recSize), recSize);
	    memcpy(record.base, (*input)->bytes, recSize);
	    h2o_socket_write(sock, &record, 1, cb);
		h2o_buffer_consume(input, recSize);

		/*later reset IO timeout timer here*/
	}
}

static void close_generator(struct st_websocket_generator_t *generator)
{
    /* can be called more than once */
    if (h2o_timeout_is_linked(&generator->timeout))
        h2o_timeout_unlink(&generator->timeout);

    if (generator->pipe_socket != NULL) {
        h2o_socket_close(generator->pipe_socket);
        generator->pipe_socket = NULL;
    }
    if (generator->web_socket != NULL) {
        h2o_socket_close(generator->web_socket);
        generator->web_socket = NULL;
    }
    h2o_mem_clear_pool(&generator->pool);
    free(generator);
}
/*websocket components*/
static void errorclose(struct st_websocket_generator_t *generator)
{
	h2o_send_error_503(generator->req, "Internal Server Error", "Internal Server Error", 0);
	close_generator(generator);
}

static void websocket_on_send_complete(h2o_socket_t *sock, const char *err)
{
	websocket_generator_t * generator = sock->data;
    if (err != NULL) {
    	h2o_req_log_error(generator->req, MODULE_NAME, "websocket write failed:%s", err);
    	close_generator(generator);
        return;
    }
    h2o_mem_clear_pool(&generator->pool);
}

static void websocket_on_recv(h2o_socket_t *sock, const char *err)
{
	websocket_generator_t * generator = sock->data;
    if (err != NULL) {
    	h2o_req_log_error(generator->req, MODULE_NAME, "websocket read failed:%s", err);
    	close_generator(generator);
        return;
    }

	send_socket_data(generator, generator->pipe_socket, &sock->input, websocket_on_send_complete);
	h2o_socket_read_start(generator->web_socket, websocket_on_recv);
}

static void websocket_on_complete(void *user_data, h2o_socket_t *sock, size_t reqsize)
{
	websocket_generator_t * generator = user_data;
    /* close the connection on error */
    if (sock == NULL) {//if this fails, there is no reason to send an error
    	h2o_req_log_error(generator->req, MODULE_NAME, "websocket connection failed");
    	close_generator(generator);
        return;
    }

    generator->web_socket = sock;
    sock->data = generator;
    h2o_buffer_consume(&sock->input, reqsize);
    h2o_socket_read_start(generator->web_socket, websocket_on_recv);
    h2o_mem_clear_pool(&generator->pool);
}


static void h2o_upgrade_to_websocket(h2o_req_t *req, const char *client_key, const char * client_protocol, void *data)
{
    char accept_key[29];
    /* build response */
    create_accept_key(accept_key, client_key);
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, NULL, H2O_STRLIT("websocket"));
    h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("sec-websocket-accept"), 0, NULL, accept_key,
                          strlen(accept_key));
    if (client_protocol)
    {
    	h2o_add_header_by_str(&req->pool, &req->res.headers, H2O_STRLIT("sec-websocket-protocol"), 0, NULL, client_protocol,
    	                  strlen(client_protocol));
    }

    /* send */
    h2o_http1_upgrade(req, NULL, 0, websocket_on_complete, data);
}

/*internal socket components*/

static void on_internal_send_complete(h2o_socket_t *sock, const char *err)
{
	websocket_generator_t * generator = sock->data;
    if (err != NULL) {
    	h2o_req_log_error(generator->req, MODULE_NAME, "internal write connection failed:%s", err);
    	close_generator(generator);
        return;
    }
}

static void on_internal_socket_read(h2o_socket_t * sock, const char *err)
{
	websocket_generator_t * generator = sock->data;
    if (err != NULL) {
    	h2o_req_log_error(generator->req, MODULE_NAME, "internal socket read failed:%s", err);
    	close_generator(generator);
        return;
    }

    send_socket_data(generator, generator->web_socket, &sock->input, on_internal_send_complete);
    h2o_socket_read_start(sock, on_internal_socket_read);
}

static void on_internal_socket_connect(h2o_socket_t *sock, const char *errstr, void *data)
{
	websocket_generator_t * generator = data;
    if (sock == NULL) {
    	h2o_req_log_error(generator->req, MODULE_NAME, "internal socket connection failed:%s", errstr);
    	errorclose(generator);
        return;
    }

    generator->pipe_socket = sock;
    sock->data = generator;
    h2o_socket_read_start(sock, on_internal_socket_read);
}
/*generator components*/
/* enable this later, first need to understand how to reset the timeout based on each positive read*/
/*
static void on_rw_timeout(h2o_timeout_entry_t *entry)
{
    struct st_websocket_generator_t *generator = H2O_STRUCT_FROM_MEMBER(struct st_websocket_generator_t, timeout, entry);
    h2o_req_log_error(generator->req, MODULE_NAME, "I/O timeout");
    errorclose(generator);
}

static void set_timeout(struct st_websocket_generator_t *generator, h2o_timeout_t *timeout, h2o_timeout_cb cb)
{
    if (h2o_timeout_is_linked(&generator->timeout))
        h2o_timeout_unlink(&generator->timeout);

    generator->timeout.cb = cb;
    h2o_timeout_link(generator->req->conn->ctx->loop, timeout, &generator->timeout);
}
*/

/*actual h2o request, sets up connection, build up internal connection context*/
static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    const char *client_key;
    const char *client_protocol = NULL;

    h2o_websocket_handler_t *handler = (void *)_handler;
    websocket_generator_t * generator = calloc(1, sizeof(websocket_generator_t));
    generator->ctx = h2o_context_get_handler_context(req->conn->ctx, &handler->super);
    generator->req = req;
    generator->web_socket = NULL;
    generator->pipe_socket = NULL;

    h2o_mem_init_pool(&generator->pool);
    generator->timeout = (h2o_timeout_entry_t){0};

    if (h2o_is_websocket_handshake(req, &client_key, &client_protocol, &generator->ctx->handler->config) != 0 || client_key == NULL || req->version >= 0x200) {
    	h2o_send_error_500(generator->req, "Could not upgrade websocket", "Could not upgrade websocket", 0);
    	close_generator(generator);
        return -1;
    }

    //set_timeout(generator, &generator->ctx->io_timeout, on_rw_timeout);
    h2o_socketpool_connect(&generator->connect_req, &handler->sockpool, req->conn->ctx->loop,
                               &req->conn->ctx->receivers.hostinfo_getaddr, on_internal_socket_connect, generator);

    h2o_upgrade_to_websocket(req, client_key, client_protocol, generator);
    return 0;
}

static void on_context_init(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_websocket_handler_t *handler = (void *)_handler;
    struct st_wsock_context_t *handler_ctx = h2o_mem_alloc(sizeof(*handler_ctx));
    /* use the first event loop for handling timeouts of the socket pool */

    if (handler->sockpool.timeout == UINT64_MAX)
        h2o_socketpool_set_timeout(&handler->sockpool, ctx->loop,60000);
                                  // handler->config.keepalive_timeout != 0 ? handler->config.keepalive_timeout : 60000); //maybe enable config later

    handler_ctx->handler = handler;
    h2o_timeout_init(ctx->loop, &handler_ctx->io_timeout, handler->config.io_timeout);

    h2o_context_set_handler_context(ctx, &handler->super, handler_ctx);
}

static void on_context_dispose(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_websocket_handler_t *handler = (void *)_handler;
    struct st_wsock_context_t *handler_ctx = h2o_context_get_handler_context(ctx, &handler->super);

    if (handler_ctx == NULL)
        return;

    h2o_timeout_dispose(ctx->loop, &handler_ctx->io_timeout);
    free(handler_ctx);
}

static void on_handler_dispose(h2o_handler_t *_handler)
{
    h2o_websocket_handler_t *handler = (void *)_handler;

    if (handler->config.callbacks.dispose != NULL)
        handler->config.callbacks.dispose(handler, handler->config.callbacks.data);

    h2o_socketpool_dispose(&handler->sockpool);
    free(handler->config.accept_protocol.base);
}

static h2o_websocket_handler_t *register_common(h2o_pathconf_t *pathconf, h2o_websocket_config_vars_t *vars)
{
    h2o_websocket_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));

    handler->super.on_context_init = on_context_init;
    handler->super.on_context_dispose = on_context_dispose;
    handler->super.dispose = on_handler_dispose;
    handler->super.on_req = on_req;
    handler->config = *vars;
    if (vars->accept_protocol.base != NULL)
        handler->config.accept_protocol = h2o_strdup(NULL, vars->accept_protocol.base, vars->accept_protocol.len);

    return handler;
}

h2o_websocket_handler_t *h2o_websocket_register_by_hostport(h2o_pathconf_t *pathconf, const char *host, uint16_t port, h2o_websocket_config_vars_t *vars)
{
    h2o_websocket_handler_t *handler = register_common(pathconf, vars);

    h2o_socketpool_init_by_hostport(&handler->sockpool, h2o_iovec_init(host, strlen(host)), port, 0, SIZE_MAX /* FIXME */);
    return handler;
}

h2o_websocket_handler_t *h2o_websocket_register_by_address(h2o_pathconf_t *pathconf, struct sockaddr *sa, socklen_t salen, h2o_websocket_config_vars_t *vars)
{
    h2o_websocket_handler_t *handler = register_common(pathconf, vars);

    h2o_socketpool_init_by_address(&handler->sockpool, sa, salen, 0, SIZE_MAX /* FIXME */);
    return handler;
}
