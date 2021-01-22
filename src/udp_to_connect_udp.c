#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/uio.h>


#include "picotls.h"

int main(int argc, char **argv)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ssin = {}, bsin = {};
    int e = epoll_create1(0);

    ssin.sin_family = AF_INET;
    ssin.sin_port = htons(atoi(argv[1]));
    ssin.sin_addr.s_addr = inet_addr("127.0.0.1");

    int optval = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt reuseaddr");
        exit(1);
    }
    int ret = bind(s, (void *)&ssin, sizeof(ssin));
    if (ret != 0) {
        perror("bind");
        exit(1);
    }

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = s,  };
    ret = epoll_ctl(e, EPOLL_CTL_ADD, s, &ev);
    if (ret != 0) {
        perror("epoll_ctl");
        exit(1);
    }

    int b = -1;
    struct sockaddr_storage peer;
    while (1) {
        ret = epoll_wait(e, &ev, 1, -1);
        if (ret < 0) {
            perror("epoll_wait");
            exit(1);
        }
        if (ev.data.fd == s) {
            char buf[64*1024];
            struct iovec vec;
            struct msghdr mess;
            memset(&mess, 0, sizeof(mess));
            mess.msg_name = &peer;
            mess.msg_namelen = sizeof(peer);
            vec.iov_base = buf;
            vec.iov_len = sizeof(buf);
            mess.msg_iov = &vec;
            mess.msg_iovlen = 1;
            ssize_t rret;
            while ((rret = recvmsg(s, &mess, 0)) == -1 && errno == EINTR)
                ;
            if (b == -1 ) {
                b = socket(AF_INET, SOCK_STREAM, 0);

                bsin.sin_family = AF_INET;
                bsin.sin_port = htons(atoi(argv[2]));
                bsin.sin_addr.s_addr = inet_addr("127.0.0.1");

                ret = connect(b, (void *)&bsin, sizeof(bsin));
                if (ret != 0) {
                    perror("connect");
                    exit(1);
                }

                char req[] = "CONNECT-UDP 8.8.8.8:53 HTTP/1.1\r\n\r\n";
                ret = write(b, req, sizeof(req) - 1);
                if (ret != sizeof(req) - 1) {
                    perror("write");
                    exit(1);
                }
                char resp[1024];
                ret = read(b, resp, sizeof(resp));
                if (ret <= 0) {
                    perror("read");
                    exit(1);
                }
                fprintf(stderr, "Response: %.*s\n", (int)ret, resp);

                struct epoll_event ev = { .events = EPOLLIN, .data.fd = b,  };
                ret = epoll_ctl(e, EPOLL_CTL_ADD, b, &ev);
                if (ret != 0) {
                    perror("epoll_ctl");
                    exit(1);
                }
                int flags = fcntl(b, F_GETFL, 0);
                assert(flags != -1);
                ret = fcntl(b, F_SETFL, flags | O_NONBLOCK);
                if (ret == -1) {
                    perror("fcntl");
                    exit(1);
                }

            }
            if (rret == -1) {
                perror("recvmsg");
                exit(1);
            }
            if (rret == 0) {
                perror("zero message lenght, exiting");
                exit(1);
            }

            struct iovec iov[3];
            uint8_t zero = 0;
            uint8_t varint[8];
            uint8_t *varint_end;
            size_t varint_len;
            varint_end = ptls_encode_quicint((char *)varint, rret);
            varint_len = varint_end - varint;
            iov[0].iov_base = &zero;
            iov[0].iov_len = sizeof(zero);
            iov[1].iov_base = varint;
            iov[1].iov_len = varint_len;
            iov[2].iov_base = buf;
            iov[2].iov_len = rret;
            ret = writev(b, iov, 3);
            assert(ret == (rret + varint_len + sizeof(zero)));

            continue;
        } else if (ev.data.fd == b) {
            char *end;
            char req[128*1024];
            uint64_t chunked_buf;
            int ret = read(b, req, sizeof(req));
            if (ret < 0) {
                perror("read");
                exit(1);
            }
            if (ret == 0) {
                printf("Client closed, exiting\n");
                exit(0);
            }
            uint64_t chunk_type;
            uint64_t chunk_length;
            const uint8_t *cur = (void *)req;
            chunk_type = ptls_decode_quicint(&cur, req + ret);
            assert(cur != NULL);
            chunk_length = ptls_decode_quicint(&cur, req + ret);
            assert(cur != NULL);
            assert((void *)(cur + chunk_length) == (req + ret));

            struct msghdr mess;
            struct iovec vec;

            memset(&mess, 0, sizeof(mess));

            vec.iov_base = (void *)cur;
            vec.iov_len = chunk_length;
            mess.msg_name = &peer;
            mess.msg_namelen = sizeof(peer);
            mess.msg_iov = &vec;
            mess.msg_iovlen = 1;

            int rret = sendmsg(s, &mess, 0);
            assert(rret == chunk_length);
            continue;
        } else {
            fprintf(stderr, "%s:%d unexpected: %d\n", __func__, __LINE__, ev.data.fd);
            exit(1);
        }
    }
    return 0;
}
