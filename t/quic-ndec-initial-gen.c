#include <stdio.h>
#include <stdint.h>

int main()
{
#define PACKET_LEN 1280
#define HEADER_LEN 35
#define LEN_HIGH (((PACKET_LEN - HEADER_LEN) & 0xff00) >> 8)
#define LEN_LOW ((PACKET_LEN - HEADER_LEN) & 0xff)
    uint8_t header[HEADER_LEN] = {
        /* first byte for Initial: 0b1100???? */
        0xc5,
        /* version (29) */
        0xff,
        0x00,
        0x00,
        0x1d,
        /* DCID len */
        0x11,
        /* DCID for node id 2, with "ticket-file: t/40session-ticket/forever_ticket.yaml" (see 40http3-forward.t) */
        0xa3,
        0x35,
        0x53,
        0xbd,
        0x9f,
        0xf0,
        0x24,
        0xd7,
        0x08,
        0x54,
        0x67,
        0x4c,
        0x07,
        0x3f,
        0x9b,
        0xe8,
        0x25,
        /* SCID len */
        0x08,
        /* SCID */
        0x69,
        0xf2,
        0x0b,
        0x46,
        0x8b,
        0x1b,
        0x60,
        0x6d,
        /* token length */
        0x00,
        /* token does not appear */
        /* length */
        (0x40 | LEN_HIGH),
        LEN_LOW,
    };
    FILE *fp = fopen("quic-nondecryptable-initial.bin", "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file for writing.\n");
        return 1;
    }
    fwrite(header, sizeof(header), 1, fp);
    for (int i = 0; i < PACKET_LEN - HEADER_LEN; i++)
        fputc(0, fp);
    fclose(fp);

    return 0;
}
