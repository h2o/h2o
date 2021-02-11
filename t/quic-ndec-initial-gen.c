#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define PACKET_LEN 1280
#define HEADER_LEN 35
#define LEN_HIGH (((PACKET_LEN - HEADER_LEN) & 0xff00) >> 8)
#define LEN_LOW ((PACKET_LEN - HEADER_LEN) & 0xff)
#define DCID_LEN 17

static void fill_header(uint8_t header[HEADER_LEN], uint8_t dcid[DCID_LEN], bool flip_scid)
{
    size_t i = 0;
    /* first byte for Initial: 0b1100???? */
    header[i++] = 0xc5;
    /* version (29) */
    header[i++] = 0xff;
    header[i++] = 0x00;
    header[i++] = 0x00;
    header[i++] = 0x1d;
    /* DCID len */
    header[i++] = 0x11;
    assert(i + DCID_LEN <= HEADER_LEN);
    for (size_t j = 0; j < DCID_LEN; j++)
        header[i++] = dcid[j];
    /* SCID len */
    header[i++] = 0x08;
    /* SCID */
    header[i++] = 0x69;
    header[i++] = 0xf2;
    header[i++] = 0x0b;
    header[i++] = 0x46;
    header[i++] = 0x8b;
    header[i++] = 0x1b;
    header[i++] = 0x60;
    header[i++] = 0x6d ^ (flip_scid ? 1 : 0);
    /* token length */
    header[i++] = 0x00;
    /* token does not appear */
    /* length */
    header[i++] = (0x40 | LEN_HIGH);
    header[i++] = LEN_LOW;

    assert(i == HEADER_LEN);
}

int main()
{

    uint8_t dcid_node1[DCID_LEN] = {
        /* DCID for node id 2, with "ticket-file: t/40session-ticket/forever_ticket.yaml" (see 40http3-forward.t) */
        0xa3, 0xc6, 0x82, 0xf3, 0x9d, 0xa2, 0xa7, 0x87, 0x8c, 0xd1, 0x78, 0x3f, 0xc1, 0xa7, 0x5f, 0x2e, 0x36,
    };
    uint8_t dcid_node2[DCID_LEN] = {
        /* DCID for node id 2, with "ticket-file: t/40session-ticket/forever_ticket.yaml" (see 40http3-forward.t) */
        0xa3, 0x35, 0x53, 0xbd, 0x9f, 0xf0, 0x24, 0xd7, 0x08, 0x54, 0x67, 0x4c, 0x07, 0x3f, 0x9b, 0xe8, 0x25,
    };
    uint8_t header[HEADER_LEN];

    FILE *fp;

    fp = fopen("quic-nondecryptable-initial.bin", "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open quic-nondecryptable-initial.bin for writing.\n");
        return 1;
    }
    fill_header(header, dcid_node2, false);
    fwrite(header, sizeof(header), 1, fp);
    for (int i = 0; i < PACKET_LEN - HEADER_LEN; i++)
        fputc(0, fp);
    fclose(fp);

    fp = fopen("quic-initial-w-corrupted-scid.bin", "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open quic-initial-w-corrupted-scid.bin for writing.\n");
        return 1;
    }
    fill_header(header, dcid_node1, true); /* flip SCID intentionally */
    fwrite(header, sizeof(header), 1, fp);
    for (int i = 0; i < PACKET_LEN - HEADER_LEN; i++)
        fputc(0, fp);
    fclose(fp);

    return 0;
}
