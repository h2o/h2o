#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define PACKET_LEN 1280
#define HEADER_LEN_MAX 35
#define DCID_LEN 17

enum scid_mode {
    SCID_NORMAL,
    SCID_FLIP,
    SCID_ZERO_LEN,
};

static uint8_t header_len_high(size_t header_len)
{
    return ((PACKET_LEN - header_len) & 0xff00) >> 8;
}

static uint8_t header_len_low(size_t header_len)
{
    return (PACKET_LEN - header_len) & 0xff;
}

static size_t fill_header(uint8_t header[HEADER_LEN_MAX], const uint8_t dcid[DCID_LEN], enum scid_mode scid_mode)
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
    assert(i + DCID_LEN <= HEADER_LEN_MAX);
    for (size_t j = 0; j < DCID_LEN; j++)
        header[i++] = dcid[j];
    /* SCID len */
    if (scid_mode == SCID_ZERO_LEN) {
        header[i++] = 0;
    } else {
        header[i++] = 0x08;
        /* SCID */
        header[i++] = 0x69;
        header[i++] = 0xf2;
        header[i++] = 0x0b;
        header[i++] = 0x46;
        header[i++] = 0x8b;
        header[i++] = 0x1b;
        header[i++] = 0x60;
        header[i++] = 0x6d ^ (scid_mode == SCID_FLIP ? 1 : 0);
    }
    /* token length */
    header[i++] = 0x00;
    /* token does not appear */
    /* length */
    size_t header_len = i + 2;
    header[i++] = (0x40 | header_len_high(header_len));
    header[i++] = header_len_low(header_len);

    assert(i <= HEADER_LEN_MAX);

    return i;
}

static int output(const char *filename, const uint8_t dcid[DCID_LEN], enum scid_mode scid_mode)
{
    uint8_t header[HEADER_LEN_MAX];
    size_t header_len;
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s for writing.\n", filename);
        return 1;
    }
    header_len = fill_header(header, dcid, scid_mode);
    fwrite(header, sizeof(header), 1, fp);
    for (size_t i = 0; i < PACKET_LEN - header_len; i++)
        fputc(0, fp);
    fclose(fp);

    return 0;
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
    int ret;

    ret = output("quic-nondecryptable-initial.bin", dcid_node2, SCID_NORMAL);
    if (ret)
        return ret;

    ret = output("quic-initial-w-corrupted-scid.bin", dcid_node1, SCID_FLIP);
    if (ret)
        return ret;

    ret = output("quic-initial-w-zerolen-scid.bin", dcid_node1, SCID_ZERO_LEN);
    if (ret)
        return ret;

    return 0;
}
