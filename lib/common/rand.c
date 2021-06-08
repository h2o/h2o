#include <openssl/rand.h>
#include <inttypes.h>
#include "h2o/rand.h"
#include "h2o/string_.h"
#include "picotls/openssl.h"

static void format_uuid_rfc4122(char *dst, const uint8_t *uuid)
{
    // String Representation:
    // > UUID  = time-low "-" time-mid "-"
    // >         time-high-and-version "-"
    // >         clock-seq-and-reserved
    // >         clock-seq-low "-" node
    // See also "4.1.2. Layout and Byte Order" for the layout
    size_t pos = 0;
#define UUID_ENC_PART(b, p, u, start, last) do { \
        h2o_hex_encode(&b[p], &u[start], last - start + 1); \
        p += (last - start + 1) * 2; \
    } while (0)

    UUID_ENC_PART(dst, pos, uuid, 0, 3); /* time_low */
    dst[pos++] = '-';
    UUID_ENC_PART(dst, pos, uuid, 4, 5); /* time_mid */
    dst[pos++] = '-';
    UUID_ENC_PART(dst, pos, uuid, 6, 7); /* time_hi_and_version */
    dst[pos++] = '-';
    UUID_ENC_PART(dst, pos, uuid, 8, 8); /* clock_seq_hi_and_reserved */
    UUID_ENC_PART(dst, pos, uuid, 9, 9); /* clock_seq_low */
    dst[pos++] = '-';
    UUID_ENC_PART(dst, pos, uuid, 10, 15); /* node */
#undef UUID_ENC_PART

    /* '\0' is set by h2o_hex_encode() */
}

void h2o_generate_uuidv4(char *buf)
{
    // RFC-4122 "A Universally Unique IDentifier (UUID) URN Namespace"
    // 4.4. Algorithms for Creating a UUID from Truly Random or Pseudo-Random Numbers

    uint8_t uuid[16];
    ptls_openssl_random_bytes((void*)&uuid, sizeof(uuid));

    // Variant:
    // > Set the two most significant bits (bits 6 and 7) of the
    // > clock_seq_hi_and_reserved to zero and one, respectively.
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    // Version:
    // > Set the four most significant bits (bits 12 through 15) of the
    // > time_hi_and_version field to the 4-bit version number from
    // > Section 4.1.3.
    uint8_t version = 4;
    uuid[6] = (uuid[6] & 0x0f) | (version << 4);
    format_uuid_rfc4122(buf, uuid);
}
