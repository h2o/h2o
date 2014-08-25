#ifndef h2o__internal_h
#define h2o__internal_h

static uint16_t decode16u(const uint8_t *src);
static uint32_t decode24u(const uint8_t *src);
static uint32_t decode32u(const uint8_t *src);
static uint8_t *encode24u(uint8_t *dst, uint32_t value);
static uint8_t *encode32u(uint8_t *dst, uint32_t value);

static size_t sz_min(size_t x, size_t y);

inline uint16_t decode16u(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

inline uint32_t decode24u(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

inline uint32_t decode32u(const uint8_t *src)
{
    return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
}

inline uint8_t *encode24u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline uint8_t *encode32u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 24;
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline size_t sz_min(size_t x, size_t y)
{
    return x < y ? x : y;
}

#endif
