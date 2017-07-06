#ifndef HUFFMAN_TABLE_H__
#define HUFFMAN_TABLE_H__

#include <stdint.h>

static uint8_t htable_five[] = { 48, 49, 50, 97, 99, 101, 105, 111, 115, 116, };
static uint8_t htable_six[] = { 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56, 57, 61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117, };
static uint8_t htable_seven[] = { 58, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119, 120, 121, 122, };
static uint8_t htable_eight[] = { 38, 42, 44, 59, 88, 90, };
static uint8_t htable_ten[] = { 33, 34, 40, 41, 63, };
static uint8_t htable_eleven[] = { 39, 43, 124, };
static uint8_t htable_twelve[] = { 35, 62, };
static uint8_t htable_thirteen[] = { 0, 36, 64, 91, 93, 126, };
static uint8_t htable_fourteen[] = { 94, 125, };
static uint8_t htable_fifteen[] = { 60, 96, 123, };
static uint8_t htable_sixteen[] = { 92, 195, 208, };
static uint8_t htable_twenty[] = { 128, 130, 131, 162, 184, 194, 224, 226, };
static uint8_t htable_twenty_one[] = { 153, 161, 167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, };
static uint8_t htable_twenty_two[] = { 129, 132, 133, 134, 136, 146, 154, 156, 160, 163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232, 233, };
static uint8_t htable_twenty_three[] = { 1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174, 175, 180, 182, 183, 188, 191, 197, 231, 239, };
static uint8_t htable_twenty_four[] = { 9, 142, 144, 145, 148, 159, 171, 206, 215, 225, 236, 237, };
static uint8_t htable_twenty_five[] = { 199, 207, 234, 235, };
static uint8_t htable_twenty_six[] = { 192, 193, 200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242, 243, 255, };
static uint8_t htable_twenty_seven[] = { 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252, 253, 254, };
static uint8_t htable_twenty_eight[] = { 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127, 220, 249, };
static uint8_t htable_twenty_thirty[] = { 10, 13, 22, 0 /* really, EOS */ };

static struct {
    uint8_t shift;
    uint32_t min;
    uint32_t max;
    uint8_t *chars;
} htable[] = {
    { 5, 0x0, 0x9, htable_five, },
    { 6, 0x14, 0x2d, htable_six, },
    { 7, 0x5c, 0x7b, htable_seven, },
    { 8, 0xf8, 0xfd, htable_eight, },
    { 10, 0x3f8, 0x3fc, htable_ten, },
    { 11, 0x7fa, 0x7fc, htable_eleven, },
    { 12, 0xffa, 0xffb, htable_twelve, },
    { 13, 0x1ff8, 0x1ffd, htable_thirteen, },
    { 14, 0x3ffc, 0x3ffd, htable_fourteen, },
    { 15, 0x7ffc, 0x7ffe, htable_fifteen, },
    { 19, 0x7fff0, 0x7fff2, htable_sixteen, },
    { 20, 0xfffe6, 0xfffed, htable_twenty, },
    { 21, 0x1fffdc, 0x1fffe8, htable_twenty_one, },
    { 22, 0x3fffd2, 0x3fffeb, htable_twenty_two, },
    { 23, 0x7fffd8, 0x7ffff4, htable_twenty_three, },
    { 24, 0xffffea, 0xfffff5, htable_twenty_four, },
    { 25, 0x1ffffec, 0x1ffffef, htable_twenty_five, },
    { 26, 0x3ffffe0, 0x3ffffee, htable_twenty_six, },
    { 27, 0x7ffffde, 0x7fffff0, htable_twenty_seven, },
    { 28, 0xfffffe2, 0xffffffe, htable_twenty_eight, },
    { 30, 0x3ffffffc, 0x3fffffff, htable_twenty_thirty, },
};

#endif /* HUFFMAN_TABLE_H__ */
/* vim: set expandtab ts=4 sw=4: */
