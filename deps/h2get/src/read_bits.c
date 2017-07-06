#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "h2get.h"

uint8_t *read_bits(uint8_t *buf, uint8_t nr_bits, uint32_t *value, uint8_t *offset)
{
    uint32_t ret = 0;
    bool first = true;

    assert(*offset <= 7);
    assert(nr_bits <= 32);
    assert(nr_bits >= 1);

    uint8_t to_read_now = 0;
    while (nr_bits > 0) {
        to_read_now = nr_bits;
        if (to_read_now + *offset > 8) {
            to_read_now = 8U - *offset;
        }
        if (first) {
            first = false;
        } else {
            buf++;
            ret <<= to_read_now;
        }
        ret |= (*buf >> (8U - (to_read_now + *offset))) & ((1 << to_read_now) - 1);
        *offset = (8U - (*offset + to_read_now));
        nr_bits -= to_read_now;
    }
    *value = ret;
    return buf;
}

#ifdef TEST
int test_read_bits(void);
int test_read_bits(void)
{
    int i;
    int j;
    uint8_t *ret;
    uint32_t value;

    uint8_t *inputs[] = {
        (uint8_t[]){0b11111111},
        (uint8_t[]){0b10101010},
        (uint8_t[]){0b01010101},
        (uint8_t[]){0b11001100},
        (uint8_t[]){0b11111111, 0b11111111},
        (uint8_t[]){0b10101010, 0b10101010},
        (uint8_t[]){0b01010101, 0b01010101},
        (uint8_t[]){0b11001100, 0b11001100},
    };
    struct instance {
        uint8_t nr_bits;
        uint8_t offset;
        uint32_t expected_value;
        uint8_t expected_offset;
    };
    struct test {
        uint8_t *input;
        int nr_instances;
        int line;
        struct instance instances[20];
    };
    struct test tests[10];
    int nr_tests = 0;
    tests[nr_tests].input = inputs[0];
    tests[nr_tests].line = __LINE__;
    tests[nr_tests].nr_instances = 8;
    tests[nr_tests].instances[0] = ((struct instance){
        1, 0, 0b1, 7,
    });
    tests[nr_tests].instances[1] = ((struct instance){
        2, 0, 0b11, 6,
    });
    tests[nr_tests].instances[2] = ((struct instance){
        3, 0, 0b111, 5,
    });
    tests[nr_tests].instances[3] = ((struct instance){
        4, 0, 0b1111, 4,
    });
    tests[nr_tests].instances[4] = ((struct instance){
        5, 0, 0b11111, 3,
    });
    tests[nr_tests].instances[5] = ((struct instance){
        6, 0, 0b111111, 2,
    });
    tests[nr_tests].instances[6] = ((struct instance){
        7, 0, 0b1111111, 1,
    });
    tests[nr_tests].instances[7] = ((struct instance){
        8, 0, 0b11111111, 0,
    });
    nr_tests++;
    tests[nr_tests].input = inputs[1];
    tests[nr_tests].line = __LINE__;
    tests[nr_tests].nr_instances = 8;
    tests[nr_tests].instances[0] = ((struct instance){
        1, 0, 0b1, 7,
    });
    tests[nr_tests].instances[1] = ((struct instance){
        2, 0, 0b10, 6,
    });
    tests[nr_tests].instances[2] = ((struct instance){
        3, 0, 0b101, 5,
    });
    tests[nr_tests].instances[3] = ((struct instance){
        4, 0, 0b1010, 4,
    });
    tests[nr_tests].instances[4] = ((struct instance){
        5, 0, 0b10101, 3,
    });
    tests[nr_tests].instances[5] = ((struct instance){
        6, 0, 0b101010, 2,
    });
    tests[nr_tests].instances[6] = ((struct instance){
        7, 0, 0b1010101, 1,
    });
    tests[nr_tests].instances[7] = ((struct instance){
        8, 0, 0b10101010, 0,
    });
    nr_tests++;
    tests[nr_tests].input = inputs[2];
    tests[nr_tests].line = __LINE__;
    tests[nr_tests].nr_instances = 8;
    tests[nr_tests].instances[0] = ((struct instance){
        1, 0, 0b0, 7,
    });
    tests[nr_tests].instances[1] = ((struct instance){
        2, 0, 0b01, 6,
    });
    tests[nr_tests].instances[2] = ((struct instance){
        3, 0, 0b010, 5,
    });
    tests[nr_tests].instances[3] = ((struct instance){
        4, 0, 0b0101, 4,
    });
    tests[nr_tests].instances[4] = ((struct instance){
        5, 0, 0b01010, 3,
    });
    tests[nr_tests].instances[5] = ((struct instance){
        6, 0, 0b010101, 2,
    });
    tests[nr_tests].instances[6] = ((struct instance){
        7, 0, 0b0101010, 1,
    });
    tests[nr_tests].instances[7] = ((struct instance){
        8, 0, 0b01010101, 0,
    });
    nr_tests++;
    tests[nr_tests].input = inputs[3];
    tests[nr_tests].line = __LINE__;
    tests[nr_tests].nr_instances = 8;
    tests[nr_tests].instances[0] = ((struct instance){
        1, 0, 0b1, 7,
    });
    tests[nr_tests].instances[1] = ((struct instance){
        2, 0, 0b11, 6,
    });
    tests[nr_tests].instances[2] = ((struct instance){
        3, 0, 0b110, 5,
    });
    tests[nr_tests].instances[3] = ((struct instance){
        4, 0, 0b1100, 4,
    });
    tests[nr_tests].instances[4] = ((struct instance){
        5, 0, 0b11001, 3,
    });
    tests[nr_tests].instances[5] = ((struct instance){
        6, 0, 0b110011, 2,
    });
    tests[nr_tests].instances[6] = ((struct instance){
        7, 0, 0b1100110, 1,
    });
    tests[nr_tests].instances[7] = ((struct instance){
        8, 0, 0b11001100, 0,
    });
    nr_tests++;
    tests[nr_tests].input = inputs[3];
    tests[nr_tests].line = __LINE__;
    tests[nr_tests].nr_instances = 7;
    tests[nr_tests].instances[0] = ((struct instance){
        1, 1, 0b1, 6,
    });
    tests[nr_tests].instances[1] = ((struct instance){
        2, 1, 0b10, 5,
    });
    tests[nr_tests].instances[2] = ((struct instance){
        3, 1, 0b100, 4,
    });
    tests[nr_tests].instances[3] = ((struct instance){
        4, 1, 0b1001, 3,
    });
    tests[nr_tests].instances[4] = ((struct instance){
        5, 1, 0b10011, 2,
    });
    tests[nr_tests].instances[5] = ((struct instance){
        6, 1, 0b100110, 1,
    });
    tests[nr_tests].instances[6] = ((struct instance){
        7, 1, 0b1001100, 0,
    });
    nr_tests++;
    tests[nr_tests].input = inputs[4];
    tests[nr_tests].line = __LINE__;
    tests[nr_tests].nr_instances = 16;
    tests[nr_tests].instances[0] = ((struct instance){
        1, 0, 0b1, 7,
    });
    tests[nr_tests].instances[1] = ((struct instance){
        2, 0, 0b11, 6,
    });
    tests[nr_tests].instances[2] = ((struct instance){
        3, 0, 0b111, 5,
    });
    tests[nr_tests].instances[3] = ((struct instance){
        4, 0, 0b1111, 4,
    });
    tests[nr_tests].instances[4] = ((struct instance){
        5, 0, 0b11111, 3,
    });
    tests[nr_tests].instances[5] = ((struct instance){
        6, 0, 0b111111, 2,
    });
    tests[nr_tests].instances[6] = ((struct instance){
        7, 0, 0b1111111, 1,
    });
    tests[nr_tests].instances[7] = ((struct instance){
        8, 0, 0b11111111, 0,
    });
    tests[nr_tests].instances[8] = ((struct instance){
        9, 0, 0b111111111, 7,
    });
    tests[nr_tests].instances[9] = ((struct instance){
        10, 0, 0b1111111111, 6,
    });
    tests[nr_tests].instances[10] = ((struct instance){
        11, 0, 0b11111111111, 5,
    });
    tests[nr_tests].instances[11] = ((struct instance){
        12, 0, 0b111111111111, 4,
    });
    tests[nr_tests].instances[12] = ((struct instance){
        13, 0, 0b1111111111111, 3,
    });
    tests[nr_tests].instances[13] = ((struct instance){
        14, 0, 0b11111111111111, 2,
    });
    tests[nr_tests].instances[14] = ((struct instance){
        15, 0, 0b111111111111111, 1,
    });
    tests[nr_tests].instances[15] = ((struct instance){
        16, 0, 0b1111111111111111, 0,
    });
    nr_tests++;
    tests[nr_tests].input = inputs[5];
    tests[nr_tests].line = __LINE__;
    tests[nr_tests].nr_instances = 15;
    tests[nr_tests].instances[0] = ((struct instance){
        1, 1, 0b0, 6,
    });
    tests[nr_tests].instances[1] = ((struct instance){
        2, 1, 0b01, 5,
    });
    tests[nr_tests].instances[2] = ((struct instance){
        3, 1, 0b010, 4,
    });
    tests[nr_tests].instances[3] = ((struct instance){
        4, 1, 0b0101, 3,
    });
    tests[nr_tests].instances[4] = ((struct instance){
        5, 1, 0b01010, 2,
    });
    tests[nr_tests].instances[5] = ((struct instance){
        6, 1, 0b010101, 1,
    });
    tests[nr_tests].instances[6] = ((struct instance){
        7, 1, 0b0101010, 0,
    });
    tests[nr_tests].instances[7] = ((struct instance){
        8, 1, 0b01010101, 7,
    });
    tests[nr_tests].instances[8] = ((struct instance){
        9, 1, 0b010101010, 6,
    });
    tests[nr_tests].instances[9] = ((struct instance){
        10, 1, 0b0101010101, 5,
    });
    tests[nr_tests].instances[10] = ((struct instance){
        11, 1, 0b01010101010, 4,
    });
    tests[nr_tests].instances[11] = ((struct instance){
        12, 1, 0b010101010101, 3,
    });
    tests[nr_tests].instances[12] = ((struct instance){
        13, 1, 0b0101010101010, 2,
    });
    tests[nr_tests].instances[13] = ((struct instance){
        14, 1, 0b01010101010101, 1,
    });
    tests[nr_tests].instances[14] = ((struct instance){
        15, 1, 0b010101010101010, 0,
    });
    nr_tests++;

    for (i = 0; i < nr_tests; i++) {
        for (j = 0; j < tests[i].nr_instances; j++) {
            uint8_t offset;
            offset = tests[i].instances[j].offset;
            fprintf(stderr, "line: %d, test %d, instance %d, input: %u, "
                            "nr_bits: %u, offset: %u\n",
                    tests[i].line, i, j, tests[i].input[0], tests[i].instances[j].nr_bits, offset);
            ret = read_bits(tests[i].input, tests[i].instances[j].nr_bits, &value, &offset);
            assert(ret);
            if (tests[i].instances[j].expected_value != value) {
                fprintf(stderr, "%x %x\n", tests[i].instances[j].expected_value, value);
                assert(tests[i].instances[j].expected_value == value);
            }
            if (tests[i].instances[j].expected_offset != offset) {
                fprintf(stderr, "%x %x\n", tests[i].instances[j].expected_offset, offset);
                assert(tests[i].instances[j].expected_offset == offset);
            }
        }
    }

    return 0;
}

#endif

/* vim: set expandtab ts=4 sw=4: */
