#ifndef h2o__timeout_val_h
#define h2o__timeout_val_h

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_h2o_timeout_val_t {
    unsigned int set : 1;
    uint64_t val : 63;
} h2o_timeout_val_t;

typedef struct st_h2o_timeout_abs_t {
    unsigned int set : 1;
    uint64_t val : 63;
} h2o_timeout_abs_t;

#define H2O_TIMEOUT_VAL_UNSET ((h2o_timeout_val_t){0, 0})
#define H2O_TIMEOUT_ABS_UNSET ((h2o_timeout_abs_t){0, 0})
static inline h2o_timeout_val_t h2o_timeout_val_from_uint(uint64_t val)
{
    h2o_timeout_val_t t = {1, val};
    return t;
}

static inline h2o_timeout_abs_t h2o_timeout_abs_from_uint(uint64_t val)
{
    h2o_timeout_abs_t t = {1, val};
    return t;
}

static inline int h2o_timeout_val_equal(h2o_timeout_val_t a, h2o_timeout_val_t b)
{
    return a.set == b.set && a.val == b.val;
}

#ifdef __cplusplus
}
#endif

#endif
