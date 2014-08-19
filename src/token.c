#include "h2o.h"
#include "token_table.h"

int h2o_buf_is_token(const uv_buf_t *buf)
{
    return &h2o__tokens[0].buf <= buf && buf < &h2o__tokens[H2O_MAX_TOKENS].buf;
}
