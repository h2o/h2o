/** @file yrmcds_text.h
 *
 * Private header file for text protocol.
 */

#pragma once

#ifndef YRMCDS_TEXT_H_INCLUDED
#define YRMCDS_TEXT_H_INCLUDED

#include "yrmcds.h"

yrmcds_error yrmcds_text_get(yrmcds* c, const char* key, size_t key_len,
                             int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_touch(yrmcds* c, const char* key, size_t key_len,
                               uint32_t expire, int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_set(yrmcds* c, const char* key, size_t key_len,
                             const char* data, size_t data_len,
                             uint32_t flags, uint32_t expire, uint64_t cas,
                             int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_replace(yrmcds* c, const char* key, size_t key_len,
                                 const char* data, size_t data_len,
                                 uint32_t flags, uint32_t expire, uint64_t cas,
                                 int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_add(yrmcds* c, const char* key, size_t key_len,
                             const char* data, size_t data_len,
                             uint32_t flags, uint32_t expire, uint64_t cas,
                             int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_append(yrmcds* c, const char* key, size_t key_len,
                                const char* data, size_t data_len,
                                int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_prepend(yrmcds* c, const char* key, size_t key_len,
                                 const char* data, size_t data_len,
                                 int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_incr(yrmcds* c, const char* key, size_t key_len,
                              uint64_t value, int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_decr(yrmcds* c, const char* key, size_t key_len,
                              uint64_t value, int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_remove(yrmcds* c, const char* key, size_t key_len,
                                int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_flush(yrmcds* c, uint32_t delay,
                               int quiet, uint32_t* serial);
yrmcds_error yrmcds_text_version(yrmcds* c, uint32_t* serial);
yrmcds_error yrmcds_text_quit(yrmcds* c, uint32_t* serial);


#endif // YRMCDS_TEXT_H_INCLUDED
