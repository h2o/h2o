/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef yoml_h
#define yoml_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>

typedef enum enum_yoml_type_t { YOML_TYPE_SCALAR, YOML_TYPE_SEQUENCE, YOML_TYPE_MAPPING, YOML__TYPE_UNRESOLVED_ALIAS } yoml_type_t;

typedef struct st_yoml_t yoml_t;

typedef struct st_yoml_sequence_t {
    size_t size;
    yoml_t *elements[1];
} yoml_sequence_t;

typedef struct st_yoml_mapping_element_t {
    yoml_t *key;
    yoml_t *value;
} yoml_mapping_element_t;

typedef struct st_yoml_mapping_t {
    size_t size;
    yoml_mapping_element_t elements[1];
} yoml_mapping_t;

struct st_yoml_t {
    yoml_type_t type;
    char *filename;
    size_t line;
    size_t column;
    char *anchor;
    char *tag;
    size_t _refcnt;
    union {
        char *scalar;
        yoml_sequence_t sequence;
        yoml_mapping_t mapping;
        char *alias;
    } data;
};

static inline void yoml_free(yoml_t *node, void *(*mem_set)(void *, int, size_t))
{
    size_t i;

    if (node == NULL)
        return;

    if (--node->_refcnt == 0) {
        free(node->filename);
        free(node->anchor);
        free(node->tag);
        switch (node->type) {
        case YOML_TYPE_SCALAR:
            if (mem_set != NULL)
                mem_set(node->data.scalar, 0, strlen(node->data.scalar));
            free(node->data.scalar);
            break;
        case YOML_TYPE_SEQUENCE:
            for (i = 0; i != node->data.sequence.size; ++i) {
                yoml_free(node->data.sequence.elements[i], mem_set);
            }
            break;
        case YOML_TYPE_MAPPING:
            for (i = 0; i != node->data.mapping.size; ++i) {
                yoml_free(node->data.mapping.elements[i].key, mem_set);
                yoml_free(node->data.mapping.elements[i].value, mem_set);
            }
            break;
        case YOML__TYPE_UNRESOLVED_ALIAS:
            free(node->data.alias);
            break;
        }
        free(node);
    }
}

static inline yoml_t *yoml_find_anchor(yoml_t *node, const char *name)
{
    yoml_t *n;
    size_t i;

    if (node->anchor != NULL && strcmp(node->anchor, name) == 0)
        return node;

    switch (node->type) {
    case YOML_TYPE_SEQUENCE:
        for (i = 0; i != node->data.sequence.size; ++i)
            if ((n = yoml_find_anchor(node->data.sequence.elements[i], name)) != NULL)
                return n;
        break;
    case YOML_TYPE_MAPPING:
        for (i = 0; i != node->data.mapping.size; ++i)
            if ((n = yoml_find_anchor(node->data.mapping.elements[i].key, name)) != NULL ||
                (n = yoml_find_anchor(node->data.mapping.elements[i].value, name)) != NULL)
                return n;
        break;
    default:
        break;
    }

    return NULL;
}

static inline yoml_t *yoml_get(yoml_t *node, const char *name)
{
    size_t i;

    if (node->type != YOML_TYPE_MAPPING)
        return NULL;
    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        if (key->type == YOML_TYPE_SCALAR && strcmp(key->data.scalar, name) == 0)
            return node->data.mapping.elements[i].value;
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif

#endif
