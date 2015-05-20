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
#include <stdio.h>
#include "yoml.h"
#include "yoml-parser.h"

#include "picotest.h"

static yoml_t *parse(const char *fn, const char *s)
{
    yaml_parser_t parser;
    yoml_t *doc;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, (yaml_char_t*)s, strlen(s));
    doc = yoml_parse_document(&parser, NULL, fn);
    yaml_parser_delete(&parser);

    return doc;
}

int main(int argc, char **argv)
{
    yoml_t *doc, *t;

    doc = parse("foo.yaml", "abc");
    ok(doc != NULL);
    ok(strcmp(doc->filename, "foo.yaml") == 0);
    ok(doc->type == YOML_TYPE_SCALAR);
    ok(strcmp(doc->data.scalar, "abc") == 0);
    yoml_free(doc);

    doc = parse(
       "foo.yaml",
        "---\n"
        "a: b\n"
        "c: d\n"
        "---\n"
        "e: f\n");
    ok(doc != NULL);
    ok(strcmp(doc->filename, "foo.yaml") == 0);
    ok(doc->type == YOML_TYPE_MAPPING);
    ok(doc->data.mapping.size == 2);
    t = doc->data.mapping.elements[0].key;
    ok(strcmp(t->filename, "foo.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "a") == 0);
    t = doc->data.mapping.elements[0].value;
    ok(strcmp(t->filename, "foo.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "b") == 0);
    t = doc->data.mapping.elements[1].key;
    ok(strcmp(t->filename, "foo.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "c") == 0);
    t = doc->data.mapping.elements[1].value;
    ok(strcmp(t->filename, "foo.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "d") == 0);
    yoml_free(doc);

    doc = parse(
            "bar.yaml",
            "- a: b\n"
            "  c: d\n"
            "- e\n");
    ok(doc != NULL);
    ok(strcmp(doc->filename, "bar.yaml") == 0);
    ok(doc->type == YOML_TYPE_SEQUENCE);
    ok(doc->data.sequence.size == 2);
    t = doc->data.sequence.elements[0];
    ok(strcmp(doc->filename, "bar.yaml") == 0);
    ok(t->type == YOML_TYPE_MAPPING);
    ok(t->data.mapping.size == 2);
    t = doc->data.sequence.elements[0]->data.mapping.elements[0].key;
    ok(strcmp(doc->filename, "bar.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "a") == 0);
    t = doc->data.sequence.elements[0]->data.mapping.elements[0].value;
    ok(strcmp(doc->filename, "bar.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "b") == 0);
    t = doc->data.sequence.elements[0]->data.mapping.elements[1].key;
    ok(strcmp(doc->filename, "bar.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "c") == 0);
    t = doc->data.sequence.elements[0]->data.mapping.elements[1].value;
    ok(strcmp(doc->filename, "bar.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "d") == 0);
    t = doc->data.sequence.elements[1];
    ok(strcmp(doc->filename, "bar.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "e") == 0);
    yoml_free(doc);

    doc = parse(
        "baz.yaml",
        "- &abc\n"
        "  - 1\n"
        "  - 2\n"
        "- *abc\n");
    ok(doc != NULL);
    ok(strcmp(doc->filename, "baz.yaml") == 0);
    ok(doc->type == YOML_TYPE_SEQUENCE);
    ok(doc->data.sequence.size == 2);
    ok(doc->data.sequence.elements[0] == doc->data.sequence.elements[1]);
    t = doc->data.sequence.elements[0];
    ok(strcmp(t->filename, "baz.yaml") == 0);
    ok(t->_refcnt == 2);
    ok(t->type == YOML_TYPE_SEQUENCE);
    ok(t->data.sequence.size == 2);
    t = doc->data.sequence.elements[0]->data.sequence.elements[0];
    ok(strcmp(t->filename, "baz.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "1") == 0);
    t = doc->data.sequence.elements[0]->data.sequence.elements[1];
    ok(strcmp(t->filename, "baz.yaml") == 0);
    ok(t->type == YOML_TYPE_SCALAR);
    ok(strcmp(t->data.scalar, "2") == 0);

    return done_testing();
}
