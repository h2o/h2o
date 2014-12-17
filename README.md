YOML - a DOM-like interface to YAML
====

YOML is a DOM-like interface to YAML, implemented as a wrapper around [libyaml](http://pyyaml.org/wiki/LibYAML).

It is a header-only library.  Just include the .h files to use the library.

```
#include "yoml.h" /* defines the structures */
#include "yoml-parser.h" /* defines the parser */

static yoml_t *parse_file(FILE *fp)
{
  yaml_parser_t parser;
  yoml_t *doc;

  yaml_parser_initialize(&parser);
  yaml_parser_set_input_file(&parser, fp);

  doc = yoml_parse_document(&parser, NULL);

  yaml_parser_delete(&parser);

  return doc;
}

static void dump_node(yoml_t *node, int indent)
{
  size_t i;

  switch (node->type) {
  case YOML_TYPE_SCALAR:
    printf("%*s[SCALAR] %s\n", indent, "", node->data.scalar);
    break;
  case YOML_TYPE_SEQUENCE:
    printf("%*s[SEQUENCE] (size:%zu)\n", indent, "", node->data.sequence.size);
    for (i = 0; i != node.data.sequence.size; ++i)
      dump_node(node->data.sequence.elements[i], indent + 2);
    break;
  case YOML_TYPE_MAPPING:
    printf("%*s[MAPPING] (size:%zu)\n", indent, "", node->data.mapping.size);
    indent += 2;
    for (i = 0; i != node.data.mapping.size; ++i) {
      printf(%*s[KEY]\n", indent, "");
      dump_node(node->data.mapping.elements[i].key, indent + 2);
      printf(%*s[VALUE]\n", indent, "");
      dump_node(node->data.mapping.elements[i].value, indent + 2);
    }
    indent -= 2;
    break;
  }
}

static void dump_file(FILE *fp)
{
  yoml_t *doc = parse_file(fp);

  if (doc == NULL) {
    fprintf(stderr, "parse error!\n"); /* error info can be obtained from yaml_parser_t */
    return;
  }

  dump_node(doc, 0);
  yoml_free(doc);
}
```
