#include <ctype.h>
#include <inttypes.h>
#include <string.h>

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/hash.h"
#include "mruby/string.h"

#define E_JSON_PARSER_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "JSON"), "ParserError"))

#define JSON_EOF -1

#define DEFAULT_MAX_NESTING 100

struct json_parser {
  mrb_state *mrb;
  mrb_value src;
  unsigned int cursor;
  unsigned int lineno;
  int nesting;

  int max_nesting;
};

static void json_check_nesting(struct json_parser *);
static int json_delimiter_p(char ch);
static int json_getc(struct json_parser *);
static void json_skip_ws(struct json_parser *);
static void json_ungetc(struct json_parser *);
static int json_unicode2utf8(uint32_t, char *);
static int json_whitespace_p(char ch);

static int json_parse_array(struct json_parser *, mrb_value *);
static int json_parse_object(struct json_parser *, mrb_value *);
static int json_parse_number2(struct json_parser *, int, mrb_value *, int, int);
static int json_parse_string(struct json_parser *, mrb_value *);
static int json_parse_value(struct json_parser *, mrb_value *);

#if MRUBY_RELEASE_NO < 10000
static struct RClass *
mrb_module_get(mrb_state *mrb, const char *name)
{
  return mrb_class_get(mrb, name);
}
#endif

static void
json_check_nesting(struct json_parser *parser)
{
  mrb_state *mrb = parser->mrb;

  if (parser->max_nesting != -1) {
    if (parser->nesting >= parser->max_nesting) {
      // +1 for compatibility with CRuby
      mrb_raisef(mrb, E_JSON_PARSER_ERROR, "nesting of %S is too deep", mrb_fixnum_value(parser->nesting+1));
    }
  }
}

static int
json_delimiter_p(char ch)
{
  return (json_whitespace_p(ch) || ch == ',' || ch == ']' || ch == '}');
}

static int
json_getc(struct json_parser *parser)
{
  if (parser->cursor < RSTRING_LEN(parser->src)) {
    unsigned char ch = RSTRING_PTR(parser->src)[parser->cursor];
    parser->cursor++;
    return ch;
  } else {
    return JSON_EOF;
  }
}

static int
json_parse_readstring(struct json_parser *parser, const char *str)
{
  size_t len;
  int ch;

  len = strlen(str);
  if (parser->cursor + len > RSTRING_LEN(parser->src))
    return 0;
  if (memcmp(str, RSTRING_PTR(parser->src) + parser->cursor, len) != 0)
    return -1;
  parser->cursor += len;
  if (parser->cursor == RSTRING_LEN(parser->src))
    return 1;
  ch = RSTRING_PTR(parser->src)[parser->cursor];
  if (!json_delimiter_p(ch))
    return -1;
  return 1;
}

static void
json_skip_ws(struct json_parser *parser)
{
  int ch;

  do {
    ch = json_getc(parser);
    if (ch == 0x0a)
      parser->lineno++;
  } while (json_whitespace_p(ch));
  if (ch != JSON_EOF) {
    json_ungetc(parser);
  }
}

static void
json_ungetc(struct json_parser *parser)
{
  if (parser->cursor > 0)
    parser->cursor--;
}

static int
json_unicode2utf8(uint32_t unicode, char *cp)
{
  int n = 0;
  if (unicode < 0x80) {
    cp[n++] = unicode;
  } else if (unicode < 0x800) {
    cp[n++] = 0xc0 + (unicode >> 6);
    cp[n++] = 0x80 + (unicode & 0x3f);
  } else if (unicode < 0x10000) {
    cp[n++] = 0xe0 + (unicode >> 12);
    cp[n++] = 0x80 + ((unicode >> 6) & 0x3f);
    cp[n++] = 0x80 + (unicode & 0x3f);
  } else {
    cp[n++] = 0xf0 + (unicode >> 18);
    cp[n++] = 0x80 + ((unicode >> 12) & 0x3f);
    cp[n++] = 0x80 + ((unicode >> 6) & 0x3f);
    cp[n++] = 0x80 + (unicode & 0x3f);
  }
  return n;
}

static int
json_whitespace_p(char ch)
{
  return (ch == 0x20 || ch == 0x09 || ch == 0x0a || ch == 0x0d);
}

static int
json_parse_array(struct json_parser *parser, mrb_value *result)
{
  mrb_state *mrb = parser->mrb;
  mrb_value ary, v;
  int ch;

  json_check_nesting(parser);

  ary = mrb_ary_new(mrb);

  json_skip_ws(parser);
  ch = json_getc(parser);
  if (ch == ']') { /* easy case */
    *result = ary;
    return 1;
  }
  if (ch == JSON_EOF) {
    mrb_raise(mrb, E_JSON_PARSER_ERROR, "JSON_EOF in array(1)");
  }
  json_ungetc(parser);

  while (1) {
    parser->nesting++;
    if (json_parse_value(parser, &v) != 1) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "error in array");
    }
    parser->nesting--;

    mrb_ary_push(mrb, ary, v);

    json_skip_ws(parser);
    ch = json_getc(parser);
    if (ch == ']') {
      break;
    }
    if (ch == JSON_EOF) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "JSON_EOF in array(2)");
    }
    if (ch != ',') {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "not ',' in array");
    }
  }
  *result = ary;
  return 1;
}

static int
json_parse_object(struct json_parser *parser, mrb_value *result)
{
  mrb_state *mrb = parser->mrb;
  mrb_value h, k, v;
  int ch;

  json_check_nesting(parser);

  h = mrb_hash_new(mrb);

  json_skip_ws(parser);
  ch = json_getc(parser);
  if (ch == '}') { /* easy case */
    *result = h;
    return 1;
  }
  if (ch == JSON_EOF) {
    mrb_raise(mrb, E_JSON_PARSER_ERROR, "EOF in object(1)");
  }
  json_ungetc(parser);

  while (1) {
    parser->nesting++;
    if (json_parse_value(parser, &k) != 1) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "error in object key");
    }
    parser->nesting--;
    if (! mrb_string_p(k)) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "key is not a string");
    }

    json_skip_ws(parser);

    ch = json_getc(parser);
    if (ch == JSON_EOF) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "EOF in object(2)");
    }
    if (ch != ':') {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "no ':' in object");
    }

    parser->nesting++;
    if (json_parse_value(parser, &v) != 1) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "error in object value");
    }
    parser->nesting--;

    mrb_hash_set(mrb, h, k, v);

    json_skip_ws(parser);
    ch = json_getc(parser);
    if (ch == '}') {
      break;
    }
    if (ch == JSON_EOF) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "EOF in object(3)");
    }
    if (ch != ',') {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "no ',' in object");
    }
  }
  *result = h;
  return 1;
}

static int
json_parse_number(struct json_parser *parser, int ch, mrb_value *result)
{
  mrb_state *mrb = parser->mrb;
  mrb_int num;
  int d, sign;

  if (ch == '-') {
    sign = -1;
    ch = json_getc(parser);
    if (ch == JSON_EOF) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "no character following minus");
    }
    if (!isdigit(ch)) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "character following minus is not a digit");
    }
  } else {
    sign = 1;
  }
  num = (ch - '0') * sign;
  while (1) {
    ch = json_getc(parser);
    if (ch == JSON_EOF) {
      break;
    }
    if (isdigit(ch)) {
      if (num == 0) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "leading zeros are not allowed");
      }
      d = (ch - '0') * sign;
      if (num < MRB_INT_MIN / 10 ||
          (num == MRB_INT_MIN / 10 && d < MRB_INT_MIN - num * 10) ||
          num > MRB_INT_MAX / 10 ||
          (num == MRB_INT_MAX / 10 && d > MRB_INT_MAX - num * 10)) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "integer overflow");
        return -1;
      }
      num = num * 10 + d;
    } else if (ch == '.' || ch == 'e' || ch == 'E') {
      return json_parse_number2(parser, ch, result, num, sign);
    } else if (json_delimiter_p(ch)) {
      json_ungetc(parser);
      break;
    } else {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "invalid number");
    }
  }
  *result = mrb_fixnum_value(num);
  return 1;
}

static int
json_parse_number2(struct json_parser *parser, int ch, mrb_value *result, int num, int sign)
{
  mrb_state *mrb = parser->mrb;
  double d;
  int i, state;
  char buf[64];

  /*
   * "-"? ("0" | [1-9] digit* ) ("." digit+ )? ([eE][-+] digit+)?
   * state:                      000 111111     22223333 444444
   */
  i = snprintf(buf, sizeof(buf), "%s%d%c",
      (num == 0 && sign < 0) ? "-" : "",
      num, ch);
  if (ch == '.')
    state = 0;
  else /* (ch == 'e' || ch == 'E') */
    state = 2;
  while (1) {
    ch = json_getc(parser);
    if (ch == JSON_EOF)
      break;
    switch (state) {
      case 0:
        if (!isdigit(ch))
          goto formaterr;
        state = 1;
        break;
      case 1:
        if (isdigit(ch))
          ; /* read more digits */
        else if (ch == 'e' || ch == 'E')
          state = 2;
        else if (json_delimiter_p(ch)) {
          json_ungetc(parser);
          state = -1;
        } else
          goto formaterr;
        break;
      case 2:
        if (ch == '-' || ch == '+')
          state = 3;
        else if (isdigit(ch))
          state = 4;
        else
          goto formaterr;
        break;
      case 3:
        if (!isdigit(ch))
          goto formaterr;
        state = 4;
        break;
      case 4:
      default:
        if (isdigit(ch))
          ; /* read more digits */
        else {
          json_ungetc(parser);
          state = -1;
        }
        break;
    }
    if (state == -1)
      break;
    if (i == sizeof(buf) - 1) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "floating point number too long");
    }
    buf[i++] = ch;
  }
  buf[i] = '\0';
  sscanf(buf, "%lf", &d);
  *result = mrb_float_value(mrb, d);
  return 1;

formaterr:
  mrb_raise(mrb, E_JSON_PARSER_ERROR, "floating point number error");
  return -1;
}

static int
json_parse_string(struct json_parser *parser, mrb_value *result)
{
  mrb_state *mrb = parser->mrb;
  mrb_value str;
  uint32_t unicode;
  uint16_t utf16;
  int ch, i, n;
  char *cp;

  str = mrb_str_buf_new(mrb, 30);
  cp = RSTRING_PTR(str);
  n = 0;
  unicode = 0;

  while (1) {
    ch = json_getc(parser);
    if (ch == JSON_EOF) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "EOF in string");
    }
    
    if (ch == '"') {
      break;
    } else if (ch == '\\') {
      ch = json_getc(parser);
      if (ch == JSON_EOF) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "EOF following escape char");
      }
      switch (ch) {
        case '"':
        case '\\':
        case '/':
          break;
        case 'b':
          ch = 0x08;
          break;
        case 'f':
          ch = 0x0c;
          break;
        case 'n':
          ch = 0x0a;
          break;
        case 'r':
          ch = 0x0d;
          break;
        case 't':
          ch = 0x09;
          break;
        case 'u':
          utf16 = 0;
          for (i = 0; i < 4; i++) {
            ch = json_getc(parser);
            if (ch == JSON_EOF) {
              mrb_raise(mrb, E_JSON_PARSER_ERROR, "invalid unicode escape");
            }
            if (ch >= '0' && ch <= '9') {
              ch -= '0';
            } else if (ch >= 'A' && ch <= 'F') {
              ch = (ch - 'A') + 10;
            } else if (ch >= 'a' && ch <= 'f') {
              ch = (ch - 'a') + 10;
            } else {
              mrb_raise(mrb, E_JSON_PARSER_ERROR, "invalid unicode character");
            }
            utf16 *= 16;
            utf16 += ch;
          }

          if (n + 8 >= RSTRING_CAPA(str)) {
            mrb_str_resize(mrb, str, RSTRING_CAPA(str)*2);
            cp = RSTRING_PTR(str);
          }

          if ((utf16 & 0xf800) == 0xd800) {
            if ((utf16 & 0xfc00) == 0xd800) {
              /* high surrogate */
              unicode = utf16;
              continue;
            } else {
              /* low surrogate */
              if (unicode > 0) {
                unicode = ((unicode & 0x03ff) + 0x040) << 10;
                unicode += utf16 & 0x03ff;
              } else {
                /* error: low surrogate comes first... */
              }
            }
          } else {
            if (unicode > 0) {
              /* error: high surrogate not followed by low surrogate */
              n += json_unicode2utf8(unicode, &cp[n]);
            }
            unicode = utf16;
          }

          n += json_unicode2utf8(unicode, &cp[n]);
          unicode = 0;
          continue;
        default:
          mrb_raise(mrb, E_JSON_PARSER_ERROR, "invalid escape char");
          break;
      }
    } else if (ch < 0x20) {
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "invalid char");
    }

    if (n + 1 == RSTRING_CAPA(str)) {
      mrb_str_resize(mrb, str, RSTRING_CAPA(str)*2);
      cp = RSTRING_PTR(str);
    }
    cp[n++] = ch;
  }
  cp[n] = '\0';
  mrb_str_resize(mrb, str, n);
  *result = str;
  return 1;
}

static int
json_parse_value(struct json_parser *parser, mrb_value *result)
{
  mrb_state *mrb = parser->mrb;
  int ch;

  do {
    ch = json_getc(parser);
    if (ch == JSON_EOF)
      return 0;
  } while (json_whitespace_p(ch));

  switch (ch) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case '-':
      if (json_parse_number(parser, ch, result) != 1) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "number...?");
      }
      break;

    case '"':
      if (json_parse_string(parser, result) != 1) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "string...?");
      }
      break;

    case '[':
      if (json_parse_array(parser, result) != 1) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "array...?");
      }
      break;

    case '{':
      if (json_parse_object(parser, result) != 1) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "object...?");
      }
      break;

    case 'f':
      if (json_parse_readstring(parser, "alse") != 1) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "unexpected f");
      }
      *result = mrb_false_value();
      break;

    case 'n':
      if (json_parse_readstring(parser, "ull") != 1) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "unexpected n");
      }
      *result = mrb_nil_value();
      break;

    case 't':
      if (json_parse_readstring(parser, "rue") != 1) {
        mrb_raise(mrb, E_JSON_PARSER_ERROR, "unexpected t");
      }
      *result = mrb_true_value();
      break;

    default:
      mrb_raise(mrb, E_JSON_PARSER_ERROR, "unexpected character");
  }

  return 1;
}

static mrb_value
mrb_json_parse(mrb_state *mrb, mrb_value mod)
{
  struct json_parser parser;
  mrb_value obj, options, source;

  mrb_get_args(mrb, "S|H", &source, &options);

  parser.mrb         = mrb;
  parser.src         = source;
  parser.cursor      = 0;
  parser.lineno      = 0;
  parser.nesting     = 0;
  parser.max_nesting = DEFAULT_MAX_NESTING;

  if (json_parse_value(&parser, &obj) == 0) {
    mrb_raise(mrb, E_JSON_PARSER_ERROR, "no JSON value");
  }

  // if we have extra characters:
  // unexpected token at '3' (JSON::ParserError)

  return obj;
}

void
mrb_mruby_iijson_gem_init(mrb_state *mrb)
{
  struct RClass *m;

  m = mrb_define_module(mrb, "JSON");
  mrb_define_module_function(mrb, m, "parse", mrb_json_parse, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));
}

void
mrb_mruby_iijson_gem_final(mrb_state *mrb)
{
}
