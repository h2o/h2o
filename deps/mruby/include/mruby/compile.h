/*
** mruby/compile.h - mruby parser
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_COMPILE_H
#define MRUBY_COMPILE_H

#include "common.h"

/**
 * MRuby Compiler
 */
MRB_BEGIN_DECL

#include <mruby.h>

struct mrb_jmpbuf;

struct mrb_parser_state;
/* load context */
typedef struct mrbc_context {
  mrb_sym *syms;
  int slen;
  char *filename;
  short lineno;
  int (*partial_hook)(struct mrb_parser_state*);
  void *partial_data;
  struct RClass *target_class;
  mrb_bool capture_errors:1;
  mrb_bool dump_result:1;
  mrb_bool no_exec:1;
  mrb_bool keep_lv:1;
  mrb_bool no_optimize:1;

  size_t parser_nerr;
} mrbc_context;

MRB_API mrbc_context* mrbc_context_new(mrb_state *mrb);
MRB_API void mrbc_context_free(mrb_state *mrb, mrbc_context *cxt);
MRB_API const char *mrbc_filename(mrb_state *mrb, mrbc_context *c, const char *s);
MRB_API void mrbc_partial_hook(mrb_state *mrb, mrbc_context *c, int (*partial_hook)(struct mrb_parser_state*), void*data);

/* AST node structure */
typedef struct mrb_ast_node {
  struct mrb_ast_node *car, *cdr;
  uint16_t lineno, filename_index;
} mrb_ast_node;

/* lexer states */
enum mrb_lex_state_enum {
  EXPR_BEG,                   /* ignore newline, +/- is a sign. */
  EXPR_END,                   /* newline significant, +/- is an operator. */
  EXPR_ENDARG,                /* ditto, and unbound braces. */
  EXPR_ENDFN,                 /* ditto, and unbound braces. */
  EXPR_ARG,                   /* newline significant, +/- is an operator. */
  EXPR_CMDARG,                /* newline significant, +/- is an operator. */
  EXPR_MID,                   /* newline significant, +/- is an operator. */
  EXPR_FNAME,                 /* ignore newline, no reserved words. */
  EXPR_DOT,                   /* right after '.' or '::', no reserved words. */
  EXPR_CLASS,                 /* immediate after 'class', no here document. */
  EXPR_VALUE,                 /* alike EXPR_BEG but label is disallowed. */
  EXPR_MAX_STATE
};

/* saved error message */
struct mrb_parser_message {
  int lineno;
  int column;
  char* message;
};

#define STR_FUNC_PARSING 0x01
#define STR_FUNC_EXPAND  0x02
#define STR_FUNC_REGEXP  0x04
#define STR_FUNC_WORD    0x08
#define STR_FUNC_SYMBOL  0x10
#define STR_FUNC_ARRAY   0x20
#define STR_FUNC_HEREDOC 0x40
#define STR_FUNC_XQUOTE  0x80

enum mrb_string_type {
  str_not_parsing  = (0),
  str_squote   = (STR_FUNC_PARSING),
  str_dquote   = (STR_FUNC_PARSING|STR_FUNC_EXPAND),
  str_regexp   = (STR_FUNC_PARSING|STR_FUNC_REGEXP|STR_FUNC_EXPAND),
  str_sword    = (STR_FUNC_PARSING|STR_FUNC_WORD|STR_FUNC_ARRAY),
  str_dword    = (STR_FUNC_PARSING|STR_FUNC_WORD|STR_FUNC_ARRAY|STR_FUNC_EXPAND),
  str_ssym     = (STR_FUNC_PARSING|STR_FUNC_SYMBOL),
  str_ssymbols = (STR_FUNC_PARSING|STR_FUNC_SYMBOL|STR_FUNC_ARRAY),
  str_dsymbols = (STR_FUNC_PARSING|STR_FUNC_SYMBOL|STR_FUNC_ARRAY|STR_FUNC_EXPAND),
  str_heredoc  = (STR_FUNC_PARSING|STR_FUNC_HEREDOC),
  str_xquote   = (STR_FUNC_PARSING|STR_FUNC_XQUOTE|STR_FUNC_EXPAND),
};

/* heredoc structure */
struct mrb_parser_heredoc_info {
  mrb_bool allow_indent:1;
  mrb_bool line_head:1;
  enum mrb_string_type type;
  const char *term;
  int term_len;
  mrb_ast_node *doc;
};

#define MRB_PARSER_TOKBUF_MAX 65536
#define MRB_PARSER_TOKBUF_SIZE 256

/* parser structure */
struct mrb_parser_state {
  mrb_state *mrb;
  struct mrb_pool *pool;
  mrb_ast_node *cells;
  const char *s, *send;
#ifndef MRB_DISABLE_STDIO
  FILE *f;
#endif
  mrbc_context *cxt;
  char const *filename;
  int lineno;
  int column;

  enum mrb_lex_state_enum lstate;
  mrb_ast_node *lex_strterm; /* (type nest_level beg . end) */

  unsigned int cond_stack;
  unsigned int cmdarg_stack;
  int paren_nest;
  int lpar_beg;
  int in_def, in_single;
  mrb_bool cmd_start:1;
  mrb_ast_node *locals;

  mrb_ast_node *pb;
  char *tokbuf;
  char buf[MRB_PARSER_TOKBUF_SIZE];
  int tidx;
  int tsiz;

  mrb_ast_node *all_heredocs; /* list of mrb_parser_heredoc_info* */
  mrb_ast_node *heredocs_from_nextline;
  mrb_ast_node *parsing_heredoc;
  mrb_ast_node *lex_strterm_before_heredoc;
  mrb_bool heredoc_end_now:1; /* for mirb */

  void *ylval;

  size_t nerr;
  size_t nwarn;
  mrb_ast_node *tree;

  mrb_bool no_optimize:1;
  mrb_bool capture_errors:1;
  struct mrb_parser_message error_buffer[10];
  struct mrb_parser_message warn_buffer[10];

  mrb_sym* filename_table;
  size_t filename_table_length;
  int current_filename_index;

  struct mrb_jmpbuf* jmp;
};

MRB_API struct mrb_parser_state* mrb_parser_new(mrb_state*);
MRB_API void mrb_parser_free(struct mrb_parser_state*);
MRB_API void mrb_parser_parse(struct mrb_parser_state*,mrbc_context*);
MRB_API double mrb_float_read(const char*, char**);

MRB_API void mrb_parser_set_filename(struct mrb_parser_state*, char const*);
MRB_API char const* mrb_parser_get_filename(struct mrb_parser_state*, uint16_t idx);

/* utility functions */
#ifndef MRB_DISABLE_STDIO
MRB_API struct mrb_parser_state* mrb_parse_file(mrb_state*,FILE*,mrbc_context*);
#endif
MRB_API struct mrb_parser_state* mrb_parse_string(mrb_state*,const char*,mrbc_context*);
MRB_API struct mrb_parser_state* mrb_parse_nstring(mrb_state*,const char*,size_t,mrbc_context*);
MRB_API struct RProc* mrb_generate_code(mrb_state*, struct mrb_parser_state*);
MRB_API mrb_value mrb_load_exec(mrb_state *mrb, struct mrb_parser_state *p, mrbc_context *c);

/* program load functions */
#ifndef MRB_DISABLE_STDIO
MRB_API mrb_value mrb_load_file(mrb_state*,FILE*);
MRB_API mrb_value mrb_load_file_cxt(mrb_state*,FILE*, mrbc_context *cxt);
#endif
MRB_API mrb_value mrb_load_string(mrb_state *mrb, const char *s);
MRB_API mrb_value mrb_load_nstring(mrb_state *mrb, const char *s, size_t len);
MRB_API mrb_value mrb_load_string_cxt(mrb_state *mrb, const char *s, mrbc_context *cxt);
MRB_API mrb_value mrb_load_nstring_cxt(mrb_state *mrb, const char *s, size_t len, mrbc_context *cxt);

/** @} */
MRB_END_DECL

#endif /* MRUBY_COMPILE_H */
