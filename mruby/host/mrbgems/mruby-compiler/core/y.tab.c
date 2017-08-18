/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     keyword_class = 258,
     keyword_module = 259,
     keyword_def = 260,
     keyword_begin = 261,
     keyword_if = 262,
     keyword_unless = 263,
     keyword_while = 264,
     keyword_until = 265,
     keyword_for = 266,
     keyword_undef = 267,
     keyword_rescue = 268,
     keyword_ensure = 269,
     keyword_end = 270,
     keyword_then = 271,
     keyword_elsif = 272,
     keyword_else = 273,
     keyword_case = 274,
     keyword_when = 275,
     keyword_break = 276,
     keyword_next = 277,
     keyword_redo = 278,
     keyword_retry = 279,
     keyword_in = 280,
     keyword_do = 281,
     keyword_do_cond = 282,
     keyword_do_block = 283,
     keyword_do_LAMBDA = 284,
     keyword_return = 285,
     keyword_yield = 286,
     keyword_super = 287,
     keyword_self = 288,
     keyword_nil = 289,
     keyword_true = 290,
     keyword_false = 291,
     keyword_and = 292,
     keyword_or = 293,
     keyword_not = 294,
     modifier_if = 295,
     modifier_unless = 296,
     modifier_while = 297,
     modifier_until = 298,
     modifier_rescue = 299,
     keyword_alias = 300,
     keyword_BEGIN = 301,
     keyword_END = 302,
     keyword__LINE__ = 303,
     keyword__FILE__ = 304,
     keyword__ENCODING__ = 305,
     tIDENTIFIER = 306,
     tFID = 307,
     tGVAR = 308,
     tIVAR = 309,
     tCONSTANT = 310,
     tCVAR = 311,
     tLABEL = 312,
     tINTEGER = 313,
     tFLOAT = 314,
     tCHAR = 315,
     tXSTRING = 316,
     tREGEXP = 317,
     tSTRING = 318,
     tSTRING_PART = 319,
     tSTRING_MID = 320,
     tLABEL_END = 321,
     tNTH_REF = 322,
     tBACK_REF = 323,
     tREGEXP_END = 324,
     tUPLUS = 325,
     tUMINUS = 326,
     tPOW = 327,
     tCMP = 328,
     tEQ = 329,
     tEQQ = 330,
     tNEQ = 331,
     tGEQ = 332,
     tLEQ = 333,
     tANDOP = 334,
     tOROP = 335,
     tMATCH = 336,
     tNMATCH = 337,
     tDOT2 = 338,
     tDOT3 = 339,
     tAREF = 340,
     tASET = 341,
     tLSHFT = 342,
     tRSHFT = 343,
     tCOLON2 = 344,
     tCOLON3 = 345,
     tOP_ASGN = 346,
     tASSOC = 347,
     tLPAREN = 348,
     tLPAREN_ARG = 349,
     tRPAREN = 350,
     tLBRACK = 351,
     tLBRACE = 352,
     tLBRACE_ARG = 353,
     tSTAR = 354,
     tAMPER = 355,
     tLAMBDA = 356,
     tANDDOT = 357,
     tSYMBEG = 358,
     tREGEXP_BEG = 359,
     tWORDS_BEG = 360,
     tSYMBOLS_BEG = 361,
     tSTRING_BEG = 362,
     tXSTRING_BEG = 363,
     tSTRING_DVAR = 364,
     tLAMBEG = 365,
     tHEREDOC_BEG = 366,
     tHEREDOC_END = 367,
     tLITERAL_DELIM = 368,
     tHD_LITERAL_DELIM = 369,
     tHD_STRING_PART = 370,
     tHD_STRING_MID = 371,
     tLOWEST = 372,
     tUMINUS_NUM = 373,
     tLAST_TOKEN = 374
   };
#endif
/* Tokens.  */
#define keyword_class 258
#define keyword_module 259
#define keyword_def 260
#define keyword_begin 261
#define keyword_if 262
#define keyword_unless 263
#define keyword_while 264
#define keyword_until 265
#define keyword_for 266
#define keyword_undef 267
#define keyword_rescue 268
#define keyword_ensure 269
#define keyword_end 270
#define keyword_then 271
#define keyword_elsif 272
#define keyword_else 273
#define keyword_case 274
#define keyword_when 275
#define keyword_break 276
#define keyword_next 277
#define keyword_redo 278
#define keyword_retry 279
#define keyword_in 280
#define keyword_do 281
#define keyword_do_cond 282
#define keyword_do_block 283
#define keyword_do_LAMBDA 284
#define keyword_return 285
#define keyword_yield 286
#define keyword_super 287
#define keyword_self 288
#define keyword_nil 289
#define keyword_true 290
#define keyword_false 291
#define keyword_and 292
#define keyword_or 293
#define keyword_not 294
#define modifier_if 295
#define modifier_unless 296
#define modifier_while 297
#define modifier_until 298
#define modifier_rescue 299
#define keyword_alias 300
#define keyword_BEGIN 301
#define keyword_END 302
#define keyword__LINE__ 303
#define keyword__FILE__ 304
#define keyword__ENCODING__ 305
#define tIDENTIFIER 306
#define tFID 307
#define tGVAR 308
#define tIVAR 309
#define tCONSTANT 310
#define tCVAR 311
#define tLABEL 312
#define tINTEGER 313
#define tFLOAT 314
#define tCHAR 315
#define tXSTRING 316
#define tREGEXP 317
#define tSTRING 318
#define tSTRING_PART 319
#define tSTRING_MID 320
#define tLABEL_END 321
#define tNTH_REF 322
#define tBACK_REF 323
#define tREGEXP_END 324
#define tUPLUS 325
#define tUMINUS 326
#define tPOW 327
#define tCMP 328
#define tEQ 329
#define tEQQ 330
#define tNEQ 331
#define tGEQ 332
#define tLEQ 333
#define tANDOP 334
#define tOROP 335
#define tMATCH 336
#define tNMATCH 337
#define tDOT2 338
#define tDOT3 339
#define tAREF 340
#define tASET 341
#define tLSHFT 342
#define tRSHFT 343
#define tCOLON2 344
#define tCOLON3 345
#define tOP_ASGN 346
#define tASSOC 347
#define tLPAREN 348
#define tLPAREN_ARG 349
#define tRPAREN 350
#define tLBRACK 351
#define tLBRACE 352
#define tLBRACE_ARG 353
#define tSTAR 354
#define tAMPER 355
#define tLAMBDA 356
#define tANDDOT 357
#define tSYMBEG 358
#define tREGEXP_BEG 359
#define tWORDS_BEG 360
#define tSYMBOLS_BEG 361
#define tSTRING_BEG 362
#define tXSTRING_BEG 363
#define tSTRING_DVAR 364
#define tLAMBEG 365
#define tHEREDOC_BEG 366
#define tHEREDOC_END 367
#define tLITERAL_DELIM 368
#define tHD_LITERAL_DELIM 369
#define tHD_STRING_PART 370
#define tHD_STRING_MID 371
#define tLOWEST 372
#define tUMINUS_NUM 373
#define tLAST_TOKEN 374




/* Copy the first part of user declarations.  */
#line 7 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"

#undef PARSER_DEBUG
#ifdef PARSER_DEBUG
# define YYDEBUG 1
#endif
#define YYERROR_VERBOSE 1
/*
 * Force yacc to use our memory management.  This is a little evil because
 * the macros assume that "parser_state *p" is in scope
 */
#define YYMALLOC(n)    mrb_malloc(p->mrb, (n))
#define YYFREE(o)      mrb_free(p->mrb, (o))
#define YYSTACK_USE_ALLOCA 0

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <mruby.h>
#include <mruby/compile.h>
#include <mruby/proc.h>
#include <mruby/error.h>
#include <mruby/throw.h>
#include "node.h"

#define YYLEX_PARAM p

typedef mrb_ast_node node;
typedef struct mrb_parser_state parser_state;
typedef struct mrb_parser_heredoc_info parser_heredoc_info;

static int yyparse(parser_state *p);
static int yylex(void *lval, parser_state *p);
static void yyerror(parser_state *p, const char *s);
static void yywarn(parser_state *p, const char *s);
static void yywarning(parser_state *p, const char *s);
static void backref_error(parser_state *p, node *n);
static void void_expr_error(parser_state *p, node *n);
static void tokadd(parser_state *p, int32_t c);

#define identchar(c) (ISALNUM(c) || (c) == '_' || !ISASCII(c))

typedef unsigned int stack_type;

#define BITSTACK_PUSH(stack, n) ((stack) = ((stack)<<1)|((n)&1))
#define BITSTACK_POP(stack)     ((stack) = (stack) >> 1)
#define BITSTACK_LEXPOP(stack)  ((stack) = ((stack) >> 1) | ((stack) & 1))
#define BITSTACK_SET_P(stack)   ((stack)&1)

#define COND_PUSH(n)    BITSTACK_PUSH(p->cond_stack, (n))
#define COND_POP()      BITSTACK_POP(p->cond_stack)
#define COND_LEXPOP()   BITSTACK_LEXPOP(p->cond_stack)
#define COND_P()        BITSTACK_SET_P(p->cond_stack)

#define CMDARG_PUSH(n)  BITSTACK_PUSH(p->cmdarg_stack, (n))
#define CMDARG_POP()    BITSTACK_POP(p->cmdarg_stack)
#define CMDARG_LEXPOP() BITSTACK_LEXPOP(p->cmdarg_stack)
#define CMDARG_P()      BITSTACK_SET_P(p->cmdarg_stack)

#define SET_LINENO(c,n) ((c)->lineno = (n))
#define NODE_LINENO(c,n) do {\
  if (n) {\
     (c)->filename_index = (n)->filename_index;\
     (c)->lineno = (n)->lineno;\
  }\
} while (0)

#define sym(x) ((mrb_sym)(intptr_t)(x))
#define nsym(x) ((node*)(intptr_t)(x))
#define nint(x) ((node*)(intptr_t)(x))
#define intn(x) ((int)(intptr_t)(x))

static inline mrb_sym
intern_cstr_gen(parser_state *p, const char *s)
{
  return mrb_intern_cstr(p->mrb, s);
}
#define intern_cstr(s) intern_cstr_gen(p,(s))

static inline mrb_sym
intern_gen(parser_state *p, const char *s, size_t len)
{
  return mrb_intern(p->mrb, s, len);
}
#define intern(s,len) intern_gen(p,(s),(len))

static inline mrb_sym
intern_gen_c(parser_state *p, const char c)
{
  return mrb_intern(p->mrb, &c, 1);
}
#define intern_c(c) intern_gen_c(p,(c))

static void
cons_free_gen(parser_state *p, node *cons)
{
  cons->cdr = p->cells;
  p->cells = cons;
}
#define cons_free(c) cons_free_gen(p, (c))

static void*
parser_palloc(parser_state *p, size_t size)
{
  void *m = mrb_pool_alloc(p->pool, size);

  if (!m) {
    MRB_THROW(p->jmp);
  }
  return m;
}

static node*
cons_gen(parser_state *p, node *car, node *cdr)
{
  node *c;

  if (p->cells) {
    c = p->cells;
    p->cells = p->cells->cdr;
  }
  else {
    c = (node *)parser_palloc(p, sizeof(mrb_ast_node));
  }

  c->car = car;
  c->cdr = cdr;
  c->lineno = p->lineno;
  c->filename_index = p->current_filename_index;
  return c;
}
#define cons(a,b) cons_gen(p,(a),(b))

static node*
list1_gen(parser_state *p, node *a)
{
  return cons(a, 0);
}
#define list1(a) list1_gen(p, (a))

static node*
list2_gen(parser_state *p, node *a, node *b)
{
  return cons(a, cons(b,0));
}
#define list2(a,b) list2_gen(p, (a),(b))

static node*
list3_gen(parser_state *p, node *a, node *b, node *c)
{
  return cons(a, cons(b, cons(c,0)));
}
#define list3(a,b,c) list3_gen(p, (a),(b),(c))

static node*
list4_gen(parser_state *p, node *a, node *b, node *c, node *d)
{
  return cons(a, cons(b, cons(c, cons(d, 0))));
}
#define list4(a,b,c,d) list4_gen(p, (a),(b),(c),(d))

static node*
list5_gen(parser_state *p, node *a, node *b, node *c, node *d, node *e)
{
  return cons(a, cons(b, cons(c, cons(d, cons(e, 0)))));
}
#define list5(a,b,c,d,e) list5_gen(p, (a),(b),(c),(d),(e))

static node*
list6_gen(parser_state *p, node *a, node *b, node *c, node *d, node *e, node *f)
{
  return cons(a, cons(b, cons(c, cons(d, cons(e, cons(f, 0))))));
}
#define list6(a,b,c,d,e,f) list6_gen(p, (a),(b),(c),(d),(e),(f))

static node*
append_gen(parser_state *p, node *a, node *b)
{
  node *c = a;

  if (!a) return b;
  while (c->cdr) {
    c = c->cdr;
  }
  if (b) {
    c->cdr = b;
  }
  return a;
}
#define append(a,b) append_gen(p,(a),(b))
#define push(a,b) append_gen(p,(a),list1(b))

static char*
parser_strndup(parser_state *p, const char *s, size_t len)
{
  char *b = (char *)parser_palloc(p, len+1);

  memcpy(b, s, len);
  b[len] = '\0';
  return b;
}
#undef strndup
#define strndup(s,len) parser_strndup(p, s, len)

static char*
parser_strdup(parser_state *p, const char *s)
{
  return parser_strndup(p, s, strlen(s));
}
#undef strdup
#define strdup(s) parser_strdup(p, s)

/* xxx ----------------------------- */

static node*
local_switch(parser_state *p)
{
  node *prev = p->locals;

  p->locals = cons(0, 0);
  return prev;
}

static void
local_resume(parser_state *p, node *prev)
{
  p->locals = prev;
}

static void
local_nest(parser_state *p)
{
  p->locals = cons(0, p->locals);
}

static void
local_unnest(parser_state *p)
{
  if (p->locals) {
    p->locals = p->locals->cdr;
  }
}

static mrb_bool
local_var_p(parser_state *p, mrb_sym sym)
{
  node *l = p->locals;

  while (l) {
    node *n = l->car;
    while (n) {
      if (sym(n->car) == sym) return TRUE;
      n = n->cdr;
    }
    l = l->cdr;
  }
  return FALSE;
}

static void
local_add_f(parser_state *p, mrb_sym sym)
{
  if (p->locals) {
    p->locals->car = push(p->locals->car, nsym(sym));
  }
}

static void
local_add(parser_state *p, mrb_sym sym)
{
  if (!local_var_p(p, sym)) {
    local_add_f(p, sym);
  }
}

static node*
locals_node(parser_state *p)
{
  return p->locals ? p->locals->car : NULL;
}

/* (:scope (vars..) (prog...)) */
static node*
new_scope(parser_state *p, node *body)
{
  return cons((node*)NODE_SCOPE, cons(locals_node(p), body));
}

/* (:begin prog...) */
static node*
new_begin(parser_state *p, node *body)
{
  if (body) {
    return list2((node*)NODE_BEGIN, body);
  }
  return cons((node*)NODE_BEGIN, 0);
}

#define newline_node(n) (n)

/* (:rescue body rescue else) */
static node*
new_rescue(parser_state *p, node *body, node *resq, node *els)
{
  return list4((node*)NODE_RESCUE, body, resq, els);
}

static node*
new_mod_rescue(parser_state *p, node *body, node *resq)
{
  return new_rescue(p, body, list1(list3(0, 0, resq)), 0);
}

/* (:ensure body ensure) */
static node*
new_ensure(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_ENSURE, cons(a, cons(0, b)));
}

/* (:nil) */
static node*
new_nil(parser_state *p)
{
  return list1((node*)NODE_NIL);
}

/* (:true) */
static node*
new_true(parser_state *p)
{
  return list1((node*)NODE_TRUE);
}

/* (:false) */
static node*
new_false(parser_state *p)
{
  return list1((node*)NODE_FALSE);
}

/* (:alias new old) */
static node*
new_alias(parser_state *p, mrb_sym a, mrb_sym b)
{
  return cons((node*)NODE_ALIAS, cons(nsym(a), nsym(b)));
}

/* (:if cond then else) */
static node*
new_if(parser_state *p, node *a, node *b, node *c)
{
  void_expr_error(p, a);
  return list4((node*)NODE_IF, a, b, c);
}

/* (:unless cond then else) */
static node*
new_unless(parser_state *p, node *a, node *b, node *c)
{
  void_expr_error(p, a);
  return list4((node*)NODE_IF, a, c, b);
}

/* (:while cond body) */
static node*
new_while(parser_state *p, node *a, node *b)
{
  void_expr_error(p, a);
  return cons((node*)NODE_WHILE, cons(a, b));
}

/* (:until cond body) */
static node*
new_until(parser_state *p, node *a, node *b)
{
  void_expr_error(p, a);
  return cons((node*)NODE_UNTIL, cons(a, b));
}

/* (:for var obj body) */
static node*
new_for(parser_state *p, node *v, node *o, node *b)
{
  void_expr_error(p, o);
  return list4((node*)NODE_FOR, v, o, b);
}

/* (:case a ((when ...) body) ((when...) body)) */
static node*
new_case(parser_state *p, node *a, node *b)
{
  node *n = list2((node*)NODE_CASE, a);
  node *n2 = n;

  void_expr_error(p, a);
  while (n2->cdr) {
    n2 = n2->cdr;
  }
  n2->cdr = b;
  return n;
}

/* (:postexe a) */
static node*
new_postexe(parser_state *p, node *a)
{
  return cons((node*)NODE_POSTEXE, a);
}

/* (:self) */
static node*
new_self(parser_state *p)
{
  return list1((node*)NODE_SELF);
}

/* (:call a b c) */
static node*
new_call(parser_state *p, node *a, mrb_sym b, node *c, int pass)
{
  node *n = list4(nint(pass?NODE_CALL:NODE_SCALL), a, nsym(b), c);
  void_expr_error(p, a);
  NODE_LINENO(n, a);
  return n;
}

/* (:fcall self mid args) */
static node*
new_fcall(parser_state *p, mrb_sym b, node *c)
{
  node *n = new_self(p);
  NODE_LINENO(n, c);
  n = list4((node*)NODE_FCALL, n, nsym(b), c);
  NODE_LINENO(n, c);
  return n;
}

/* (:super . c) */
static node*
new_super(parser_state *p, node *c)
{
  return cons((node*)NODE_SUPER, c);
}

/* (:zsuper) */
static node*
new_zsuper(parser_state *p)
{
  return list1((node*)NODE_ZSUPER);
}

/* (:yield . c) */
static node*
new_yield(parser_state *p, node *c)
{
  if (c) {
    if (c->cdr) {
      yyerror(p, "both block arg and actual block given");
    }
    return cons((node*)NODE_YIELD, c->car);
  }
  return cons((node*)NODE_YIELD, 0);
}

/* (:return . c) */
static node*
new_return(parser_state *p, node *c)
{
  return cons((node*)NODE_RETURN, c);
}

/* (:break . c) */
static node*
new_break(parser_state *p, node *c)
{
  return cons((node*)NODE_BREAK, c);
}

/* (:next . c) */
static node*
new_next(parser_state *p, node *c)
{
  return cons((node*)NODE_NEXT, c);
}

/* (:redo) */
static node*
new_redo(parser_state *p)
{
  return list1((node*)NODE_REDO);
}

/* (:retry) */
static node*
new_retry(parser_state *p)
{
  return list1((node*)NODE_RETRY);
}

/* (:dot2 a b) */
static node*
new_dot2(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_DOT2, cons(a, b));
}

/* (:dot3 a b) */
static node*
new_dot3(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_DOT3, cons(a, b));
}

/* (:colon2 b c) */
static node*
new_colon2(parser_state *p, node *b, mrb_sym c)
{
  void_expr_error(p, b);
  return cons((node*)NODE_COLON2, cons(b, nsym(c)));
}

/* (:colon3 . c) */
static node*
new_colon3(parser_state *p, mrb_sym c)
{
  return cons((node*)NODE_COLON3, nsym(c));
}

/* (:and a b) */
static node*
new_and(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_AND, cons(a, b));
}

/* (:or a b) */
static node*
new_or(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_OR, cons(a, b));
}

/* (:array a...) */
static node*
new_array(parser_state *p, node *a)
{
  return cons((node*)NODE_ARRAY, a);
}

/* (:splat . a) */
static node*
new_splat(parser_state *p, node *a)
{
  return cons((node*)NODE_SPLAT, a);
}

/* (:hash (k . v) (k . v)...) */
static node*
new_hash(parser_state *p, node *a)
{
  return cons((node*)NODE_HASH, a);
}

/* (:sym . a) */
static node*
new_sym(parser_state *p, mrb_sym sym)
{
  return cons((node*)NODE_SYM, nsym(sym));
}

static mrb_sym
new_strsym(parser_state *p, node* str)
{
  const char *s = (const char*)str->cdr->car;
  size_t len = (size_t)str->cdr->cdr;

  return mrb_intern(p->mrb, s, len);
}

/* (:lvar . a) */
static node*
new_lvar(parser_state *p, mrb_sym sym)
{
  return cons((node*)NODE_LVAR, nsym(sym));
}

/* (:gvar . a) */
static node*
new_gvar(parser_state *p, mrb_sym sym)
{
  return cons((node*)NODE_GVAR, nsym(sym));
}

/* (:ivar . a) */
static node*
new_ivar(parser_state *p, mrb_sym sym)
{
  return cons((node*)NODE_IVAR, nsym(sym));
}

/* (:cvar . a) */
static node*
new_cvar(parser_state *p, mrb_sym sym)
{
  return cons((node*)NODE_CVAR, nsym(sym));
}

/* (:const . a) */
static node*
new_const(parser_state *p, mrb_sym sym)
{
  return cons((node*)NODE_CONST, nsym(sym));
}

/* (:undef a...) */
static node*
new_undef(parser_state *p, mrb_sym sym)
{
  return list2((node*)NODE_UNDEF, nsym(sym));
}

/* (:class class super body) */
static node*
new_class(parser_state *p, node *c, node *s, node *b)
{
  void_expr_error(p, s);
  return list4((node*)NODE_CLASS, c, s, cons(locals_node(p), b));
}

/* (:sclass obj body) */
static node*
new_sclass(parser_state *p, node *o, node *b)
{
  void_expr_error(p, o);
  return list3((node*)NODE_SCLASS, o, cons(locals_node(p), b));
}

/* (:module module body) */
static node*
new_module(parser_state *p, node *m, node *b)
{
  return list3((node*)NODE_MODULE, m, cons(locals_node(p), b));
}

/* (:def m lv (arg . body)) */
static node*
new_def(parser_state *p, mrb_sym m, node *a, node *b)
{
  return list5((node*)NODE_DEF, nsym(m), locals_node(p), a, b);
}

/* (:sdef obj m lv (arg . body)) */
static node*
new_sdef(parser_state *p, node *o, mrb_sym m, node *a, node *b)
{
  void_expr_error(p, o);
  return list6((node*)NODE_SDEF, o, nsym(m), locals_node(p), a, b);
}

/* (:arg . sym) */
static node*
new_arg(parser_state *p, mrb_sym sym)
{
  return cons((node*)NODE_ARG, nsym(sym));
}

/* (m o r m2 b) */
/* m: (a b c) */
/* o: ((a . e1) (b . e2)) */
/* r: a */
/* m2: (a b c) */
/* b: a */
static node*
new_args(parser_state *p, node *m, node *opt, mrb_sym rest, node *m2, mrb_sym blk)
{
  node *n;

  n = cons(m2, nsym(blk));
  n = cons(nsym(rest), n);
  n = cons(opt, n);
  return cons(m, n);
}

/* (:block_arg . a) */
static node*
new_block_arg(parser_state *p, node *a)
{
  return cons((node*)NODE_BLOCK_ARG, a);
}

/* (:block arg body) */
static node*
new_block(parser_state *p, node *a, node *b)
{
  return list4((node*)NODE_BLOCK, locals_node(p), a, b);
}

/* (:lambda arg body) */
static node*
new_lambda(parser_state *p, node *a, node *b)
{
  return list4((node*)NODE_LAMBDA, locals_node(p), a, b);
}

/* (:asgn lhs rhs) */
static node*
new_asgn(parser_state *p, node *a, node *b)
{
  void_expr_error(p, b);
  return cons((node*)NODE_ASGN, cons(a, b));
}

/* (:masgn mlhs=(pre rest post)  mrhs) */
static node*
new_masgn(parser_state *p, node *a, node *b)
{
  void_expr_error(p, b);
  return cons((node*)NODE_MASGN, cons(a, b));
}

/* (:asgn lhs rhs) */
static node*
new_op_asgn(parser_state *p, node *a, mrb_sym op, node *b)
{
  void_expr_error(p, b);
  return list4((node*)NODE_OP_ASGN, a, nsym(op), b);
}

/* (:int . i) */
static node*
new_int(parser_state *p, const char *s, int base)
{
  return list3((node*)NODE_INT, (node*)strdup(s), nint(base));
}

/* (:float . i) */
static node*
new_float(parser_state *p, const char *s)
{
  return cons((node*)NODE_FLOAT, (node*)strdup(s));
}

/* (:str . (s . len)) */
static node*
new_str(parser_state *p, const char *s, int len)
{
  return cons((node*)NODE_STR, cons((node*)strndup(s, len), nint(len)));
}

/* (:dstr . a) */
static node*
new_dstr(parser_state *p, node *a)
{
  return cons((node*)NODE_DSTR, a);
}

/* (:str . (s . len)) */
static node*
new_xstr(parser_state *p, const char *s, int len)
{
  return cons((node*)NODE_XSTR, cons((node*)strndup(s, len), nint(len)));
}

/* (:xstr . a) */
static node*
new_dxstr(parser_state *p, node *a)
{
  return cons((node*)NODE_DXSTR, a);
}

/* (:dsym . a) */
static node*
new_dsym(parser_state *p, node *a)
{
  return cons((node*)NODE_DSYM, new_dstr(p, a));
}

/* (:regx . (s . (opt . enc))) */
static node*
new_regx(parser_state *p, const char *p1, const char* p2, const char* p3)
{
  return cons((node*)NODE_REGX, cons((node*)p1, cons((node*)p2, (node*)p3)));
}

/* (:dregx . (a . b)) */
static node*
new_dregx(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_DREGX, cons(a, b));
}

/* (:backref . n) */
static node*
new_back_ref(parser_state *p, int n)
{
  return cons((node*)NODE_BACK_REF, nint(n));
}

/* (:nthref . n) */
static node*
new_nth_ref(parser_state *p, int n)
{
  return cons((node*)NODE_NTH_REF, nint(n));
}

/* (:heredoc . a) */
static node*
new_heredoc(parser_state *p)
{
  parser_heredoc_info *inf = (parser_heredoc_info *)parser_palloc(p, sizeof(parser_heredoc_info));
  return cons((node*)NODE_HEREDOC, (node*)inf);
}

static void
new_bv(parser_state *p, mrb_sym id)
{
}

static node*
new_literal_delim(parser_state *p)
{
  return cons((node*)NODE_LITERAL_DELIM, 0);
}

/* (:words . a) */
static node*
new_words(parser_state *p, node *a)
{
  return cons((node*)NODE_WORDS, a);
}

/* (:symbols . a) */
static node*
new_symbols(parser_state *p, node *a)
{
  return cons((node*)NODE_SYMBOLS, a);
}

/* xxx ----------------------------- */

/* (:call a op) */
static node*
call_uni_op(parser_state *p, node *recv, const char *m)
{
  void_expr_error(p, recv);
  return new_call(p, recv, intern_cstr(m), 0, 1);
}

/* (:call a op b) */
static node*
call_bin_op(parser_state *p, node *recv, const char *m, node *arg1)
{
  return new_call(p, recv, intern_cstr(m), list1(list1(arg1)), 1);
}

static void
args_with_block(parser_state *p, node *a, node *b)
{
  if (b) {
    if (a->cdr) {
      yyerror(p, "both block arg and actual block given");
    }
    a->cdr = b;
  }
}

static void
call_with_block(parser_state *p, node *a, node *b)
{
  node *n;

  switch ((enum node_type)intn(a->car)) {
  case NODE_SUPER:
  case NODE_ZSUPER:
    if (!a->cdr) a->cdr = cons(0, b);
    else {
      args_with_block(p, a->cdr, b);
    }
    break;
  case NODE_CALL:
  case NODE_FCALL:
  case NODE_SCALL:
    n = a->cdr->cdr->cdr;
    if (!n->car) n->car = cons(0, b);
    else {
      args_with_block(p, n->car, b);
    }
    break;
  default:
    break;
  }
}

static node*
negate_lit(parser_state *p, node *n)
{
  return cons((node*)NODE_NEGATE, n);
}

static node*
cond(node *n)
{
  return n;
}

static node*
ret_args(parser_state *p, node *n)
{
  if (n->cdr) {
    yyerror(p, "block argument should not be given");
    return NULL;
  }
  if (!n->car->cdr) return n->car->car;
  return new_array(p, n->car);
}

static void
assignable(parser_state *p, node *lhs)
{
  if (intn(lhs->car) == NODE_LVAR) {
    local_add(p, sym(lhs->cdr));
  }
}

static node*
var_reference(parser_state *p, node *lhs)
{
  node *n;

  if (intn(lhs->car) == NODE_LVAR) {
    if (!local_var_p(p, sym(lhs->cdr))) {
      n = new_fcall(p, sym(lhs->cdr), 0);
      cons_free(lhs);
      return n;
    }
  }

  return lhs;
}

typedef enum mrb_string_type  string_type;

static node*
new_strterm(parser_state *p, string_type type, int term, int paren)
{
  return cons(nint(type), cons((node*)0, cons(nint(paren), nint(term))));
}

static void
end_strterm(parser_state *p)
{
  cons_free(p->lex_strterm->cdr->cdr);
  cons_free(p->lex_strterm->cdr);
  cons_free(p->lex_strterm);
  p->lex_strterm = NULL;
}

static parser_heredoc_info *
parsing_heredoc_inf(parser_state *p)
{
  node *nd = p->parsing_heredoc;
  if (nd == NULL)
    return NULL;
  /* mrb_assert(nd->car->car == NODE_HEREDOC); */
  return (parser_heredoc_info*)nd->car->cdr;
}

static void
heredoc_treat_nextline(parser_state *p)
{
  if (p->heredocs_from_nextline == NULL)
    return;
  if (p->parsing_heredoc == NULL) {
    node *n;
    p->parsing_heredoc = p->heredocs_from_nextline;
    p->lex_strterm_before_heredoc = p->lex_strterm;
    p->lex_strterm = new_strterm(p, parsing_heredoc_inf(p)->type, 0, 0);
    n = p->all_heredocs;
    if (n) {
      while (n->cdr)
        n = n->cdr;
      n->cdr = p->parsing_heredoc;
    }
    else {
      p->all_heredocs = p->parsing_heredoc;
    }
  }
  else {
    node *n, *m;
    m = p->heredocs_from_nextline;
    while (m->cdr)
      m = m->cdr;
    n = p->all_heredocs;
    mrb_assert(n != NULL);
    if (n == p->parsing_heredoc) {
      m->cdr = n;
      p->all_heredocs = p->heredocs_from_nextline;
      p->parsing_heredoc = p->heredocs_from_nextline;
    }
    else {
      while (n->cdr != p->parsing_heredoc) {
        n = n->cdr;
        mrb_assert(n != NULL);
      }
      m->cdr = n->cdr;
      n->cdr = p->heredocs_from_nextline;
      p->parsing_heredoc = p->heredocs_from_nextline;
    }
  }
  p->heredocs_from_nextline = NULL;
}

static void
heredoc_end(parser_state *p)
{
  p->parsing_heredoc = p->parsing_heredoc->cdr;
  if (p->parsing_heredoc == NULL) {
    p->lstate = EXPR_BEG;
    p->cmd_start = TRUE;
    end_strterm(p);
    p->lex_strterm = p->lex_strterm_before_heredoc;
    p->lex_strterm_before_heredoc = NULL;
    p->heredoc_end_now = TRUE;
  }
  else {
    /* next heredoc */
    p->lex_strterm->car = nint(parsing_heredoc_inf(p)->type);
  }
}
#define is_strterm_type(p,str_func) (intn((p)->lex_strterm->car) & (str_func))

/* xxx ----------------------------- */



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 1047 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
{
    node *nd;
    mrb_sym id;
    int num;
    stack_type stack;
    const struct vtable *vars;
}
/* Line 193 of yacc.c.  */
#line 1378 "/Users/travisgalloway/github/h2o/mruby/host/mrbgems/mruby-compiler/core/y.tab.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 1391 "/Users/travisgalloway/github/h2o/mruby/host/mrbgems/mruby-compiler/core/y.tab.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   11549

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  146
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  163
/* YYNRULES -- Number of rules.  */
#define YYNRULES  559
/* YYNRULES -- Number of states.  */
#define YYNSTATES  987

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   374

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     145,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   132,     2,     2,     2,   130,   125,     2,
     140,   141,   128,   126,   138,   127,   144,   129,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   120,   143,
     122,   118,   121,   119,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   137,     2,   142,   124,     2,   139,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   135,   123,   136,   133,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   131,   134
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    10,    12,    14,    18,    21,
      23,    24,    30,    35,    38,    40,    42,    46,    49,    50,
      55,    58,    62,    66,    70,    74,    78,    83,    85,    89,
      93,    97,   101,   103,   107,   111,   118,   124,   130,   136,
     142,   146,   148,   152,   154,   156,   160,   164,   168,   171,
     173,   175,   177,   179,   181,   186,   187,   193,   196,   200,
     205,   211,   216,   222,   225,   228,   231,   234,   237,   239,
     243,   245,   249,   251,   254,   258,   264,   267,   272,   275,
     280,   282,   286,   288,   292,   295,   299,   301,   304,   306,
     311,   315,   319,   323,   327,   330,   332,   334,   339,   343,
     347,   351,   355,   358,   360,   362,   364,   367,   369,   373,
     375,   377,   379,   381,   383,   385,   387,   389,   390,   395,
     397,   399,   401,   403,   405,   407,   409,   411,   413,   415,
     417,   419,   421,   423,   425,   427,   429,   431,   433,   435,
     437,   439,   441,   443,   445,   447,   449,   451,   453,   455,
     457,   459,   461,   463,   465,   467,   469,   471,   473,   475,
     477,   479,   481,   483,   485,   487,   489,   491,   493,   495,
     497,   499,   501,   503,   505,   507,   509,   511,   513,   515,
     517,   519,   521,   523,   525,   527,   529,   531,   533,   537,
     541,   548,   554,   560,   566,   572,   577,   581,   585,   589,
     593,   597,   601,   605,   609,   613,   618,   623,   626,   629,
     633,   637,   641,   645,   649,   653,   657,   661,   665,   669,
     673,   677,   681,   684,   687,   691,   695,   699,   703,   710,
     712,   714,   717,   722,   725,   727,   731,   735,   737,   739,
     741,   743,   746,   751,   754,   756,   759,   762,   767,   769,
     770,   773,   776,   779,   781,   783,   786,   788,   791,   795,
     800,   804,   809,   812,   814,   816,   818,   820,   822,   824,
     826,   828,   829,   834,   835,   836,   842,   843,   847,   851,
     855,   858,   862,   866,   868,   871,   876,   880,   883,   885,
     888,   889,   890,   896,   903,   910,   911,   912,   920,   921,
     922,   930,   936,   941,   942,   943,   953,   954,   961,   962,
     963,   972,   973,   979,   980,   981,   989,   990,   991,  1001,
    1003,  1005,  1007,  1009,  1011,  1013,  1015,  1018,  1020,  1022,
    1024,  1030,  1032,  1035,  1037,  1039,  1041,  1045,  1047,  1051,
    1053,  1058,  1065,  1069,  1075,  1078,  1083,  1085,  1089,  1096,
    1105,  1110,  1117,  1122,  1125,  1132,  1135,  1140,  1147,  1150,
    1155,  1158,  1163,  1165,  1167,  1169,  1173,  1175,  1180,  1182,
    1187,  1189,  1193,  1195,  1197,  1202,  1204,  1208,  1212,  1213,
    1219,  1222,  1227,  1233,  1239,  1242,  1247,  1252,  1256,  1260,
    1264,  1267,  1269,  1274,  1275,  1281,  1282,  1288,  1294,  1296,
    1298,  1305,  1307,  1309,  1311,  1313,  1316,  1318,  1321,  1323,
    1325,  1327,  1329,  1331,  1333,  1335,  1338,  1342,  1344,  1347,
    1349,  1350,  1355,  1357,  1360,  1363,  1367,  1370,  1374,  1376,
    1378,  1381,  1383,  1386,  1388,  1391,  1393,  1394,  1399,  1402,
    1406,  1408,  1413,  1416,  1418,  1420,  1422,  1424,  1426,  1429,
    1432,  1436,  1438,  1440,  1443,  1446,  1448,  1450,  1452,  1454,
    1456,  1458,  1460,  1462,  1464,  1466,  1468,  1470,  1472,  1474,
    1476,  1477,  1478,  1483,  1487,  1490,  1497,  1506,  1511,  1518,
    1523,  1530,  1533,  1538,  1545,  1548,  1553,  1556,  1561,  1563,
    1564,  1566,  1568,  1570,  1572,  1574,  1576,  1578,  1582,  1584,
    1588,  1591,  1594,  1597,  1599,  1603,  1605,  1609,  1611,  1613,
    1616,  1618,  1620,  1622,  1625,  1628,  1630,  1632,  1633,  1638,
    1640,  1643,  1645,  1649,  1653,  1656,  1659,  1663,  1668,  1670,
    1672,  1674,  1676,  1678,  1680,  1682,  1684,  1686,  1688,  1690,
    1692,  1694,  1696,  1698,  1700,  1701,  1703,  1704,  1706,  1709,
    1712,  1713,  1715,  1717,  1719,  1721,  1723,  1725,  1727,  1730
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int16 yyrhs[] =
{
     147,     0,    -1,    -1,   148,   149,    -1,   150,   300,    -1,
     308,    -1,   151,    -1,   150,   307,   151,    -1,     1,   151,
      -1,   156,    -1,    -1,    46,   152,   135,   149,   136,    -1,
     154,   244,   222,   247,    -1,   155,   300,    -1,   308,    -1,
     156,    -1,   155,   307,   156,    -1,     1,   156,    -1,    -1,
      45,   178,   157,   178,    -1,    12,   179,    -1,   156,    40,
     161,    -1,   156,    41,   161,    -1,   156,    42,   161,    -1,
     156,    43,   161,    -1,   156,    44,   156,    -1,    47,   135,
     154,   136,    -1,   158,    -1,   167,   118,   162,    -1,   174,
     118,   196,    -1,   167,   118,   183,    -1,   167,   118,   196,
      -1,   160,    -1,   174,   118,   159,    -1,   268,    91,   159,
      -1,   218,   137,   188,   303,    91,   159,    -1,   218,   298,
      51,    91,   159,    -1,   218,   298,    55,    91,   159,    -1,
     218,    89,    55,    91,   162,    -1,   218,    89,    51,    91,
     159,    -1,   270,    91,   159,    -1,   162,    -1,   162,    44,
     156,    -1,   158,    -1,   162,    -1,   160,    37,   160,    -1,
     160,    38,   160,    -1,    39,   301,   160,    -1,   132,   162,
      -1,   183,    -1,   160,    -1,   166,    -1,   163,    -1,   237,
      -1,   237,   299,   295,   190,    -1,    -1,    98,   165,   228,
     154,   136,    -1,   294,   190,    -1,   294,   190,   164,    -1,
     218,   298,   295,   190,    -1,   218,   298,   295,   190,   164,
      -1,   218,    89,   295,   190,    -1,   218,    89,   295,   190,
     164,    -1,    32,   190,    -1,    31,   190,    -1,    30,   189,
      -1,    21,   189,    -1,    22,   189,    -1,   169,    -1,    93,
     168,   302,    -1,   169,    -1,    93,   168,   302,    -1,   171,
      -1,   171,   170,    -1,   171,    99,   173,    -1,   171,    99,
     173,   138,   172,    -1,   171,    99,    -1,   171,    99,   138,
     172,    -1,    99,   173,    -1,    99,   173,   138,   172,    -1,
      99,    -1,    99,   138,   172,    -1,   173,    -1,    93,   168,
     302,    -1,   170,   138,    -1,   171,   170,   138,    -1,   170,
      -1,   171,   170,    -1,   267,    -1,   218,   137,   188,   303,
      -1,   218,   298,    51,    -1,   218,    89,    51,    -1,   218,
     298,    55,    -1,   218,    89,    55,    -1,    90,    55,    -1,
     270,    -1,   267,    -1,   218,   137,   188,   303,    -1,   218,
     298,    51,    -1,   218,    89,    51,    -1,   218,   298,    55,
      -1,   218,    89,    55,    -1,    90,    55,    -1,   270,    -1,
      51,    -1,    55,    -1,    90,   175,    -1,   175,    -1,   218,
      89,   175,    -1,    51,    -1,    55,    -1,    52,    -1,   181,
      -1,   182,    -1,   177,    -1,   263,    -1,   178,    -1,    -1,
     179,   138,   180,   178,    -1,   123,    -1,   124,    -1,   125,
      -1,    73,    -1,    74,    -1,    75,    -1,    81,    -1,    82,
      -1,   121,    -1,    77,    -1,   122,    -1,    78,    -1,    76,
      -1,    87,    -1,    88,    -1,   126,    -1,   127,    -1,   128,
      -1,    99,    -1,   129,    -1,   130,    -1,    72,    -1,   132,
      -1,   133,    -1,    70,    -1,    71,    -1,    85,    -1,    86,
      -1,   139,    -1,    48,    -1,    49,    -1,    50,    -1,    46,
      -1,    47,    -1,    45,    -1,    37,    -1,     6,    -1,    21,
      -1,    19,    -1,     3,    -1,     5,    -1,    26,    -1,    18,
      -1,    17,    -1,    15,    -1,    14,    -1,    36,    -1,    11,
      -1,    25,    -1,     4,    -1,    22,    -1,    34,    -1,    39,
      -1,    38,    -1,    23,    -1,    13,    -1,    24,    -1,    30,
      -1,    33,    -1,    32,    -1,    16,    -1,    35,    -1,    12,
      -1,    20,    -1,    31,    -1,     7,    -1,     8,    -1,     9,
      -1,    10,    -1,   174,   118,   185,    -1,   268,    91,   185,
      -1,   218,   137,   188,   303,    91,   185,    -1,   218,   298,
      51,    91,   185,    -1,   218,   298,    55,    91,   185,    -1,
     218,    89,    51,    91,   185,    -1,   218,    89,    55,    91,
     185,    -1,    90,    55,    91,   185,    -1,   270,    91,   185,
      -1,   183,    83,   183,    -1,   183,    84,   183,    -1,   183,
     126,   183,    -1,   183,   127,   183,    -1,   183,   128,   183,
      -1,   183,   129,   183,    -1,   183,   130,   183,    -1,   183,
      72,   183,    -1,   131,    58,    72,   183,    -1,   131,    59,
      72,   183,    -1,    70,   183,    -1,    71,   183,    -1,   183,
     123,   183,    -1,   183,   124,   183,    -1,   183,   125,   183,
      -1,   183,    73,   183,    -1,   183,   121,   183,    -1,   183,
      77,   183,    -1,   183,   122,   183,    -1,   183,    78,   183,
      -1,   183,    74,   183,    -1,   183,    75,   183,    -1,   183,
      76,   183,    -1,   183,    81,   183,    -1,   183,    82,   183,
      -1,   132,   183,    -1,   133,   183,    -1,   183,    87,   183,
      -1,   183,    88,   183,    -1,   183,    79,   183,    -1,   183,
      80,   183,    -1,   183,   119,   183,   301,   120,   183,    -1,
     197,    -1,   308,    -1,   195,   304,    -1,   195,   194,   292,
     304,    -1,   292,   304,    -1,   183,    -1,   183,    44,   183,
      -1,   140,   188,   302,    -1,   308,    -1,   186,    -1,   308,
      -1,   189,    -1,   195,   138,    -1,   195,   194,   292,   138,
      -1,   292,   138,    -1,   166,    -1,   195,   193,    -1,   292,
     193,    -1,   195,   194,   292,   193,    -1,   192,    -1,    -1,
     191,   189,    -1,   100,   183,    -1,   194,   192,    -1,   308,
      -1,   138,    -1,   138,   256,    -1,   183,    -1,    99,   183,
      -1,   195,   194,   183,    -1,   195,   194,    99,   183,    -1,
     195,   194,   183,    -1,   195,   194,    99,   183,    -1,    99,
     183,    -1,   248,    -1,   249,    -1,   253,    -1,   254,    -1,
     255,    -1,   269,    -1,   270,    -1,    52,    -1,    -1,     6,
     198,   153,    15,    -1,    -1,    -1,    94,   199,   156,   200,
     302,    -1,    -1,    94,   201,   302,    -1,    93,   154,   141,
      -1,   218,    89,    55,    -1,    90,    55,    -1,    96,   184,
     142,    -1,    97,   291,   136,    -1,    30,    -1,    31,   187,
      -1,    39,   140,   160,   302,    -1,    39,   140,   302,    -1,
     294,   239,    -1,   238,    -1,   238,   239,    -1,    -1,    -1,
     101,   202,   233,   203,   234,    -1,     7,   161,   219,   154,
     221,    15,    -1,     8,   161,   219,   154,   222,    15,    -1,
      -1,    -1,     9,   204,   161,   220,   205,   154,    15,    -1,
      -1,    -1,    10,   206,   161,   220,   207,   154,    15,    -1,
      19,   161,   300,   242,    15,    -1,    19,   300,   242,    15,
      -1,    -1,    -1,    11,   223,    25,   208,   161,   220,   209,
     154,    15,    -1,    -1,     3,   176,   271,   210,   153,    15,
      -1,    -1,    -1,     3,    87,   160,   211,   305,   212,   153,
      15,    -1,    -1,     4,   176,   213,   153,    15,    -1,    -1,
      -1,     5,   177,   214,   215,   273,   153,    15,    -1,    -1,
      -1,     5,   289,   297,   216,   177,   217,   273,   153,    15,
      -1,    21,    -1,    22,    -1,    23,    -1,    24,    -1,   197,
      -1,   305,    -1,    16,    -1,   305,    16,    -1,   305,    -1,
      27,    -1,   222,    -1,    17,   161,   219,   154,   221,    -1,
     308,    -1,    18,   154,    -1,   174,    -1,   167,    -1,   276,
      -1,    93,   226,   302,    -1,   224,    -1,   225,   138,   224,
      -1,   225,    -1,   225,   138,    99,   276,    -1,   225,   138,
      99,   276,   138,   225,    -1,   225,   138,    99,    -1,   225,
     138,    99,   138,   225,    -1,    99,   276,    -1,    99,   276,
     138,   225,    -1,    99,    -1,    99,   138,   225,    -1,   278,
     138,   282,   138,   285,   288,    -1,   278,   138,   282,   138,
     285,   138,   278,   288,    -1,   278,   138,   282,   288,    -1,
     278,   138,   282,   138,   278,   288,    -1,   278,   138,   285,
     288,    -1,   278,   138,    -1,   278,   138,   285,   138,   278,
     288,    -1,   278,   288,    -1,   282,   138,   285,   288,    -1,
     282,   138,   285,   138,   278,   288,    -1,   282,   288,    -1,
     282,   138,   278,   288,    -1,   285,   288,    -1,   285,   138,
     278,   288,    -1,   287,    -1,   308,    -1,   229,    -1,   123,
     230,   123,    -1,    80,    -1,   123,   227,   230,   123,    -1,
     301,    -1,   301,   143,   231,   301,    -1,   232,    -1,   231,
     138,   232,    -1,    51,    -1,   275,    -1,   140,   274,   230,
     141,    -1,   274,    -1,   110,   154,   136,    -1,    29,   154,
      15,    -1,    -1,    28,   236,   228,   154,    15,    -1,   166,
     235,    -1,   237,   299,   295,   187,    -1,   237,   299,   295,
     187,   239,    -1,   237,   299,   295,   190,   235,    -1,   294,
     186,    -1,   218,   298,   295,   187,    -1,   218,    89,   295,
     186,    -1,   218,    89,   296,    -1,   218,   298,   186,    -1,
     218,    89,   186,    -1,    32,   186,    -1,    32,    -1,   218,
     137,   188,   303,    -1,    -1,   135,   240,   228,   154,   136,
      -1,    -1,    26,   241,   228,   154,    15,    -1,    20,   195,
     219,   154,   243,    -1,   222,    -1,   242,    -1,    13,   245,
     246,   219,   154,   244,    -1,   308,    -1,   183,    -1,   196,
      -1,   308,    -1,    92,   174,    -1,   308,    -1,    14,   154,
      -1,   308,    -1,   266,    -1,   262,    -1,   261,    -1,   265,
      -1,    60,    -1,    63,    -1,   107,    63,    -1,   107,   250,
      63,    -1,   251,    -1,   250,   251,    -1,    65,    -1,    -1,
      64,   252,   154,   136,    -1,   113,    -1,   114,   256,    -1,
     108,    61,    -1,   108,   250,    61,    -1,   104,    62,    -1,
     104,   250,    62,    -1,   111,    -1,   257,    -1,   256,   257,
      -1,   112,    -1,   258,   112,    -1,   259,    -1,   258,   259,
      -1,   116,    -1,    -1,   115,   260,   154,   136,    -1,   105,
      63,    -1,   105,   250,    63,    -1,   263,    -1,   103,   107,
     250,    63,    -1,   103,   264,    -1,   177,    -1,    54,    -1,
      53,    -1,    56,    -1,    63,    -1,   107,    63,    -1,   106,
      63,    -1,   106,   250,    63,    -1,    58,    -1,    59,    -1,
     131,    58,    -1,   131,    59,    -1,    51,    -1,    54,    -1,
      53,    -1,    56,    -1,    55,    -1,   267,    -1,   267,    -1,
      34,    -1,    33,    -1,    35,    -1,    36,    -1,    49,    -1,
      48,    -1,    67,    -1,    68,    -1,    -1,    -1,   122,   272,
     161,   305,    -1,   140,   274,   302,    -1,   274,   305,    -1,
     278,   138,   283,   138,   285,   288,    -1,   278,   138,   283,
     138,   285,   138,   278,   288,    -1,   278,   138,   283,   288,
      -1,   278,   138,   283,   138,   278,   288,    -1,   278,   138,
     285,   288,    -1,   278,   138,   285,   138,   278,   288,    -1,
     278,   288,    -1,   283,   138,   285,   288,    -1,   283,   138,
     285,   138,   278,   288,    -1,   283,   288,    -1,   283,   138,
     278,   288,    -1,   285,   288,    -1,   285,   138,   278,   288,
      -1,   287,    -1,    -1,    55,    -1,    54,    -1,    53,    -1,
      56,    -1,   275,    -1,    51,    -1,   276,    -1,    93,   226,
     302,    -1,   277,    -1,   278,   138,   277,    -1,    51,   118,
      -1,   279,   183,    -1,   279,   218,    -1,   281,    -1,   282,
     138,   281,    -1,   280,    -1,   283,   138,   280,    -1,   128,
      -1,    99,    -1,   284,    51,    -1,   284,    -1,   125,    -1,
     100,    -1,   286,    51,    -1,   138,   287,    -1,   308,    -1,
     269,    -1,    -1,   140,   290,   160,   302,    -1,   308,    -1,
     292,   304,    -1,   293,    -1,   292,   138,   293,    -1,   183,
      92,   183,    -1,    57,   183,    -1,    66,   183,    -1,   107,
      66,   183,    -1,   107,   250,    66,   183,    -1,    51,    -1,
      55,    -1,    52,    -1,    51,    -1,    55,    -1,    52,    -1,
     181,    -1,    51,    -1,    52,    -1,   181,    -1,   144,    -1,
      89,    -1,   144,    -1,   102,    -1,   298,    -1,    89,    -1,
      -1,   307,    -1,    -1,   306,    -1,   301,   141,    -1,   301,
     142,    -1,    -1,   306,    -1,   194,    -1,   143,    -1,   306,
      -1,   257,    -1,   145,    -1,   305,    -1,   307,   305,    -1,
      -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,  1199,  1199,  1199,  1210,  1216,  1220,  1225,  1229,  1235,
    1237,  1236,  1248,  1275,  1281,  1285,  1290,  1294,  1300,  1300,
    1304,  1308,  1312,  1316,  1320,  1324,  1328,  1333,  1334,  1338,
    1342,  1346,  1350,  1353,  1357,  1361,  1365,  1369,  1373,  1378,
    1382,  1389,  1390,  1394,  1398,  1399,  1403,  1407,  1411,  1415,
    1418,  1427,  1428,  1431,  1432,  1439,  1438,  1451,  1455,  1460,
    1464,  1469,  1473,  1478,  1482,  1486,  1490,  1494,  1500,  1504,
    1510,  1511,  1517,  1521,  1525,  1529,  1533,  1537,  1541,  1545,
    1549,  1553,  1559,  1560,  1566,  1570,  1576,  1580,  1586,  1590,
    1594,  1598,  1602,  1606,  1612,  1618,  1625,  1629,  1633,  1637,
    1641,  1645,  1651,  1657,  1664,  1668,  1671,  1675,  1679,  1686,
    1687,  1688,  1689,  1694,  1701,  1702,  1705,  1709,  1709,  1715,
    1716,  1717,  1718,  1719,  1720,  1721,  1722,  1723,  1724,  1725,
    1726,  1727,  1728,  1729,  1730,  1731,  1732,  1733,  1734,  1735,
    1736,  1737,  1738,  1739,  1740,  1741,  1742,  1743,  1746,  1746,
    1746,  1747,  1747,  1748,  1748,  1748,  1749,  1749,  1749,  1749,
    1750,  1750,  1750,  1751,  1751,  1751,  1752,  1752,  1752,  1752,
    1753,  1753,  1753,  1753,  1754,  1754,  1754,  1754,  1755,  1755,
    1755,  1755,  1756,  1756,  1756,  1756,  1757,  1757,  1760,  1764,
    1768,  1772,  1776,  1780,  1784,  1789,  1794,  1799,  1803,  1807,
    1811,  1815,  1819,  1823,  1827,  1831,  1835,  1839,  1843,  1847,
    1851,  1855,  1859,  1863,  1867,  1871,  1875,  1879,  1883,  1887,
    1891,  1895,  1899,  1903,  1907,  1911,  1915,  1919,  1923,  1927,
    1933,  1934,  1939,  1943,  1950,  1954,  1962,  1968,  1969,  1972,
    1973,  1974,  1979,  1984,  1991,  1997,  2002,  2007,  2012,  2019,
    2019,  2030,  2036,  2040,  2046,  2047,  2050,  2056,  2062,  2067,
    2074,  2079,  2084,  2091,  2092,  2093,  2094,  2095,  2096,  2097,
    2098,  2103,  2102,  2114,  2118,  2113,  2123,  2123,  2127,  2131,
    2135,  2139,  2144,  2149,  2153,  2157,  2161,  2165,  2169,  2170,
    2176,  2182,  2175,  2194,  2202,  2210,  2210,  2210,  2217,  2217,
    2217,  2224,  2230,  2235,  2237,  2234,  2246,  2244,  2260,  2265,
    2258,  2280,  2278,  2293,  2297,  2292,  2312,  2318,  2311,  2333,
    2337,  2341,  2345,  2351,  2358,  2359,  2360,  2363,  2364,  2367,
    2368,  2376,  2377,  2383,  2387,  2390,  2394,  2400,  2404,  2410,
    2414,  2418,  2422,  2426,  2430,  2434,  2438,  2442,  2448,  2452,
    2456,  2460,  2464,  2468,  2472,  2476,  2480,  2484,  2488,  2492,
    2496,  2500,  2504,  2510,  2511,  2518,  2522,  2526,  2533,  2537,
    2543,  2544,  2547,  2552,  2555,  2559,  2565,  2569,  2576,  2575,
    2588,  2598,  2602,  2607,  2614,  2618,  2622,  2626,  2630,  2634,
    2638,  2642,  2646,  2653,  2652,  2665,  2664,  2678,  2686,  2695,
    2698,  2705,  2708,  2712,  2713,  2716,  2720,  2723,  2727,  2730,
    2731,  2732,  2733,  2736,  2737,  2738,  2742,  2748,  2749,  2755,
    2760,  2759,  2770,  2774,  2780,  2784,  2790,  2794,  2800,  2803,
    2804,  2807,  2813,  2819,  2820,  2823,  2830,  2829,  2843,  2847,
    2854,  2858,  2865,  2872,  2873,  2874,  2875,  2876,  2880,  2886,
    2890,  2896,  2897,  2898,  2902,  2908,  2912,  2916,  2920,  2924,
    2930,  2936,  2940,  2944,  2948,  2952,  2956,  2964,  2973,  2974,
    2978,  2982,  2981,  2997,  3003,  3009,  3013,  3017,  3021,  3025,
    3029,  3033,  3037,  3041,  3045,  3049,  3053,  3057,  3061,  3066,
    3072,  3077,  3082,  3087,  3094,  3098,  3105,  3109,  3115,  3119,
    3125,  3132,  3139,  3146,  3150,  3156,  3160,  3166,  3167,  3170,
    3175,  3182,  3183,  3186,  3193,  3197,  3204,  3209,  3209,  3234,
    3235,  3241,  3246,  3252,  3258,  3263,  3268,  3273,  3280,  3281,
    3282,  3285,  3286,  3287,  3288,  3291,  3292,  3293,  3296,  3297,
    3300,  3304,  3310,  3311,  3317,  3318,  3321,  3322,  3325,  3328,
    3331,  3332,  3333,  3336,  3337,  3338,  3341,  3348,  3349,  3353
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "keyword_class", "keyword_module",
  "keyword_def", "keyword_begin", "keyword_if", "keyword_unless",
  "keyword_while", "keyword_until", "keyword_for", "keyword_undef",
  "keyword_rescue", "keyword_ensure", "keyword_end", "keyword_then",
  "keyword_elsif", "keyword_else", "keyword_case", "keyword_when",
  "keyword_break", "keyword_next", "keyword_redo", "keyword_retry",
  "keyword_in", "keyword_do", "keyword_do_cond", "keyword_do_block",
  "keyword_do_LAMBDA", "keyword_return", "keyword_yield", "keyword_super",
  "keyword_self", "keyword_nil", "keyword_true", "keyword_false",
  "keyword_and", "keyword_or", "keyword_not", "modifier_if",
  "modifier_unless", "modifier_while", "modifier_until", "modifier_rescue",
  "keyword_alias", "keyword_BEGIN", "keyword_END", "keyword__LINE__",
  "keyword__FILE__", "keyword__ENCODING__", "tIDENTIFIER", "tFID", "tGVAR",
  "tIVAR", "tCONSTANT", "tCVAR", "tLABEL", "tINTEGER", "tFLOAT", "tCHAR",
  "tXSTRING", "tREGEXP", "tSTRING", "tSTRING_PART", "tSTRING_MID",
  "tLABEL_END", "tNTH_REF", "tBACK_REF", "tREGEXP_END", "tUPLUS",
  "tUMINUS", "tPOW", "tCMP", "tEQ", "tEQQ", "tNEQ", "tGEQ", "tLEQ",
  "tANDOP", "tOROP", "tMATCH", "tNMATCH", "tDOT2", "tDOT3", "tAREF",
  "tASET", "tLSHFT", "tRSHFT", "tCOLON2", "tCOLON3", "tOP_ASGN", "tASSOC",
  "tLPAREN", "tLPAREN_ARG", "tRPAREN", "tLBRACK", "tLBRACE", "tLBRACE_ARG",
  "tSTAR", "tAMPER", "tLAMBDA", "tANDDOT", "tSYMBEG", "tREGEXP_BEG",
  "tWORDS_BEG", "tSYMBOLS_BEG", "tSTRING_BEG", "tXSTRING_BEG",
  "tSTRING_DVAR", "tLAMBEG", "tHEREDOC_BEG", "tHEREDOC_END",
  "tLITERAL_DELIM", "tHD_LITERAL_DELIM", "tHD_STRING_PART",
  "tHD_STRING_MID", "tLOWEST", "'='", "'?'", "':'", "'>'", "'<'", "'|'",
  "'^'", "'&'", "'+'", "'-'", "'*'", "'/'", "'%'", "tUMINUS_NUM", "'!'",
  "'~'", "tLAST_TOKEN", "'{'", "'}'", "'['", "','", "'`'", "'('", "')'",
  "']'", "';'", "'.'", "'\\n'", "$accept", "program", "@1", "top_compstmt",
  "top_stmts", "top_stmt", "@2", "bodystmt", "compstmt", "stmts", "stmt",
  "@3", "command_asgn", "command_rhs", "expr", "expr_value",
  "command_call", "block_command", "cmd_brace_block", "@4", "command",
  "mlhs", "mlhs_inner", "mlhs_basic", "mlhs_item", "mlhs_list",
  "mlhs_post", "mlhs_node", "lhs", "cname", "cpath", "fname", "fsym",
  "undef_list", "@5", "op", "reswords", "arg", "aref_args", "arg_rhs",
  "paren_args", "opt_paren_args", "opt_call_args", "call_args",
  "command_args", "@6", "block_arg", "opt_block_arg", "comma", "args",
  "mrhs", "primary", "@7", "@8", "@9", "@10", "@11", "@12", "@13", "@14",
  "@15", "@16", "@17", "@18", "@19", "@20", "@21", "@22", "@23", "@24",
  "@25", "@26", "primary_value", "then", "do", "if_tail", "opt_else",
  "for_var", "f_marg", "f_marg_list", "f_margs", "block_param",
  "opt_block_param", "block_param_def", "opt_bv_decl", "bv_decls", "bvar",
  "f_larglist", "lambda_body", "do_block", "@27", "block_call",
  "method_call", "brace_block", "@28", "@29", "case_body", "cases",
  "opt_rescue", "exc_list", "exc_var", "opt_ensure", "literal", "string",
  "string_rep", "string_interp", "@30", "xstring", "regexp", "heredoc",
  "heredoc_bodies", "heredoc_body", "heredoc_string_rep",
  "heredoc_string_interp", "@31", "words", "symbol", "basic_symbol", "sym",
  "symbols", "numeric", "variable", "var_lhs", "var_ref", "backref",
  "superclass", "@32", "f_arglist", "f_args", "f_bad_arg", "f_norm_arg",
  "f_arg_item", "f_arg", "f_opt_asgn", "f_opt", "f_block_opt",
  "f_block_optarg", "f_optarg", "restarg_mark", "f_rest_arg",
  "blkarg_mark", "f_block_arg", "opt_f_block_arg", "singleton", "@33",
  "assoc_list", "assocs", "assoc", "operation", "operation2", "operation3",
  "dot_or_colon", "call_op", "call_op2", "opt_terms", "opt_nl", "rparen",
  "rbracket", "trailer", "term", "nl", "terms", "none", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,    61,    63,
      58,    62,    60,   124,    94,    38,    43,    45,    42,    47,
      37,   373,    33,   126,   374,   123,   125,    91,    44,    96,
      40,    41,    93,    59,    46,    10
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint16 yyr1[] =
{
       0,   146,   148,   147,   149,   150,   150,   150,   150,   151,
     152,   151,   153,   154,   155,   155,   155,   155,   157,   156,
     156,   156,   156,   156,   156,   156,   156,   156,   156,   156,
     156,   156,   156,   158,   158,   158,   158,   158,   158,   158,
     158,   159,   159,   159,   160,   160,   160,   160,   160,   160,
     161,   162,   162,   163,   163,   165,   164,   166,   166,   166,
     166,   166,   166,   166,   166,   166,   166,   166,   167,   167,
     168,   168,   169,   169,   169,   169,   169,   169,   169,   169,
     169,   169,   170,   170,   171,   171,   172,   172,   173,   173,
     173,   173,   173,   173,   173,   173,   174,   174,   174,   174,
     174,   174,   174,   174,   175,   175,   176,   176,   176,   177,
     177,   177,   177,   177,   178,   178,   179,   180,   179,   181,
     181,   181,   181,   181,   181,   181,   181,   181,   181,   181,
     181,   181,   181,   181,   181,   181,   181,   181,   181,   181,
     181,   181,   181,   181,   181,   181,   181,   181,   182,   182,
     182,   182,   182,   182,   182,   182,   182,   182,   182,   182,
     182,   182,   182,   182,   182,   182,   182,   182,   182,   182,
     182,   182,   182,   182,   182,   182,   182,   182,   182,   182,
     182,   182,   182,   182,   182,   182,   182,   182,   183,   183,
     183,   183,   183,   183,   183,   183,   183,   183,   183,   183,
     183,   183,   183,   183,   183,   183,   183,   183,   183,   183,
     183,   183,   183,   183,   183,   183,   183,   183,   183,   183,
     183,   183,   183,   183,   183,   183,   183,   183,   183,   183,
     184,   184,   184,   184,   185,   185,   186,   187,   187,   188,
     188,   188,   188,   188,   189,   189,   189,   189,   189,   191,
     190,   192,   193,   193,   194,   194,   195,   195,   195,   195,
     196,   196,   196,   197,   197,   197,   197,   197,   197,   197,
     197,   198,   197,   199,   200,   197,   201,   197,   197,   197,
     197,   197,   197,   197,   197,   197,   197,   197,   197,   197,
     202,   203,   197,   197,   197,   204,   205,   197,   206,   207,
     197,   197,   197,   208,   209,   197,   210,   197,   211,   212,
     197,   213,   197,   214,   215,   197,   216,   217,   197,   197,
     197,   197,   197,   218,   219,   219,   219,   220,   220,   221,
     221,   222,   222,   223,   223,   224,   224,   225,   225,   226,
     226,   226,   226,   226,   226,   226,   226,   226,   227,   227,
     227,   227,   227,   227,   227,   227,   227,   227,   227,   227,
     227,   227,   227,   228,   228,   229,   229,   229,   230,   230,
     231,   231,   232,   232,   233,   233,   234,   234,   236,   235,
     237,   237,   237,   237,   238,   238,   238,   238,   238,   238,
     238,   238,   238,   240,   239,   241,   239,   242,   243,   243,
     244,   244,   245,   245,   245,   246,   246,   247,   247,   248,
     248,   248,   248,   249,   249,   249,   249,   250,   250,   251,
     252,   251,   251,   251,   253,   253,   254,   254,   255,   256,
     256,   257,   257,   258,   258,   259,   260,   259,   261,   261,
     262,   262,   263,   264,   264,   264,   264,   264,   264,   265,
     265,   266,   266,   266,   266,   267,   267,   267,   267,   267,
     268,   269,   269,   269,   269,   269,   269,   269,   270,   270,
     271,   272,   271,   273,   273,   274,   274,   274,   274,   274,
     274,   274,   274,   274,   274,   274,   274,   274,   274,   274,
     275,   275,   275,   275,   276,   276,   277,   277,   278,   278,
     279,   280,   281,   282,   282,   283,   283,   284,   284,   285,
     285,   286,   286,   287,   288,   288,   289,   290,   289,   291,
     291,   292,   292,   293,   293,   293,   293,   293,   294,   294,
     294,   295,   295,   295,   295,   296,   296,   296,   297,   297,
     298,   298,   299,   299,   300,   300,   301,   301,   302,   303,
     304,   304,   304,   305,   305,   305,   306,   307,   307,   308
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     1,     1,     3,     2,     1,
       0,     5,     4,     2,     1,     1,     3,     2,     0,     4,
       2,     3,     3,     3,     3,     3,     4,     1,     3,     3,
       3,     3,     1,     3,     3,     6,     5,     5,     5,     5,
       3,     1,     3,     1,     1,     3,     3,     3,     2,     1,
       1,     1,     1,     1,     4,     0,     5,     2,     3,     4,
       5,     4,     5,     2,     2,     2,     2,     2,     1,     3,
       1,     3,     1,     2,     3,     5,     2,     4,     2,     4,
       1,     3,     1,     3,     2,     3,     1,     2,     1,     4,
       3,     3,     3,     3,     2,     1,     1,     4,     3,     3,
       3,     3,     2,     1,     1,     1,     2,     1,     3,     1,
       1,     1,     1,     1,     1,     1,     1,     0,     4,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     3,     3,
       6,     5,     5,     5,     5,     4,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     4,     4,     2,     2,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     2,     2,     3,     3,     3,     3,     6,     1,
       1,     2,     4,     2,     1,     3,     3,     1,     1,     1,
       1,     2,     4,     2,     1,     2,     2,     4,     1,     0,
       2,     2,     2,     1,     1,     2,     1,     2,     3,     4,
       3,     4,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     0,     4,     0,     0,     5,     0,     3,     3,     3,
       2,     3,     3,     1,     2,     4,     3,     2,     1,     2,
       0,     0,     5,     6,     6,     0,     0,     7,     0,     0,
       7,     5,     4,     0,     0,     9,     0,     6,     0,     0,
       8,     0,     5,     0,     0,     7,     0,     0,     9,     1,
       1,     1,     1,     1,     1,     1,     2,     1,     1,     1,
       5,     1,     2,     1,     1,     1,     3,     1,     3,     1,
       4,     6,     3,     5,     2,     4,     1,     3,     6,     8,
       4,     6,     4,     2,     6,     2,     4,     6,     2,     4,
       2,     4,     1,     1,     1,     3,     1,     4,     1,     4,
       1,     3,     1,     1,     4,     1,     3,     3,     0,     5,
       2,     4,     5,     5,     2,     4,     4,     3,     3,     3,
       2,     1,     4,     0,     5,     0,     5,     5,     1,     1,
       6,     1,     1,     1,     1,     2,     1,     2,     1,     1,
       1,     1,     1,     1,     1,     2,     3,     1,     2,     1,
       0,     4,     1,     2,     2,     3,     2,     3,     1,     1,
       2,     1,     2,     1,     2,     1,     0,     4,     2,     3,
       1,     4,     2,     1,     1,     1,     1,     1,     2,     2,
       3,     1,     1,     2,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       0,     0,     4,     3,     2,     6,     8,     4,     6,     4,
       6,     2,     4,     6,     2,     4,     2,     4,     1,     0,
       1,     1,     1,     1,     1,     1,     1,     3,     1,     3,
       2,     2,     2,     1,     3,     1,     3,     1,     1,     2,
       1,     1,     1,     2,     2,     1,     1,     0,     4,     1,
       2,     1,     3,     3,     2,     2,     3,     4,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     0,     1,     0,     1,     2,     2,
       0,     1,     1,     1,     1,     1,     1,     1,     2,     0
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
       2,     0,     0,     1,     0,     0,     0,     0,   271,     0,
       0,   295,   298,     0,     0,   544,   319,   320,   321,   322,
     283,   249,   391,   463,   462,   464,   465,   546,     0,    10,
       0,   467,   466,   455,   270,   457,   456,   459,   458,   451,
     452,   413,   414,   468,   469,     0,     0,     0,     0,   273,
     559,   559,    80,   290,     0,     0,     0,     0,     0,     0,
     428,     0,     0,     0,     3,   544,     6,     9,    27,    32,
      44,    52,    51,     0,    68,     0,    72,    82,     0,    49,
     229,     0,    53,   288,   263,   264,   265,   266,   267,   411,
     410,   440,   412,   409,   461,     0,   268,   269,   249,     5,
       8,   319,   320,   283,   559,   391,     0,   104,   105,     0,
       0,     0,     0,   107,   470,   323,     0,   461,   269,     0,
     311,   158,   168,   159,   155,   184,   185,   186,   187,   166,
     181,   174,   164,   163,   179,   162,   161,   157,   182,   156,
     169,   173,   175,   167,   160,   176,   183,   178,   177,   170,
     180,   165,   154,   172,   171,   153,   151,   152,   148,   149,
     150,   109,   111,   110,   143,   144,   140,   122,   123,   124,
     131,   128,   130,   125,   126,   145,   146,   132,   133,   137,
     127,   129,   119,   120,   121,   134,   135,   136,   138,   139,
     141,   142,   147,   517,   313,   112,   113,   516,     0,     0,
       0,    50,     0,     0,     0,   461,     0,   269,     0,     0,
       0,     0,   334,   333,     0,     0,   461,   269,   177,   170,
     180,   165,   148,   149,   109,   110,     0,   114,   116,    20,
     115,   431,   436,   435,   553,   556,   544,   555,     0,   433,
       0,   557,   554,   545,     0,     0,     0,     0,     0,     0,
     244,   256,    66,   248,   559,   559,   521,    67,    65,   559,
     238,   284,    64,     0,   237,   390,    63,   546,     0,   547,
      18,     0,     0,   207,     0,   208,   280,     0,     0,     0,
     544,    15,   546,    70,    14,     0,   546,     0,   550,   550,
     230,     0,     0,   550,   519,     0,     0,    78,     0,    88,
      95,   489,   445,   444,   446,   447,     0,   443,   442,   426,
     420,   419,   422,     0,     0,   417,   438,     0,   449,     0,
     415,     0,   424,     0,   453,   454,    48,   222,   223,     4,
     545,     0,     0,     0,     0,     0,     0,     0,   378,   380,
       0,    84,     0,    76,    73,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   541,   559,   540,     0,   543,   542,     0,
     395,   393,   289,     0,     0,   384,    57,   287,   308,   104,
     105,   106,   453,   454,   471,   306,     0,   559,     0,     0,
       0,   314,   539,   538,   316,     0,   559,   280,   325,     0,
     324,     0,     0,   559,     0,     0,     0,     0,     0,     0,
     280,     0,   559,     0,   303,     0,   117,     0,     0,   432,
     434,     0,     0,   558,   524,   525,   257,   251,     0,     0,
       0,   254,   245,     0,   253,   254,   246,     0,   546,   240,
     559,   559,   239,   250,   546,     0,   286,    47,     0,     0,
       0,     0,     0,     0,    17,   546,   278,    13,   545,    69,
     274,   277,   281,   552,   231,   551,   552,   233,   282,   520,
      94,    86,     0,    81,     0,     0,   559,     0,   495,   492,
     491,   490,   493,     0,   508,   512,   511,   507,   489,   291,
     375,   494,   496,   498,   559,     0,   505,   559,   510,   559,
       0,   488,   448,     0,     0,   423,   429,   427,   418,   439,
     450,   416,   425,     0,     0,     7,    21,    22,    23,    24,
      25,    45,    46,   559,     0,    28,    30,     0,    31,   546,
       0,    74,    85,    43,    33,    41,     0,   234,   188,    29,
       0,   269,   204,   212,   217,   218,   219,   214,   216,   226,
     227,   220,   221,   197,   198,   224,   225,   546,   213,   215,
     209,   210,   211,   199,   200,   201,   202,   203,   531,   536,
     532,   537,   389,   249,   387,   546,   531,   533,   532,   534,
     388,   559,   531,   532,   249,   559,   559,    34,   234,   189,
      40,   196,    55,    58,     0,     0,     0,   104,   105,   108,
       0,   546,   559,     0,   546,   489,     0,   272,   559,   559,
     401,   559,   326,   535,   279,   546,   531,   532,   559,   328,
     296,   327,   299,   535,   279,   546,   531,   532,     0,     0,
       0,     0,   256,     0,   302,   526,     0,   523,   255,     0,
     258,   252,   559,   522,   236,   254,     0,   243,   285,   548,
      19,     0,    26,   195,    71,    16,   546,   550,    87,    79,
     535,    93,   546,   531,   532,   500,   495,     0,   346,   337,
     339,   546,   335,   546,     0,     0,   481,   515,   501,     0,
     484,   509,     0,   486,   513,   441,     0,   430,   205,   206,
     366,   546,     0,   364,   363,   262,     0,    83,    77,     0,
       0,     0,     0,     0,   559,     0,     0,     0,     0,   386,
      61,     0,   392,     0,     0,   385,    59,   381,    54,     0,
       0,   559,   309,     0,     0,   392,   312,   518,   489,     0,
       0,   317,   402,   403,   559,   404,     0,   559,   331,     0,
       0,   329,     0,     0,   392,     0,     0,     0,     0,     0,
     392,     0,   118,   437,   301,     0,     0,   527,   259,   247,
     559,    11,   275,   232,   392,   546,     0,   344,     0,   497,
       0,   368,     0,     0,   292,   499,   559,   559,   514,   559,
     506,   559,   559,   421,   546,     0,   559,     0,   503,   559,
     559,   362,     0,     0,   260,    75,    42,   235,   531,   532,
     546,   531,   532,     0,    39,   193,    38,   194,    62,   549,
       0,    36,   191,    37,   192,    60,   382,   383,     0,     0,
       0,     0,   472,   307,   546,     0,   474,   489,     0,     0,
     406,   332,     0,    12,   408,     0,   293,     0,   294,     0,
       0,   304,   258,   559,   242,   336,   347,     0,   342,   338,
     374,     0,     0,     0,     0,   477,     0,   479,     0,   485,
       0,   482,   487,     0,   365,   353,   355,     0,   502,     0,
     358,     0,   360,   379,   261,   392,   228,    35,   190,   396,
     394,     0,     0,   473,   315,     0,     0,   405,     0,    96,
     103,     0,   407,     0,   297,   300,     0,   398,   399,   397,
       0,   345,     0,   340,   372,   546,   370,   373,   377,   376,
     559,   559,   559,   559,   367,   559,   559,   280,     0,   559,
     504,   559,   559,    56,   310,     0,   102,     0,   559,     0,
     559,   559,     0,   343,     0,     0,   369,   478,     0,   475,
     480,   483,     0,   350,     0,   352,   535,   279,   359,     0,
     356,   361,   318,    99,   101,   546,   531,   532,   400,   330,
     305,   341,   371,   559,   559,   559,   559,   559,    97,   476,
     351,     0,   348,   354,   357,   559,   349
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     2,    64,    65,    66,   271,   405,   406,   280,
     281,   458,    68,   544,    69,   202,    70,    71,   603,   731,
      72,    73,   282,    74,    75,    76,   483,    77,   203,   113,
     114,   227,   228,   229,   639,   581,   196,    79,   287,   548,
     582,   261,   448,   449,   262,   263,   253,   442,   447,   450,
     538,    80,   199,   285,   666,   286,   301,   684,   209,   758,
     210,   759,   638,   906,   606,   604,   831,   399,   401,   615,
     616,   837,   274,   409,   630,   750,   751,   215,   679,   680,
     681,   794,   702,   703,   780,   915,   916,   499,   784,   339,
     533,    82,    83,   387,   596,   595,   432,   909,   619,   744,
     839,   843,    84,    85,   314,   315,   514,    86,    87,    88,
     648,   237,   238,   239,   427,    89,    90,    91,   308,    92,
      93,   205,   206,    96,   207,   395,   605,   739,   740,   501,
     502,   503,   504,   505,   506,   798,   799,   507,   508,   509,
     510,   788,   686,   198,   400,   292,   451,   256,    98,   610,
     584,   404,   398,   379,   240,   455,   456,   722,   474,   410,
     269,   243,   284
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -781
static const yytype_int16 yypact[] =
{
    -781,   152,  2639,  -781,  7290,  9130,  9463,  5278,  -781,  8785,
    8785,  -781,  -781,  9241,  6679,  5019,  7520,  7520,  -781,  -781,
    7520,  2815,  6037,  -781,  -781,  -781,  -781,   162,  6679,  -781,
      27,  -781,  -781,  5416,  5531,  -781,  -781,  5646,  -781,  -781,
    -781,  -781,  -781,  -781,  -781,  8900,  8900,   150,  4296,   -36,
    7865,  8095,  6953,  -781,  6405,   495,   785,   831,  1026,   299,
    -781,    85,  9015,  8900,  -781,   664,  -781,  1170,  -781,   164,
    -781,  -781,   221,   155,  -781,   143,  9352,  -781,   227, 11402,
      24,   188,   189,    60,  -781,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,  -781,   175,   262,  -781,   204,    63,  -781,
    -781,  -781,  -781,  -781,   239,   239,   247,   444,   586,  8785,
     130,  4412,   176,  -781,   244,  -781,   314,  -781,  -781,    63,
    -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,    25,   157,
     161,   165,  -781,  -781,  -781,  -781,  -781,  -781,   166,   195,
    -781,   210,  -781,   226,  -781,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,   245,  3492,
     342,   164,   228,   282,   478,    17,   318,    32,   228,  8785,
    8785,   350,  -781,  -781,   564,   405,    69,    70,  -781,  -781,
    -781,  -781,  -781,  -781,  -781,  -781,  6542,  -781,  -781,   293,
    -781,  -781,  -781,  -781,  -781,  -781,   664,  -781,   612,  -781,
     413,  -781,  -781,   664,  8900,  8900,  8900,  8900,  1021,  8900,
    -781, 11343,  -781,  -781,   344,   365,  -781,  -781,  -781,  7520,
    -781,  -781,  -781,  7520,  -781,  -781,  -781,  5135,  8785,  -781,
    -781,   371,  4528,  -781,   644,   436,   209,  7635,  4296,   383,
     664,  1170,   389,   426,  -781,  7635,   389,   403,   192,   327,
    -781, 11343,   412,   327,  -781,   497,  9574,   417,   689,   694,
     745,   967,  -781,  -781,  -781,  -781,  1123,  -781,  -781,  -781,
    -781,  -781,  -781,   769,   852,  -781,  -781,  1195,  -781,  1202,
    -781,  1240,  -781,   604,   486,   491,  -781,  -781,  -781,  -781,
    4787,  8785,  8785,  8785,  8785,  7635,  8785,  8785,  -781,  -781,
    8210,  -781,  4296,  7064,   428,  8210,  8900,  8900,  8900,  8900,
    8900,  8900,  8900,  8900,  8900,  8900,  8900,  8900,  8900,  8900,
    8900,  8900,  8900,  8900,  8900,  8900,  8900,  8900,  8900,  8900,
    8900,  8900,  9843,  -781,  7520,  -781,  9926,  -781,  -781, 11088,
    -781,  -781,  -781,  9015,  9015,  -781,   493,  -781,   164,  -781,
     778,  -781,  -781,  -781,  -781,  -781, 10009,  7520, 10092,  3492,
    8785,  -781,  -781,  -781,  -781,   567,   583,    74,  -781,  3635,
     581,  8900, 10175,  7520, 10258,  8900,  8900,  3921,    51,    51,
      75, 10341,  7520, 10424,  -781,   535,  -781,  4528,   413,  -781,
    -781,  8325,   584,  -781, 11402, 11402, 11402, 11402,  8900,  1108,
    8900,   769,  -781,  7750,  -781,  7405,  -781,   527,   389,  -781,
     499,   501,  -781,  -781,    93,   503,  -781,  -781,  6679,  4037,
     518, 10175, 10258,  8900,  1170,   389,  -781,  -781,  4903,   522,
    1170,  -781,  -781,  7980,  -781,  -781,  -781,  -781,  -781,  -781,
     778,   143,  9574,  -781,  9574, 10507,  7520, 10590,   563,  -781,
    -781,  -781,  -781,  1048,  -781,  -781,  -781,  -781,   809,  -781,
    -781,  -781,  -781,  -781,   545,  8900,  -781,   546,   638,   560,
     649,  -781,  -781,  1254,  4528,   769,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,  8900,  8900,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,    -6,  8900,  -781, 11173,   344,  -781,   389,
    9574,   565,  -781,  -781,  -781,   661,   591,  2491,  -781,  -781,
     823,   223,   436,  9863,  9863,  9863,  9863,  1066,  1066,  9946,
    2184,  9863,  9863, 11419, 11419,   504,   504,  1693,  1066,  1066,
     860,   860,   942,    50,    50,   436,   436,   436,  2948,  6152,
    3214,  6267,  -781,   239,  -781,   389,   523,  -781,   561,  -781,
    -781,  6037,  -781,  -781,  2152,    -6,    -6,  -781, 11156,  -781,
    -781,  -781,  -781,  -781,   664,  8785,  3492,   680,   655,  -781,
     239,   389,   239,   698,    93,   983,  6816,  -781,  8440,   702,
    -781,   357,  -781,  5761,  5899,   389,   308,   378,   702,  -781,
    -781,  -781,  -781,   122,   148,   389,   102,   103,  8785,  6679,
     596,   707, 11402,    71,  -781, 11402,  8900, 11402,   769,  8900,
   11343,  -781,   365,  -781,  -781,     0,  7750,  7175,  -781,  -781,
    -781,   598,  -781,  -781,     2,  1170,   389,   327,   428,  -781,
      79,   655,   389,   190,   394,  -781,  -781,  1048,   517,  -781,
     605,   389,  -781,   389,    78,   809,  -781,  -781, 11402,   809,
    -781,  -781,  1000,  -781,  -781,  -781,   622,  -781,   436,   436,
    -781,   949,  4671,  -781,  -781, 11240,  8555,  -781,  -781,  9574,
    7635,  9015,  8900, 10673,  7520, 10756,   643,  9015,  9015,  -781,
     493,   623,   734,  9015,  9015,  -781,   493,    60,   221,  4671,
    4528,    -6,  -781,   664,   751,  -781,  -781,  -781,   809,  3492,
     664,  -781, 11173,  -781,   681,  -781,  4180,   786,  -781,  8785,
     789,  -781,  8900,  8900,   422,  8900,  8900,   790,  4671,  4671,
     107,    51,  -781,  -781,  -781,  8670,  3778, 11402, 11402,  -781,
     668,  -781,  -781,  -781,   529,   389,   926,   676,  1385,  -781,
     686,   687,  4671,  4528,  -781,  -781,   697,   699,  -781,   706,
    -781,   715,   706,  -781,   389,   722,   717,  9685,  -781,   719,
     721,  -781,   846,  8900, 11258,  -781,  -781, 11402,  3081,  3347,
     389,   424,   432,  8900,  -781,  -781,  -781,  -781,  -781,  -781,
    9015,  -781,  -781,  -781,  -781,  -781,  -781,  -781,   851,   735,
    4528,  3492,  -781,  -781,   389,   855,  -781,   983,  9796,   228,
    -781,  -781,  4671,  -781,  -781,   228,  -781,  8900,  -781,   859,
     862,  -781, 11402,   116,  7175,  -781,   741,   926,   639,  -781,
    -781,   685,   868,   750,   809,  -781,  1000,  -781,  1000,  -781,
    1000,  -781,  -781,   765,  -781,   809,  -781,   845,   944,   809,
    -781,  1000,  -781,  -781, 11325,   435, 11402,  -781,  -781,  -781,
    -781,   768,   891,  -781,  -781,  3492,   856,  -781,   961,   694,
     745,  3492,  -781,  3635,  -781,  -781,  4671,  -781,  -781,  -781,
     926,   741,   926,   772,  -781,   335,  -781,  -781,  -781,  -781,
     706,   797,   706,   706,  -781,   804,   808,  -781, 10839,   706,
    -781,   813,   706,  -781,  -781,   913,   778, 10922,  7520, 11005,
     583,   357,   938,   741,   926,   685,  -781,  -781,  1000,  -781,
    -781,  -781,   809,  -781,  1000,  -781,   816,   818,  -781,  1000,
    -781,  -781,  -781,   680,   655,   389,   406,   462,  -781,  -781,
    -781,   741,  -781,   706,   706,   824,   706,   706,   536,  -781,
    -781,  1000,  -781,  -781,  -781,   706,  -781
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -781,  -781,  -781,   502,  -781,    39,  -781,  -384,   110,  -781,
      61,  -781,  -207,  -331,   109,    18,   -60,  -781,  -572,  -781,
     -12,   950,  -185,   -22,     1,  -272,  -437,   -17,  1250,   -80,
     962,     5,    10,  -781,  -781,     4,  -781,   981,  -781,   427,
      -8,  -135,  -276,    40,    12,  -781,  -381,  -245,  -129,   154,
    -301,    16,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,  -781,
    -781,  -781,   419,  -199,  -377,    28,  -574,  -781,  -717,  -675,
     307,  -781,  -520,  -781,  -610,  -781,    31,  -781,  -781,   242,
    -781,  -781,  -781,   -82,  -781,  -781,  -403,  -781,    52,  -781,
    -781,  -781,  -781,  -781,    23,   -25,  -781,  -781,  -781,  -781,
     682,  -290,  -781,   756,  -781,  -781,  -781,     3,  -781,  -781,
    -781,  1380,  1627,   989,  1157,  -781,  -781,   169,  -262,  -755,
      97,  -601,   421,  -646,  -622,  -780,   124,   323,  -781,  -616,
    -781,  -237,   484,  -781,  -781,  -781,    20,  -399,  2071,  -223,
    -781,  -781,   -75,  -781,     7,   -24,   283,  -584,  -273,   217,
      68,   -15,    -2
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -560
static const yytype_int16 yytable[] =
{
      99,   382,   326,   268,   250,   250,   376,   378,   250,   417,
     446,   195,   194,   260,   265,   613,   477,   230,   195,   264,
     479,   115,   115,   516,   482,   641,   283,   735,   208,   115,
     391,   230,   195,   236,   266,   297,   255,   255,   270,   500,
     255,   754,   632,   100,   549,   747,   653,   669,   290,   294,
     330,   760,   597,   600,   757,   797,   252,   257,   195,   307,
     258,   859,   651,    67,   511,    67,   651,   790,   115,   787,
     289,   293,   329,   791,   700,   729,   730,   344,   629,   317,
     319,   321,   323,   242,   785,   800,   380,   408,   774,   380,
     385,   795,   115,   465,   -96,  -103,   260,   265,   585,   930,
    -102,   856,   264,   708,   -91,  -276,   917,   782,  -460,  -276,
     386,   385,   231,  -323,  -463,   232,   233,   701,   201,   201,
     -69,   611,   346,   416,   201,   443,  -323,   -98,  -100,   414,
     336,   337,   -97,   242,   746,   -96,   431,   625,   543,   423,
     -83,  -241,  -241,   324,   325,  -241,   635,   -99,   818,   583,
    -103,   516,     3,   591,   825,   516,   594,   539,   279,   473,
     476,  -323,   272,   231,   476,   463,   232,   233,  -323,  -463,
     254,   254,   930,  -101,   254,   612,   543,   543,   369,   370,
     371,   389,   911,   231,   873,   390,   232,   233,   783,   583,
     917,   591,  -102,   859,   234,   381,   235,   -91,   381,   462,
     612,   336,   337,   259,   288,   276,   446,   -88,   -95,   441,
     672,   830,   482,   -94,   234,   -90,   235,   -91,   388,  -531,
     -91,   279,   734,   487,   -91,   697,   885,   418,   419,   797,
     195,   307,   241,   797,   392,   393,   683,   943,   235,   612,
     -90,   -92,   790,   428,   408,   -89,  -462,   250,   921,   338,
    -464,   250,   444,   444,  -465,  -467,   283,   452,   653,   926,
     -91,   511,  -531,   931,   612,   468,  -460,   785,   482,   971,
     242,   439,   805,   340,   785,   651,   242,   372,   377,   907,
     535,   341,   241,   255,  -466,   545,   -93,   467,  -532,   518,
     373,   373,   518,   -96,   518,   384,   518,   481,   518,  -455,
     463,  -462,   267,   453,   242,  -464,   797,   235,   -90,  -465,
    -467,   242,   115,   -88,   384,  -459,   609,   743,   201,   201,
     283,   656,  -103,   545,   545,   374,   541,  -102,   -90,   513,
     441,   -90,   375,   375,   402,   -90,   975,   235,   464,  -466,
     231,  -103,   -95,   232,   233,   345,   470,   -94,   242,   526,
     527,   528,   529,   383,  -455,   835,   475,   475,   697,   115,
     322,   475,   250,   310,   311,   516,   394,   516,   590,   525,
    -459,   234,   452,   235,   749,   746,   454,   457,   511,   259,
     589,   978,   460,   589,   851,   250,   814,   267,   279,   403,
     590,    67,   821,   823,   773,   452,   530,   407,   242,   755,
     411,   250,   589,   396,   620,   420,   590,   769,   706,   415,
     250,   452,   312,   313,   518,   590,   373,   254,   589,   -92,
     452,    81,   -98,    81,   116,   116,   -98,   589,   204,   204,
     424,   426,   214,   431,   204,   204,   204,   482,   810,   204,
     201,   201,   201,   201,   766,   531,   532,   892,   444,   444,
     908,   397,   279,   241,   590,   653,   725,    99,   375,   727,
     433,   230,   195,   652,   801,   445,   589,    81,   660,   756,
    -528,   298,   235,   945,   250,   715,   834,   725,  -100,   590,
     235,   204,   441,   668,   452,   481,   242,   242,   518,   887,
     583,   589,   591,   667,   537,   298,  -100,   241,   115,   537,
     115,   511,   687,   445,   543,   687,   459,   687,   346,   614,
     543,   935,   -92,   847,   765,   723,   543,   543,   -98,   621,
      67,   -98,   -98,   724,   466,   769,   820,   628,   204,   665,
      81,   704,   -92,  -455,   235,   -92,   242,   640,   476,   -92,
     -97,   481,   -98,   716,   -68,   472,  -455,   433,   478,   -98,
    -100,   -98,   480,   -97,   -89,   484,   115,   309,   523,   310,
     311,   721,  -392,   524,   516,   469,   542,   412,   676,   471,
     489,   490,   491,   492,  -100,   719,   346,  -100,  -100,  -528,
     373,  -455,   617,   260,  -528,   643,   260,   721,  -455,   264,
     682,   602,   264,   704,   704,   720,   618,   622,   512,   644,
     511,   721,   719,   726,   260,  -100,   728,  -100,   312,   313,
     264,   721,  -529,   543,   723,   413,   745,   748,    81,   748,
     195,   741,   375,   733,   696,  -392,   748,   247,   204,   204,
     367,   368,   369,   370,   371,   631,   631,   655,  -392,   657,
     901,   -98,   230,   195,   659,   826,   903,   -89,   721,   762,
     444,   545,   724,   421,   662,   776,   761,   545,   816,   781,
     -83,   -90,   965,   545,   545,   522,   373,   -89,   310,   311,
     -89,  -392,   242,  -392,   -89,  -459,   770,   781,   204,  -100,
    -392,   675,   204,   685,   689,   433,   204,   204,  -459,   691,
     676,    81,   489,   490,   491,   492,    81,    81,   692,   -92,
     694,   422,   250,   709,    81,   710,  -535,   590,   375,   711,
     481,   242,   452,   736,   201,   298,   612,   312,   313,   589,
     746,  -529,   764,  -459,   429,   115,  -529,   232,   233,   704,
    -459,   654,   763,   461,   771,   475,   914,   658,   489,   490,
     491,   492,   840,   778,  -279,   844,   373,   201,   664,    81,
     204,   204,   204,   204,    81,   204,   204,  -279,   793,   204,
     545,    81,   298,   813,   550,   819,   833,   845,   444,  -535,
     781,   806,   537,   838,   682,   777,   231,   912,   485,   232,
     233,   413,  -535,  -461,   687,   687,   721,   687,   375,   687,
     687,   373,  -279,   204,   687,  -532,  -461,   687,   687,  -279,
     842,   242,   550,   550,   846,   848,   854,   234,   242,   235,
     599,   601,   802,   115,   857,  -535,   204,  -535,    81,   204,
    -531,   732,   707,   939,  -535,   820,   486,   860,    81,   242,
     861,  -461,   204,   375,  -269,   864,    81,   866,  -461,   828,
     829,   204,   599,   601,   868,   874,    81,  -269,   316,   310,
     311,   748,   -97,   870,   115,   875,   841,   879,   201,   881,
     488,   883,   489,   490,   491,   492,   889,  -280,   849,   850,
     894,   890,   -89,   682,   904,   682,   853,   905,    81,   910,
    -280,   231,  -269,   918,   232,   233,   919,    81,   924,  -269,
     663,   946,   862,   863,   318,   310,   311,   737,   312,   313,
     927,   298,   493,   298,   933,   204,   934,   242,   494,   495,
     944,   936,   713,   242,   517,  -280,   310,   311,   687,   687,
     687,   687,  -280,   687,   687,   373,   250,   687,   962,   687,
     687,   590,   346,    81,   496,   948,   452,   497,   620,   748,
     891,   721,   952,   589,   312,   313,   954,   359,   360,   772,
     832,   959,   902,   970,   682,   913,  -531,   836,  -532,   298,
     714,   661,   981,   212,   779,   312,   313,   375,   120,   969,
     827,   687,   687,   687,   687,   687,   972,   676,   631,   489,
     490,   491,   492,   687,   775,   366,   367,   368,   369,   370,
     371,   690,   968,   693,   430,   515,   197,   251,   251,   925,
     488,   251,   489,   490,   491,   492,   895,   682,   786,   682,
       0,   940,     0,   941,   346,     0,   942,     0,   488,   677,
     489,   490,   491,   492,   204,    81,   273,   275,     0,   359,
     360,   251,   291,   928,   488,     0,   489,   490,   491,   492,
       0,   682,   493,   327,   328,     0,   373,     0,   494,   495,
     937,   676,     0,   489,   490,   491,   492,   204,   855,     0,
     493,     0,     0,   373,     0,     0,   494,   495,   367,   368,
     369,   370,   371,     0,   496,     0,   493,   497,     0,     0,
       0,   397,   494,   495,   320,   310,   311,   438,   375,   320,
     310,   311,   496,   493,   235,   497,     0,     0,   938,   676,
     495,   489,   490,   491,   492,   375,     0,   498,   496,     0,
     789,   497,     0,   792,     0,     0,     0,   893,     0,     0,
       0,    81,   796,   738,     0,   496,     0,     0,   298,    81,
     550,     0,     0,   204,   312,   313,   550,   204,   346,   312,
     313,   677,   550,   550,   815,   817,     0,   678,    81,    81,
     822,   824,     0,   359,   360,     0,     0,     0,    81,    97,
       0,    97,   118,   118,     0,    81,     0,     0,   204,     0,
     217,   521,   310,   311,   646,     0,     0,    81,    81,   815,
     817,     0,   822,   824,     0,    81,   512,   310,   311,   364,
     365,   366,   367,   368,   369,   370,   371,     0,     0,     0,
       0,    81,    81,     0,     0,    97,     0,     0,     0,   300,
     331,   332,   333,   334,   335,     0,   878,     0,     0,     0,
       0,   312,   313,     0,     0,   434,   435,   436,   437,     0,
     327,     0,     0,   300,     0,     0,   312,   313,     0,   550,
     251,     0,     0,     0,   251,     0,     0,   888,     0,    81,
      81,     0,    78,     0,    78,     0,     0,   898,   519,   310,
     311,    81,     0,   213,     0,   520,   310,   311,    97,     0,
     865,   867,     0,   869,   888,   871,   872,     0,     0,     0,
     876,     0,     0,   880,   882,   920,     0,   922,     0,     0,
       0,   923,     0,     0,     0,     0,     0,     0,    78,     0,
     929,     0,   932,   521,   310,   311,     0,     0,   312,   313,
       0,     0,     0,     0,    81,   312,   313,   695,   310,   311,
      81,   536,    81,     0,     0,    81,   547,   552,   553,   554,
     555,   556,   557,   558,   559,   560,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,   571,   572,   573,   574,
     575,   576,   577,   312,   313,   251,    97,   204,     0,     0,
       0,    78,     0,     0,   598,   598,     0,   312,   313,   973,
       0,     0,     0,   974,     0,   976,     0,     0,   251,     0,
     977,     0,    94,     0,    94,   117,   117,   117,     0,     0,
       0,     0,   598,   216,   251,     0,   598,   598,     0,     0,
       0,     0,   985,   251,   947,   949,   950,   951,     0,   953,
     955,     0,   642,   958,     0,   960,   961,     0,     0,   645,
       0,   647,     0,     0,   650,     0,   291,     0,    94,    97,
       0,     0,   299,     0,    97,    97,   676,     0,   489,   490,
     491,   492,    97,     0,   598,     0,     0,     0,     0,    78,
       0,     0,     0,   300,   650,     0,   299,   979,   980,   982,
     983,   984,     0,     0,     0,     0,     0,   251,     0,   986,
       0,     0,     0,     0,     0,     0,     0,     0,   677,     0,
       0,     0,     0,     0,   858,     0,   688,    97,     0,     0,
       0,    94,    97,     0,     0,     0,     0,     0,     0,    97,
     300,     0,   551,     0,   698,   699,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   705,     0,     0,     0,     0,
       0,     0,    78,     0,     0,     0,     0,    78,    78,     0,
       0,     0,     0,     0,     0,    78,     0,     0,     0,     0,
     551,   551,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    97,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    97,     0,     0,     0,
       0,     0,     0,     0,    97,     0,     0,     0,     0,    94,
      78,     0,     0,     0,    97,    78,     0,     0,     0,     0,
       0,     0,    78,     0,     0,   546,     0,     0,     0,   742,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    97,     0,     0,     0,
       0,     0,     0,     0,     0,    97,     0,   767,     0,    95,
     768,    95,     0,   546,   546,     0,     0,   650,   291,   300,
       0,   300,     0,     0,     0,     0,     0,     0,     0,    78,
       0,     0,    94,     0,     0,     0,     0,    94,    94,    78,
       0,     0,     0,     0,     0,    94,     0,    78,     0,     0,
       0,    97,     0,     0,     0,    95,   299,    78,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   804,     0,     0,
       0,     0,   598,   807,     0,   251,     0,   300,   598,   598,
       0,     0,     0,     0,   598,   598,     0,     0,     0,    78,
      94,     0,     0,     0,     0,    94,     0,     0,    78,     0,
       0,     0,    94,   299,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   598,   598,     0,   598,   598,    95,     0,
       0,     0,     0,     0,     0,     0,   852,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    97,    78,   346,   347,   348,   349,   350,
     351,   352,   353,   354,   355,   356,   357,   358,     0,    94,
     359,   360,     0,     0,   884,     0,     0,     0,     0,    94,
       0,     0,     0,     0,   886,     0,     0,    94,     0,     0,
       0,   598,     0,     0,     0,     0,     0,    94,     0,     0,
       0,     0,   361,     0,   362,   363,   364,   365,   366,   367,
     368,   369,   370,   371,     0,     0,    95,     0,   598,     0,
       0,     0,     0,     0,     0,   291,     0,     0,   235,    94,
       0,     0,     0,     0,     0,     0,     0,     0,    94,     0,
       0,     0,     0,     0,     0,     0,    78,     0,     0,    97,
       0,     0,   299,     0,   299,     0,   300,    97,   551,     0,
       0,     0,     0,     0,   551,     0,     0,     0,     0,     0,
     551,   551,     0,     0,     0,     0,    97,    97,     0,     0,
       0,     0,     0,     0,    94,     0,    97,     0,     0,    95,
       0,     0,     0,    97,    95,    95,     0,     0,     0,     0,
       0,     0,    95,     0,     0,    97,    97,     0,     0,   251,
     299,     0,     0,    97,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    97,
      97,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    78,     0,   118,     0,     0,    95,     0,     0,
      78,   546,    95,     0,     0,     0,     0,   546,     0,    95,
       0,     0,    95,   546,   546,     0,     0,   551,     0,    78,
      78,     0,     0,     0,     0,     0,    94,    97,    97,    78,
       0,     0,     0,     0,     0,   900,    78,     0,     0,    97,
       0,     0,     0,     0,     0,     0,     0,     0,    78,    78,
      95,    95,     0,     0,     0,     0,    78,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    95,     0,     0,     0,
       0,     0,    78,    78,     0,     0,    95,     0,     0,     0,
       0,     0,     0,     0,    95,     0,     0,     0,     0,     0,
       0,     0,    97,     0,    95,     0,     0,     0,    97,     0,
      97,     0,     0,    97,     0,     0,     0,     0,     0,     0,
     546,     0,     0,     0,     0,     0,   119,   119,     0,     0,
      78,    78,    94,     0,   119,     0,    95,     0,   897,   299,
      94,     0,    78,     0,     0,    95,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    94,
      94,     0,     0,     0,     0,     0,   119,   119,     0,    94,
       0,   119,   119,   119,     0,     0,    94,     0,     0,     0,
       0,     0,     0,     0,   119,     0,     0,     0,    94,    94,
       0,    95,     0,     0,     0,    78,    94,   119,     0,     0,
       0,    78,  -559,    78,     0,     0,    78,     0,     0,     0,
       0,     0,    94,    94,     0,  -559,  -559,  -559,  -559,  -559,
    -559,     0,  -559,     0,     0,     0,     0,   117,  -559,  -559,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  -559,
    -559,     0,  -559,  -559,  -559,  -559,  -559,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      94,    94,     0,     0,     0,     0,     0,     0,   899,     0,
       0,     0,    94,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    95,     0,     0,     0,     0,     0,     0,
       0,  -559,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  -559,     0,   346,   347,   348,   349,
     350,   351,   352,   353,  -559,   355,   356,  -559,  -559,     0,
       0,   359,   360,     0,     0,    94,     0,     0,     0,     0,
       0,    94,     0,    94,     0,     0,    94,  -559,  -559,     0,
       0,     0,   259,  -559,     0,  -559,  -559,  -559,     0,     0,
       0,     0,     0,     0,     0,   362,   363,   364,   365,   366,
     367,   368,   369,   370,   371,   119,   119,   119,   119,     0,
     119,     0,     0,     0,     0,     0,     0,     0,     0,    95,
       0,     0,     0,     0,     0,     0,     0,    95,    95,     0,
       0,     0,     0,     0,    95,     0,     0,     0,     0,     0,
      95,    95,     0,     0,     0,     0,    95,    95,     0,     0,
       0,     0,     0,     0,     0,     0,    95,   119,     0,     0,
       0,     0,     0,    95,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    95,    95,     0,     0,     0,
       0,     0,     0,    95,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    95,
      95,     0,     0,     0,   119,     0,     0,   119,   119,   119,
     119,   119,   119,   119,   119,   119,   119,   119,   119,   119,
     119,   119,   119,   119,   119,   119,   119,   119,   119,   119,
     119,   119,   119,     0,     0,     0,     0,    95,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    95,    95,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    95,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   119,     0,     0,     0,   119,   119,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   119,     0,     0,     0,     0,     0,     0,   119,
       0,   119,     0,     0,   119,     0,   119,     0,     0,     0,
       0,     0,    95,     0,     0,     0,     0,     0,    95,     0,
      95,     0,     0,    95,   119,   712,     0,     0,     0,     0,
       0,     0,     0,     0,   119,     0,     0,     0,     0,     0,
       0,     0,     0,   119,     0,   119,     0,     0,     0,     0,
       0,     0,     0,   346,   347,   348,   349,   350,   351,   352,
     353,   354,   355,   356,   357,   358,   119,     0,   359,   360,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   119,   119,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   119,     0,     0,     0,     0,
     361,   119,   362,   363,   364,   365,   366,   367,   368,   369,
     370,   371,     0,     0,     0,     0,     0,     0,     0,  -256,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  -559,
       4,     0,     5,     6,     7,     8,     9,    10,    11,    12,
      13,    14,     0,     0,     0,     0,     0,     0,    15,     0,
      16,    17,    18,    19,     0,     0,     0,     0,     0,    20,
      21,    22,    23,    24,    25,    26,     0,     0,    27,     0,
       0,     0,     0,     0,    28,    29,    30,    31,    32,   119,
      33,    34,    35,    36,    37,    38,     0,    39,    40,    41,
       0,     0,    42,     0,     0,     0,    43,    44,     0,    45,
      46,     0,     0,     0,     0,     0,     0,   119,     0,     0,
     119,     0,     0,     0,     0,     0,     0,   119,   119,    47,
       0,     0,    48,    49,     0,    50,    51,     0,    52,     0,
      53,     0,    54,    55,    56,    57,    58,    59,     0,     0,
      60,  -559,     0,     0,  -559,  -559,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      61,    62,    63,     0,     0,     0,     0,   119,     0,     0,
     119,     0,  -559,   119,  -559,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,  -559,     0,     0,     0,     0,
       0,     0,     0,   119,   119,     0,   119,   119,  -559,  -559,
    -559,  -559,  -559,  -559,     0,  -559,   119,     0,     0,     0,
       0,     0,  -559,  -559,     0,     0,     0,     0,     0,     0,
       0,     0,  -559,  -559,     0,  -559,  -559,  -559,  -559,  -559,
       0,     0,     0,     0,     0,     0,     0,     0,   119,     0,
       0,     0,     0,     0,   119,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   119,     0,     0,  -559,  -559,  -559,
    -559,  -559,  -559,  -559,  -559,  -559,  -559,  -559,  -559,  -559,
       0,     0,  -559,  -559,  -559,     0,     0,  -559,     0,   119,
       0,     0,     0,  -559,     0,     0,     0,  -559,   119,     0,
       0,     0,     0,     0,     0,   119,     0,  -559,     0,     0,
    -559,  -559,     0,     0,  -559,     0,  -559,  -559,  -559,  -559,
    -559,  -559,  -559,  -559,  -559,  -559,     0,     0,  -535,     0,
       0,  -559,  -559,  -559,     0,   259,  -559,  -559,  -559,  -559,
    -559,  -535,  -535,  -535,     0,  -535,  -535,     0,  -535,     0,
       0,     0,     0,     0,  -535,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,  -535,  -535,     0,  -535,  -535,
    -535,  -535,  -535,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    -535,  -535,  -535,  -535,  -535,  -535,  -535,  -535,  -535,  -535,
    -535,  -535,  -535,     0,     0,  -535,  -535,  -535,     0,   717,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    -535,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    -535,     0,     0,  -535,  -535,     0,   -99,  -535,     0,  -535,
    -535,  -535,  -535,  -535,  -535,  -535,  -535,  -535,  -535,     0,
       0,  -535,     0,  -535,  -535,  -535,   -91,     0,     0,  -535,
       0,  -535,  -535,  -535,  -535,  -535,  -535,     0,  -535,  -535,
       0,  -535,     0,     0,     0,     0,     0,  -535,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  -535,  -535,
       0,  -535,  -535,  -535,  -535,  -535,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  -535,  -535,  -535,  -535,  -535,  -535,  -535,
    -535,  -535,  -535,  -535,  -535,  -535,     0,     0,  -535,  -535,
    -535,     0,   717,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  -535,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  -535,     0,     0,  -535,  -535,     0,   -99,
    -535,     0,  -535,  -535,  -535,  -535,  -535,  -535,  -535,  -535,
    -535,  -535,     0,     0,  -279,     0,  -535,  -535,  -535,  -535,
       0,     0,  -535,     0,  -535,  -535,  -535,  -279,  -279,  -279,
       0,  -279,  -279,     0,  -279,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  -279,  -279,     0,  -279,  -279,  -279,  -279,  -279,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  -279,  -279,  -279,  -279,
    -279,  -279,  -279,  -279,  -279,  -279,  -279,  -279,  -279,     0,
       0,  -279,  -279,  -279,     0,   718,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  -279,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  -279,     0,     0,  -279,
    -279,     0,  -101,  -279,     0,  -279,  -279,  -279,  -279,  -279,
    -279,  -279,  -279,  -279,  -279,     0,     0,  -279,     0,     0,
    -279,  -279,   -93,     0,     0,  -279,     0,  -279,  -279,  -279,
    -279,  -279,  -279,     0,  -279,  -279,     0,  -279,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  -279,  -279,     0,  -279,  -279,  -279,
    -279,  -279,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  -279,
    -279,  -279,  -279,  -279,  -279,  -279,  -279,  -279,  -279,  -279,
    -279,  -279,     0,     0,  -279,  -279,  -279,     0,   718,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  -279,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  -279,
       0,     0,  -279,  -279,     0,  -101,  -279,     0,  -279,  -279,
    -279,  -279,  -279,  -279,  -279,  -279,  -279,  -279,     0,     0,
       0,     0,     0,  -279,  -279,  -279,     0,     0,  -279,     0,
    -279,  -279,  -279,   277,     0,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,  -559,  -559,  -559,     0,     0,
    -559,    15,     0,    16,    17,    18,    19,     0,     0,     0,
       0,     0,    20,    21,    22,    23,    24,    25,    26,     0,
       0,    27,     0,     0,     0,     0,     0,    28,     0,    30,
      31,    32,     0,    33,    34,    35,    36,    37,    38,     0,
      39,    40,    41,     0,     0,    42,     0,     0,     0,    43,
      44,     0,    45,    46,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    47,     0,     0,    48,    49,     0,    50,    51,
       0,    52,     0,    53,     0,    54,    55,    56,    57,    58,
      59,     0,     0,    60,  -559,     0,     0,  -559,  -559,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    61,    62,    63,     0,     0,     0,     0,
       0,     0,     0,     0,     0,  -559,   277,  -559,     5,     6,
       7,     8,     9,    10,    11,    12,    13,    14,     0,     0,
    -559,     0,  -559,  -559,    15,     0,    16,    17,    18,    19,
       0,     0,     0,     0,     0,    20,    21,    22,    23,    24,
      25,    26,     0,     0,    27,     0,     0,     0,     0,     0,
      28,     0,    30,    31,    32,     0,    33,    34,    35,    36,
      37,    38,     0,    39,    40,    41,     0,     0,    42,     0,
       0,     0,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    47,     0,     0,    48,    49,
       0,    50,    51,     0,    52,     0,    53,     0,    54,    55,
      56,    57,    58,    59,     0,     0,    60,  -559,     0,     0,
    -559,  -559,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    61,    62,    63,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  -559,   277,
    -559,     5,     6,     7,     8,     9,    10,    11,    12,    13,
      14,     0,     0,  -559,     0,     0,  -559,    15,  -559,    16,
      17,    18,    19,     0,     0,     0,     0,     0,    20,    21,
      22,    23,    24,    25,    26,     0,     0,    27,     0,     0,
       0,     0,     0,    28,     0,    30,    31,    32,     0,    33,
      34,    35,    36,    37,    38,     0,    39,    40,    41,     0,
       0,    42,     0,     0,     0,    43,    44,     0,    45,    46,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    47,     0,
       0,    48,    49,     0,    50,    51,     0,    52,     0,    53,
       0,    54,    55,    56,    57,    58,    59,     0,     0,    60,
    -559,     0,     0,  -559,  -559,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    61,
      62,    63,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  -559,   277,  -559,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,     0,     0,  -559,     0,     0,  -559,
      15,     0,    16,    17,    18,    19,     0,     0,     0,     0,
       0,    20,    21,    22,    23,    24,    25,    26,     0,     0,
      27,     0,     0,     0,     0,     0,    28,     0,    30,    31,
      32,     0,    33,    34,    35,    36,    37,    38,     0,    39,
      40,    41,     0,     0,    42,     0,     0,     0,    43,    44,
       0,    45,    46,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    47,     0,     0,    48,    49,     0,    50,    51,     0,
      52,     0,    53,     0,    54,    55,    56,    57,    58,    59,
       0,     0,    60,  -559,     0,     0,  -559,  -559,     4,     0,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
       0,     0,    61,    62,    63,     0,    15,     0,    16,    17,
      18,    19,     0,     0,  -559,     0,  -559,    20,    21,    22,
      23,    24,    25,    26,     0,     0,    27,     0,     0,     0,
       0,     0,    28,    29,    30,    31,    32,     0,    33,    34,
      35,    36,    37,    38,     0,    39,    40,    41,     0,     0,
      42,     0,     0,     0,    43,    44,     0,    45,    46,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    47,     0,     0,
      48,    49,     0,    50,    51,     0,    52,     0,    53,     0,
      54,    55,    56,    57,    58,    59,     0,     0,    60,  -559,
       0,     0,  -559,  -559,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    61,    62,
      63,     0,     0,  -559,     0,     0,     0,     0,     0,     0,
    -559,   277,  -559,     5,     6,     7,     8,     9,    10,    11,
      12,    13,    14,     0,  -559,  -559,     0,     0,     0,    15,
       0,    16,    17,    18,    19,     0,     0,     0,     0,     0,
      20,    21,    22,    23,    24,    25,    26,     0,     0,    27,
       0,     0,     0,     0,     0,    28,     0,    30,    31,    32,
       0,    33,    34,    35,    36,    37,    38,     0,    39,    40,
      41,     0,     0,    42,     0,     0,     0,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      47,     0,     0,    48,    49,     0,    50,    51,     0,    52,
       0,    53,     0,    54,    55,    56,    57,    58,    59,     0,
       0,    60,  -559,     0,     0,  -559,  -559,   277,     0,     5,
       6,     7,     8,     9,    10,    11,    12,    13,    14,     0,
       0,    61,    62,    63,     0,    15,     0,    16,    17,    18,
      19,     0,     0,  -559,     0,  -559,    20,    21,    22,    23,
      24,    25,    26,     0,     0,    27,     0,     0,     0,     0,
       0,    28,     0,    30,    31,    32,     0,    33,    34,    35,
      36,    37,    38,     0,    39,    40,    41,     0,     0,    42,
       0,     0,     0,    43,    44,     0,    45,    46,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    47,     0,     0,   278,
      49,     0,    50,    51,     0,    52,     0,    53,     0,    54,
      55,    56,    57,    58,    59,     0,     0,    60,  -559,     0,
       0,  -559,  -559,   277,     0,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,     0,     0,    61,    62,    63,
       0,    15,     0,    16,    17,    18,    19,  -559,     0,  -559,
       0,  -559,    20,    21,    22,    23,    24,    25,    26,     0,
       0,    27,     0,     0,     0,     0,     0,    28,     0,    30,
      31,    32,     0,    33,    34,    35,    36,    37,    38,     0,
      39,    40,    41,     0,     0,    42,     0,     0,     0,    43,
      44,     0,    45,    46,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    47,     0,     0,    48,    49,     0,    50,    51,
       0,    52,     0,    53,     0,    54,    55,    56,    57,    58,
      59,     0,     0,    60,  -559,     0,     0,  -559,  -559,   277,
       0,     5,     6,     7,     8,     9,    10,    11,    12,    13,
      14,     0,     0,    61,    62,    63,     0,    15,     0,    16,
      17,    18,    19,  -559,     0,  -559,     0,  -559,    20,    21,
      22,    23,    24,    25,    26,     0,     0,    27,     0,     0,
       0,     0,     0,    28,     0,    30,    31,    32,     0,    33,
      34,    35,    36,    37,    38,     0,    39,    40,    41,     0,
       0,    42,     0,     0,     0,    43,    44,     0,    45,    46,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    47,     0,
       0,    48,    49,     0,    50,    51,     0,    52,     0,    53,
       0,    54,    55,    56,    57,    58,    59,     0,     0,    60,
    -559,     0,     0,  -559,  -559,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    61,
      62,    63,     0,     0,  -559,     0,     0,     0,     0,     0,
       0,  -559,   277,  -559,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,     0,     0,  -559,     0,     0,     0,
      15,     0,    16,    17,    18,    19,     0,     0,     0,     0,
       0,    20,    21,    22,    23,    24,    25,    26,     0,     0,
      27,     0,     0,     0,     0,     0,    28,     0,    30,    31,
      32,     0,    33,    34,    35,    36,    37,    38,     0,    39,
      40,    41,     0,     0,    42,     0,     0,     0,    43,    44,
       0,    45,    46,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    47,     0,     0,    48,    49,     0,    50,    51,     0,
      52,     0,    53,     0,    54,    55,    56,    57,    58,    59,
       0,     0,    60,  -559,     0,     0,  -559,  -559,     0,     0,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
       0,     0,    61,    62,    63,     0,    15,     0,    16,    17,
      18,    19,     0,     0,  -559,     0,  -559,    20,    21,    22,
      23,    24,    25,    26,     0,     0,    27,     0,     0,     0,
       0,     0,    28,    29,    30,    31,    32,     0,    33,    34,
      35,    36,    37,    38,     0,    39,    40,    41,     0,     0,
      42,     0,     0,     0,    43,    44,     0,    45,    46,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    47,     0,     0,
      48,    49,     0,    50,    51,     0,    52,     0,    53,     0,
      54,    55,    56,    57,    58,    59,     0,     0,    60,   231,
       0,     0,   232,   233,     0,     0,     5,     6,     7,     8,
       9,    10,    11,    12,    13,    14,     0,     0,    61,    62,
      63,     0,    15,     0,    16,    17,    18,    19,     0,     0,
     234,     0,   235,    20,    21,    22,    23,    24,    25,    26,
       0,     0,    27,     0,     0,     0,     0,     0,    28,     0,
      30,    31,    32,     0,    33,    34,    35,    36,    37,    38,
       0,    39,    40,    41,     0,     0,    42,     0,     0,     0,
      43,    44,     0,    45,    46,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    47,     0,     0,    48,    49,     0,    50,
      51,     0,    52,     0,    53,     0,    54,    55,    56,    57,
      58,    59,     0,     0,    60,   231,     0,     0,   232,   233,
       0,     0,     5,     6,     7,     8,     9,    10,    11,    12,
      13,     0,     0,     0,    61,    62,    63,     0,    15,     0,
      16,    17,    18,    19,     0,     0,   234,     0,   235,    20,
      21,    22,    23,    24,    25,    26,     0,     0,    27,     0,
       0,     0,     0,     0,     0,     0,     0,    31,    32,     0,
      33,    34,    35,    36,    37,    38,     0,    39,    40,    41,
       0,     0,    42,     0,     0,     0,    43,    44,     0,    45,
      46,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   200,
       0,     0,   111,    49,     0,    50,    51,     0,     0,     0,
      53,     0,    54,    55,    56,    57,    58,    59,     0,     0,
      60,   231,     0,     0,   232,   233,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
      61,    62,    63,     0,    15,     0,    16,    17,    18,    19,
       0,     0,   234,     0,   235,    20,    21,    22,    23,    24,
      25,    26,     0,     0,    27,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,     0,    39,    40,    41,     0,     0,    42,     0,
       0,     0,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,     0,     0,    53,     0,    54,    55,
      56,    57,    58,    59,     0,     0,    60,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    61,    62,    63,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     235,   121,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,     0,     0,     0,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   154,     0,     0,
       0,     0,     0,   155,   156,   157,   158,   159,   160,   161,
     162,    35,    36,   163,    38,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   164,   165,
     166,   167,   168,   169,   170,   171,   172,     0,     0,   173,
     174,     0,     0,   175,   176,   177,   178,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   179,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   180,
     181,   182,   183,   184,   185,   186,   187,   188,   189,     0,
     190,   191,     0,     0,     0,     0,     0,   192,   193,  -528,
    -528,  -528,  -528,  -528,  -528,  -528,  -528,  -528,     0,     0,
       0,     0,     0,     0,     0,  -528,     0,  -528,  -528,  -528,
    -528,     0,  -528,     0,     0,     0,  -528,  -528,  -528,  -528,
    -528,  -528,  -528,     0,     0,  -528,     0,     0,     0,     0,
       0,     0,     0,     0,  -528,  -528,     0,  -528,  -528,  -528,
    -528,  -528,  -528,  -528,  -528,  -528,  -528,     0,     0,  -528,
       0,     0,  -528,  -528,  -528,     0,  -528,  -528,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  -528,     0,     0,  -528,
    -528,     0,  -528,  -528,     0,  -528,  -528,  -528,     0,  -528,
    -528,  -528,  -528,  -528,  -528,     0,     0,  -528,     0,     0,
       0,     0,     0,     0,  -530,  -530,  -530,  -530,  -530,  -530,
    -530,  -530,  -530,     0,     0,     0,     0,  -528,  -528,  -528,
    -530,  -528,  -530,  -530,  -530,  -530,  -528,  -530,     0,     0,
       0,  -530,  -530,  -530,  -530,  -530,  -530,  -530,     0,     0,
    -530,     0,     0,     0,     0,     0,     0,     0,     0,  -530,
    -530,     0,  -530,  -530,  -530,  -530,  -530,  -530,  -530,  -530,
    -530,  -530,     0,     0,  -530,     0,     0,  -530,  -530,  -530,
       0,  -530,  -530,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  -530,     0,     0,  -530,  -530,     0,  -530,  -530,     0,
    -530,  -530,  -530,     0,  -530,  -530,  -530,  -530,  -530,  -530,
       0,     0,  -530,     0,     0,     0,     0,     0,     0,  -529,
    -529,  -529,  -529,  -529,  -529,  -529,  -529,  -529,     0,     0,
       0,     0,  -530,  -530,  -530,  -529,  -530,  -529,  -529,  -529,
    -529,  -530,  -529,     0,     0,     0,  -529,  -529,  -529,  -529,
    -529,  -529,  -529,     0,     0,  -529,     0,     0,     0,     0,
       0,     0,     0,     0,  -529,  -529,     0,  -529,  -529,  -529,
    -529,  -529,  -529,  -529,  -529,  -529,  -529,     0,     0,  -529,
       0,     0,  -529,  -529,  -529,     0,  -529,  -529,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  -529,     0,     0,  -529,
    -529,     0,  -529,  -529,     0,  -529,  -529,  -529,     0,  -529,
    -529,  -529,  -529,  -529,  -529,     0,     0,  -529,     0,     0,
       0,     0,     0,     0,  -531,  -531,  -531,  -531,  -531,  -531,
    -531,  -531,  -531,     0,     0,     0,     0,  -529,  -529,  -529,
    -531,  -529,  -531,  -531,  -531,  -531,  -529,     0,     0,     0,
       0,  -531,  -531,  -531,  -531,  -531,  -531,  -531,     0,     0,
    -531,     0,     0,     0,     0,     0,     0,     0,     0,  -531,
    -531,     0,  -531,  -531,  -531,  -531,  -531,  -531,  -531,  -531,
    -531,  -531,     0,     0,  -531,     0,     0,  -531,  -531,  -531,
       0,  -531,  -531,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  -531,   752,     0,  -531,  -531,     0,  -531,  -531,     0,
    -531,  -531,  -531,     0,  -531,  -531,  -531,  -531,  -531,  -531,
       0,     0,  -531,     0,     0,     0,     0,     0,     0,   -99,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,  -531,  -531,  -531,     0,     0,     0,     0,     0,
       0,  -531,  -532,  -532,  -532,  -532,  -532,  -532,  -532,  -532,
    -532,     0,     0,     0,     0,     0,     0,     0,  -532,     0,
    -532,  -532,  -532,  -532,     0,     0,     0,     0,     0,  -532,
    -532,  -532,  -532,  -532,  -532,  -532,     0,     0,  -532,     0,
       0,     0,     0,     0,     0,     0,     0,  -532,  -532,     0,
    -532,  -532,  -532,  -532,  -532,  -532,  -532,  -532,  -532,  -532,
       0,     0,  -532,     0,     0,  -532,  -532,  -532,     0,  -532,
    -532,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  -532,
     753,     0,  -532,  -532,     0,  -532,  -532,     0,  -532,  -532,
    -532,     0,  -532,  -532,  -532,  -532,  -532,  -532,     0,     0,
    -532,     0,     0,     0,     0,     0,     0,  -101,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    -532,  -532,  -532,     0,     0,     0,     0,     0,     0,  -532,
    -249,  -249,  -249,  -249,  -249,  -249,  -249,  -249,  -249,     0,
       0,     0,     0,     0,     0,     0,  -249,     0,  -249,  -249,
    -249,  -249,     0,     0,     0,     0,     0,  -249,  -249,  -249,
    -249,  -249,  -249,  -249,     0,     0,  -249,     0,     0,     0,
       0,     0,     0,     0,     0,  -249,  -249,     0,  -249,  -249,
    -249,  -249,  -249,  -249,  -249,  -249,  -249,  -249,     0,     0,
    -249,     0,     0,  -249,  -249,  -249,     0,  -249,  -249,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  -249,     0,     0,
    -249,  -249,     0,  -249,  -249,     0,  -249,  -249,  -249,     0,
    -249,  -249,  -249,  -249,  -249,  -249,     0,     0,  -249,     0,
       0,     0,     0,     0,     0,  -533,  -533,  -533,  -533,  -533,
    -533,  -533,  -533,  -533,     0,     0,     0,     0,  -249,  -249,
    -249,  -533,     0,  -533,  -533,  -533,  -533,   259,     0,     0,
       0,     0,  -533,  -533,  -533,  -533,  -533,  -533,  -533,     0,
       0,  -533,     0,     0,     0,     0,     0,     0,     0,     0,
    -533,  -533,     0,  -533,  -533,  -533,  -533,  -533,  -533,  -533,
    -533,  -533,  -533,     0,     0,  -533,     0,     0,  -533,  -533,
    -533,     0,  -533,  -533,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,  -533,     0,     0,  -533,  -533,     0,  -533,  -533,
       0,  -533,  -533,  -533,     0,  -533,  -533,  -533,  -533,  -533,
    -533,     0,     0,  -533,     0,     0,     0,     0,     0,     0,
    -534,  -534,  -534,  -534,  -534,  -534,  -534,  -534,  -534,     0,
       0,     0,     0,  -533,  -533,  -533,  -534,     0,  -534,  -534,
    -534,  -534,  -533,     0,     0,     0,     0,  -534,  -534,  -534,
    -534,  -534,  -534,  -534,     0,     0,  -534,     0,     0,     0,
       0,     0,     0,     0,     0,  -534,  -534,     0,  -534,  -534,
    -534,  -534,  -534,  -534,  -534,  -534,  -534,  -534,     0,     0,
    -534,     0,     0,  -534,  -534,  -534,     0,  -534,  -534,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  -534,     0,     0,
    -534,  -534,     0,  -534,  -534,     0,  -534,  -534,  -534,     0,
    -534,  -534,  -534,  -534,  -534,  -534,     0,     0,  -534,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  -534,  -534,
    -534,     0,     0,     0,     0,     0,     0,  -534,   121,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,     0,     0,     0,   145,   146,   147,   218,   219,
     220,   221,   152,   153,   154,     0,     0,     0,     0,     0,
     155,   156,   157,   222,   223,   160,   224,   162,   302,   303,
     225,   304,     0,     0,     0,     0,     0,     0,   305,     0,
       0,     0,     0,     0,     0,   164,   165,   166,   167,   168,
     169,   170,   171,   172,     0,     0,   173,   174,     0,     0,
     175,   176,   177,   178,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   179,     0,     0,     0,     0,     0,
       0,     0,   306,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,     0,   190,   191,     0,
       0,     0,     0,     0,   192,   121,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   134,   135,
     136,   137,   138,   139,   140,   141,   142,   143,   144,     0,
       0,     0,   145,   146,   147,   218,   219,   220,   221,   152,
     153,   154,     0,     0,     0,     0,     0,   155,   156,   157,
     222,   223,   160,   224,   162,   302,   303,   225,   304,     0,
       0,     0,     0,     0,     0,   305,     0,     0,     0,     0,
       0,     0,   164,   165,   166,   167,   168,   169,   170,   171,
     172,     0,     0,   173,   174,     0,     0,   175,   176,   177,
     178,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   179,     0,     0,     0,     0,     0,     0,     0,   425,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   180,   181,   182,   183,   184,   185,   186,
     187,   188,   189,     0,   190,   191,     0,     0,     0,     0,
       0,   192,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,     0,     0,     0,   145,
     146,   147,   218,   219,   220,   221,   152,   153,   154,     0,
       0,     0,     0,     0,   155,   156,   157,   222,   223,   160,
     224,   162,     0,     0,   225,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   164,
     165,   166,   167,   168,   169,   170,   171,   172,     0,     0,
     173,   174,     0,     0,   175,   176,   177,   178,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   179,     0,
       0,     0,   226,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     180,   181,   182,   183,   184,   185,   186,   187,   188,   189,
       0,   190,   191,     0,     0,     0,     0,     0,   192,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,   143,   144,     0,     0,     0,   145,   146,   147,   218,
     219,   220,   221,   152,   153,   154,     0,     0,     0,     0,
       0,   155,   156,   157,   222,   223,   160,   224,   162,     0,
       0,   225,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   164,   165,   166,   167,
     168,   169,   170,   171,   172,     0,     0,   173,   174,     0,
       0,   175,   176,   177,   178,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   179,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   180,   181,   182,
     183,   184,   185,   186,   187,   188,   189,     0,   190,   191,
       0,     0,     0,     0,     0,   192,     5,     6,     7,     8,
       9,    10,    11,    12,    13,     0,     0,     0,     0,     0,
       0,     0,    15,     0,   101,   102,    18,    19,     0,     0,
       0,     0,     0,   103,   104,   105,    23,    24,    25,    26,
       0,     0,   106,     0,     0,     0,     0,     0,     0,     0,
       0,    31,    32,     0,    33,    34,    35,    36,    37,    38,
       0,    39,    40,    41,     0,     0,    42,     0,     0,     0,
      43,    44,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   295,     0,     0,   111,    49,     0,    50,
      51,     0,     0,     0,    53,     0,    54,    55,    56,    57,
      58,    59,     0,     0,    60,     0,     0,     5,     6,     7,
       8,     9,    10,    11,    12,    13,     0,     0,     0,     0,
       0,     0,     0,    15,   112,   101,   102,    18,    19,     0,
       0,   296,     0,     0,   103,   104,   105,    23,    24,    25,
      26,     0,     0,   106,     0,     0,     0,     0,     0,     0,
       0,     0,    31,    32,     0,    33,    34,    35,    36,    37,
      38,     0,    39,    40,    41,     0,     0,    42,     0,     0,
       0,    43,    44,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   295,     0,     0,   111,    49,     0,
      50,    51,     0,     0,     0,    53,     0,    54,    55,    56,
      57,    58,    59,     0,     0,    60,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,     0,     0,     0,    15,   112,   101,   102,    18,    19,
       0,     0,   540,     0,     0,   103,   104,   105,    23,    24,
      25,    26,     0,     0,   106,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,   244,    39,    40,    41,     0,     0,    42,     0,
       0,   245,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,     0,  -254,    53,     0,    54,    55,
      56,    57,   248,    59,     0,     0,    60,   231,     0,     0,
     232,   233,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,    14,     0,     0,     0,    61,   249,    63,    15,
       0,    16,    17,    18,    19,     0,     0,     0,     0,     0,
      20,    21,    22,    23,    24,    25,    26,     0,     0,    27,
       0,     0,     0,     0,     0,    28,    29,    30,    31,    32,
       0,    33,    34,    35,    36,    37,    38,     0,    39,    40,
      41,     0,     0,    42,     0,     0,     0,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      47,     0,     0,    48,    49,     0,    50,    51,     0,    52,
       0,    53,     0,    54,    55,    56,    57,    58,    59,     0,
       0,    60,     0,     0,     0,     0,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,    61,    62,    63,    15,     0,   101,   102,    18,    19,
       0,     0,     0,     0,     0,   103,   104,   105,    23,    24,
      25,    26,     0,     0,   106,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,   244,    39,    40,    41,     0,     0,    42,     0,
       0,   245,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,     0,     0,    53,     0,    54,    55,
      56,    57,   248,    59,     0,     0,    60,   231,     0,     0,
     232,   233,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,     0,     0,     0,     0,    61,   249,    63,    15,
       0,    16,    17,    18,    19,     0,     0,     0,     0,     0,
      20,    21,    22,    23,    24,    25,    26,     0,     0,   106,
       0,     0,     0,     0,     0,     0,     0,     0,    31,    32,
       0,    33,    34,    35,    36,    37,    38,   244,    39,    40,
      41,     0,     0,    42,     0,     0,   245,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     200,     0,     0,   111,    49,     0,    50,    51,     0,   246,
     247,    53,     0,    54,    55,    56,    57,   248,    59,     0,
       0,    60,     0,     0,     0,     0,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,    14,     0,     0,
       0,    61,   249,    63,    15,     0,    16,    17,    18,    19,
       0,     0,     0,     0,     0,    20,    21,    22,    23,    24,
      25,    26,     0,     0,    27,     0,     0,     0,     0,     0,
      28,     0,    30,    31,    32,     0,    33,    34,    35,    36,
      37,    38,     0,    39,    40,    41,     0,     0,    42,     0,
       0,     0,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    47,     0,     0,    48,    49,
       0,    50,    51,     0,    52,     0,    53,     0,    54,    55,
      56,    57,    58,    59,     0,     0,    60,     0,     0,     0,
       0,     0,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,     0,     0,     0,     0,    61,    62,    63,    15,
       0,   101,   102,    18,    19,     0,     0,     0,     0,     0,
     103,   104,   105,    23,    24,    25,    26,     0,     0,   106,
       0,     0,     0,     0,     0,     0,     0,     0,    31,    32,
       0,    33,    34,    35,    36,    37,    38,   244,    39,    40,
      41,     0,     0,    42,     0,     0,   245,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     200,     0,     0,   111,    49,     0,    50,    51,     0,   649,
     247,    53,     0,    54,    55,    56,    57,   248,    59,     0,
       0,    60,     0,     0,     0,     0,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,    61,   249,    63,    15,     0,   101,   102,    18,    19,
       0,     0,     0,     0,     0,   103,   104,   105,    23,    24,
      25,    26,     0,     0,   106,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,   244,    39,    40,    41,     0,     0,    42,     0,
       0,   245,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,   246,     0,    53,     0,    54,    55,
      56,    57,   248,    59,     0,     0,    60,     0,     0,     0,
       0,     0,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,     0,     0,     0,     0,    61,   249,    63,    15,
       0,   101,   102,    18,    19,     0,     0,     0,     0,     0,
     103,   104,   105,    23,    24,    25,    26,     0,     0,   106,
       0,     0,     0,     0,     0,     0,     0,     0,    31,    32,
       0,    33,    34,    35,    36,    37,    38,   244,    39,    40,
      41,     0,     0,    42,     0,     0,   245,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     200,     0,     0,   111,    49,     0,    50,    51,     0,   649,
       0,    53,     0,    54,    55,    56,    57,   248,    59,     0,
       0,    60,     0,     0,     0,     0,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,    61,   249,    63,    15,     0,   101,   102,    18,    19,
       0,     0,     0,     0,     0,   103,   104,   105,    23,    24,
      25,    26,     0,     0,   106,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,   244,    39,    40,    41,     0,     0,    42,     0,
       0,   245,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,     0,     0,    53,     0,    54,    55,
      56,    57,   248,    59,     0,     0,    60,     0,     0,     0,
       0,     0,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,     0,     0,     0,     0,    61,   249,    63,    15,
       0,    16,    17,    18,    19,     0,     0,     0,     0,     0,
      20,    21,    22,    23,    24,    25,    26,     0,     0,   106,
       0,     0,     0,     0,     0,     0,     0,     0,    31,    32,
       0,    33,    34,    35,    36,    37,    38,     0,    39,    40,
      41,     0,     0,    42,     0,     0,     0,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     200,     0,     0,   111,    49,     0,    50,    51,     0,   534,
       0,    53,     0,    54,    55,    56,    57,    58,    59,     0,
       0,    60,     0,     0,     0,     0,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,    61,   249,    63,    15,     0,   101,   102,    18,    19,
       0,     0,     0,     0,     0,   103,   104,   105,    23,    24,
      25,    26,     0,     0,   106,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,     0,    39,    40,    41,     0,     0,    42,     0,
       0,     0,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,   246,     0,    53,     0,    54,    55,
      56,    57,    58,    59,     0,     0,    60,     0,     0,     0,
       0,     0,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,     0,     0,     0,     0,    61,   249,    63,    15,
       0,   101,   102,    18,    19,     0,     0,     0,     0,     0,
     103,   104,   105,    23,    24,    25,    26,     0,     0,   106,
       0,     0,     0,     0,     0,     0,     0,     0,    31,    32,
       0,    33,    34,    35,    36,    37,    38,     0,    39,    40,
      41,     0,     0,    42,     0,     0,     0,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     200,     0,     0,   111,    49,     0,    50,    51,     0,   534,
       0,    53,     0,    54,    55,    56,    57,    58,    59,     0,
       0,    60,     0,     0,     0,     0,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,    61,   249,    63,    15,     0,   101,   102,    18,    19,
       0,     0,     0,     0,     0,   103,   104,   105,    23,    24,
      25,    26,     0,     0,   106,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,     0,    39,    40,    41,     0,     0,    42,     0,
       0,     0,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,   803,     0,    53,     0,    54,    55,
      56,    57,    58,    59,     0,     0,    60,     0,     0,     0,
       0,     0,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,     0,     0,     0,     0,    61,   249,    63,    15,
       0,   101,   102,    18,    19,     0,     0,     0,     0,     0,
     103,   104,   105,    23,    24,    25,    26,     0,     0,   106,
       0,     0,     0,     0,     0,     0,     0,     0,    31,    32,
       0,    33,    34,    35,    36,    37,    38,     0,    39,    40,
      41,     0,     0,    42,     0,     0,     0,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     200,     0,     0,   111,    49,     0,    50,    51,     0,   649,
       0,    53,     0,    54,    55,    56,    57,    58,    59,     0,
       0,    60,     0,     0,     0,     0,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,    61,   249,    63,    15,     0,    16,    17,    18,    19,
       0,     0,     0,     0,     0,    20,    21,    22,    23,    24,
      25,    26,     0,     0,    27,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,     0,    39,    40,    41,     0,     0,    42,     0,
       0,     0,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,     0,     0,    53,     0,    54,    55,
      56,    57,    58,    59,     0,     0,    60,     0,     0,     0,
       0,     0,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,     0,     0,     0,     0,    61,    62,    63,    15,
       0,   101,   102,    18,    19,     0,     0,     0,     0,     0,
     103,   104,   105,    23,    24,    25,    26,     0,     0,   106,
       0,     0,     0,     0,     0,     0,     0,     0,    31,    32,
       0,    33,    34,    35,    36,    37,    38,     0,    39,    40,
      41,     0,     0,    42,     0,     0,     0,    43,    44,     0,
      45,    46,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     200,     0,     0,   111,    49,     0,    50,    51,     0,     0,
       0,    53,     0,    54,    55,    56,    57,    58,    59,     0,
       0,    60,     0,     0,     0,     0,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,    61,   249,    63,    15,     0,    16,    17,    18,    19,
       0,     0,     0,     0,     0,    20,    21,    22,    23,    24,
      25,    26,     0,     0,   106,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,     0,    39,    40,    41,     0,     0,    42,     0,
       0,     0,    43,    44,     0,    45,    46,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   200,     0,     0,   111,    49,
       0,    50,    51,     0,     0,     0,    53,     0,    54,    55,
      56,    57,    58,    59,     0,     0,    60,     0,     0,     0,
       0,     0,     0,     5,     6,     7,     8,     9,    10,    11,
      12,    13,     0,     0,     0,     0,    61,   249,    63,    15,
       0,   101,   102,    18,    19,     0,     0,     0,     0,     0,
     103,   104,   105,    23,    24,    25,    26,     0,     0,   106,
       0,     0,     0,     0,     0,     0,     0,     0,    31,    32,
       0,   107,    34,    35,    36,   108,    38,     0,    39,    40,
      41,     0,     0,    42,     0,     0,     0,    43,    44,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   109,     0,     0,
     110,     0,     0,   111,    49,     0,    50,    51,     0,     0,
       0,    53,     0,    54,    55,    56,    57,    58,    59,     0,
       0,    60,     0,     0,     5,     6,     7,     8,     9,    10,
      11,    12,    13,     0,     0,     0,     0,     0,     0,     0,
      15,   112,   101,   102,    18,    19,     0,     0,     0,     0,
       0,   103,   104,   105,    23,    24,    25,    26,     0,     0,
     106,     0,     0,     0,     0,     0,     0,     0,     0,    31,
      32,     0,    33,    34,    35,    36,    37,    38,     0,    39,
      40,    41,     0,     0,    42,     0,     0,     0,    43,    44,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   211,     0,     0,    48,    49,     0,    50,    51,     0,
      52,     0,    53,     0,    54,    55,    56,    57,    58,    59,
       0,     0,    60,     0,     0,     5,     6,     7,     8,     9,
      10,    11,    12,    13,     0,     0,     0,     0,     0,     0,
       0,    15,   112,   101,   102,    18,    19,     0,     0,     0,
       0,     0,   103,   104,   105,    23,    24,    25,    26,     0,
       0,   106,     0,     0,     0,     0,     0,     0,     0,     0,
      31,    32,     0,    33,    34,    35,    36,    37,    38,     0,
      39,    40,    41,     0,     0,    42,     0,     0,     0,    43,
      44,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   295,     0,     0,   342,    49,     0,    50,    51,
       0,   343,     0,    53,     0,    54,    55,    56,    57,    58,
      59,     0,     0,    60,     0,     0,     5,     6,     7,     8,
       9,    10,    11,    12,    13,     0,     0,     0,     0,     0,
       0,     0,    15,   112,   101,   102,    18,    19,     0,     0,
       0,     0,     0,   103,   104,   105,    23,    24,    25,    26,
       0,     0,   106,     0,     0,     0,     0,     0,     0,     0,
       0,    31,    32,     0,   107,    34,    35,    36,   108,    38,
       0,    39,    40,    41,     0,     0,    42,     0,     0,     0,
      43,    44,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   110,     0,     0,   111,    49,     0,    50,
      51,     0,     0,     0,    53,     0,    54,    55,    56,    57,
      58,    59,     0,     0,    60,     0,     0,     5,     6,     7,
       8,     9,    10,    11,    12,    13,     0,     0,     0,     0,
       0,     0,     0,    15,   112,   101,   102,    18,    19,     0,
       0,     0,     0,     0,   103,   104,   105,    23,    24,    25,
      26,     0,     0,   106,     0,     0,     0,     0,     0,     0,
       0,     0,    31,    32,     0,    33,    34,    35,    36,    37,
      38,     0,    39,    40,    41,     0,     0,    42,     0,     0,
       0,    43,    44,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   295,     0,     0,   342,    49,     0,
      50,    51,     0,     0,     0,    53,     0,    54,    55,    56,
      57,    58,    59,     0,     0,    60,     0,     0,     5,     6,
       7,     8,     9,    10,    11,    12,    13,     0,     0,     0,
       0,     0,     0,     0,    15,   112,   101,   102,    18,    19,
       0,     0,     0,     0,     0,   103,   104,   105,    23,    24,
      25,    26,     0,     0,   106,     0,     0,     0,     0,     0,
       0,     0,     0,    31,    32,     0,    33,    34,    35,    36,
      37,    38,     0,    39,    40,    41,     0,     0,    42,     0,
       0,     0,    43,    44,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   877,     0,     0,   111,    49,
       0,    50,    51,     0,     0,     0,    53,     0,    54,    55,
      56,    57,    58,    59,     0,     0,    60,     0,     0,     5,
       6,     7,     8,     9,    10,    11,    12,    13,     0,     0,
       0,     0,     0,     0,     0,    15,   112,   101,   102,    18,
      19,     0,     0,     0,     0,     0,   103,   104,   105,    23,
      24,    25,    26,     0,     0,   106,     0,     0,     0,     0,
       0,     0,     0,     0,    31,    32,     0,    33,    34,    35,
      36,    37,    38,     0,    39,    40,    41,     0,     0,    42,
       0,     0,     0,    43,    44,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   896,     0,     0,   111,
      49,     0,    50,    51,   578,   579,     0,    53,   580,    54,
      55,    56,    57,    58,    59,     0,     0,    60,     0,     0,
       0,     0,     0,   164,   165,   166,   167,   168,   169,   170,
     171,   172,     0,     0,   173,   174,     0,   112,   175,   176,
     177,   178,     0,     0,     0,   346,  -560,  -560,  -560,  -560,
     351,   352,   179,     0,  -560,  -560,     0,     0,     0,     0,
     359,   360,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   180,   181,   182,   183,   184,   185,
     186,   187,   188,   189,     0,   190,   191,   586,   587,     0,
       0,   588,   192,   259,   362,   363,   364,   365,   366,   367,
     368,   369,   370,   371,     0,     0,   164,   165,   166,   167,
     168,   169,   170,   171,   172,     0,     0,   173,   174,     0,
       0,   175,   176,   177,   178,     0,     0,     0,   346,   347,
     348,   349,   350,   351,   352,   179,     0,   355,   356,     0,
       0,     0,     0,   359,   360,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   180,   181,   182,
     183,   184,   185,   186,   187,   188,   189,     0,   190,   191,
     607,   579,     0,     0,   608,   192,   259,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,     0,     0,   164,
     165,   166,   167,   168,   169,   170,   171,   172,     0,     0,
     173,   174,     0,     0,   175,   176,   177,   178,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   179,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     180,   181,   182,   183,   184,   185,   186,   187,   188,   189,
       0,   190,   191,   592,   587,     0,     0,   593,   192,   259,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   164,   165,   166,   167,   168,   169,   170,   171,
     172,     0,     0,   173,   174,     0,     0,   175,   176,   177,
     178,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   179,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   180,   181,   182,   183,   184,   185,   186,
     187,   188,   189,     0,   190,   191,   623,   579,     0,     0,
     624,   192,   259,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   164,   165,   166,   167,   168,
     169,   170,   171,   172,     0,     0,   173,   174,     0,     0,
     175,   176,   177,   178,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   179,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,     0,   190,   191,   626,
     587,     0,     0,   627,   192,   259,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   164,   165,
     166,   167,   168,   169,   170,   171,   172,     0,     0,   173,
     174,     0,     0,   175,   176,   177,   178,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   179,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   180,
     181,   182,   183,   184,   185,   186,   187,   188,   189,     0,
     190,   191,   633,   579,     0,     0,   634,   192,   259,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   164,   165,   166,   167,   168,   169,   170,   171,   172,
       0,     0,   173,   174,     0,     0,   175,   176,   177,   178,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     179,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   180,   181,   182,   183,   184,   185,   186,   187,
     188,   189,     0,   190,   191,   636,   587,     0,     0,   637,
     192,   259,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   164,   165,   166,   167,   168,   169,
     170,   171,   172,     0,     0,   173,   174,     0,     0,   175,
     176,   177,   178,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   179,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,     0,   190,   191,   670,   579,
       0,     0,   671,   192,   259,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   164,   165,   166,
     167,   168,   169,   170,   171,   172,     0,     0,   173,   174,
       0,     0,   175,   176,   177,   178,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   179,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   180,   181,
     182,   183,   184,   185,   186,   187,   188,   189,     0,   190,
     191,   673,   587,     0,     0,   674,   192,   259,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     164,   165,   166,   167,   168,   169,   170,   171,   172,     0,
       0,   173,   174,     0,     0,   175,   176,   177,   178,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   179,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   180,   181,   182,   183,   184,   185,   186,   187,   188,
     189,     0,   190,   191,   808,   579,     0,     0,   809,   192,
     259,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   164,   165,   166,   167,   168,   169,   170,
     171,   172,     0,     0,   173,   174,     0,     0,   175,   176,
     177,   178,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   179,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   180,   181,   182,   183,   184,   185,
     186,   187,   188,   189,     0,   190,   191,   811,   587,     0,
       0,   812,   192,   259,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   164,   165,   166,   167,
     168,   169,   170,   171,   172,     0,     0,   173,   174,     0,
       0,   175,   176,   177,   178,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   179,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   180,   181,   182,
     183,   184,   185,   186,   187,   188,   189,     0,   190,   191,
     956,   579,     0,     0,   957,   192,   259,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   164,
     165,   166,   167,   168,   169,   170,   171,   172,     0,     0,
     173,   174,     0,     0,   175,   176,   177,   178,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   179,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     180,   181,   182,   183,   184,   185,   186,   187,   188,   189,
       0,   190,   191,   963,   579,     0,     0,   964,   192,   259,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   164,   165,   166,   167,   168,   169,   170,   171,
     172,     0,     0,   173,   174,     0,     0,   175,   176,   177,
     178,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   179,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   180,   181,   182,   183,   184,   185,   186,
     187,   188,   189,     0,   190,   191,   966,   587,     0,     0,
     967,   192,   259,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   164,   165,   166,   167,   168,
     169,   170,   171,   172,     0,     0,   173,   174,     0,     0,
     175,   176,   177,   178,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   179,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   180,   181,   182,   183,
     184,   185,   186,   187,   188,   189,     0,   190,   191,   592,
     587,     0,     0,   593,   192,   259,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   164,   165,
     166,   167,   168,   169,   170,   171,   172,     0,     0,   173,
     174,     0,     0,   175,   176,   177,   178,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   179,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     712,     0,     0,     0,     0,     0,     0,     0,     0,   180,
     181,   182,   183,   184,   185,   186,   187,   188,   189,     0,
     190,   191,     0,     0,     0,     0,     0,   192,   346,   347,
     348,   349,   350,   351,   352,   353,   354,   355,   356,   357,
     358,     0,     0,   359,   360,   346,   347,   348,   349,   350,
     351,   352,   353,   354,   355,   356,   357,   358,     0,     0,
     359,   360,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   361,     0,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,     0,     0,     0,
       0,     0,   361,     0,   362,   363,   364,   365,   366,   367,
     368,   369,   370,   371,     0,     0,     0,     0,     0,     0,
       0,  -256,   346,   347,   348,   349,   350,   351,   352,   353,
     354,   355,   356,   357,   358,     0,     0,   359,   360,     0,
     346,   347,   348,   349,   350,   351,   352,   353,   354,   355,
     356,   357,   358,     0,     0,   359,   360,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   361,
       0,   362,   363,   364,   365,   366,   367,   368,   369,   370,
     371,     0,     0,     0,     0,     0,     0,   361,  -257,   362,
     363,   364,   365,   366,   367,   368,   369,   370,   371,     0,
       0,     0,     0,     0,     0,     0,  -258,   346,   347,   348,
     349,   350,   351,   352,   353,   354,   355,   356,   357,   358,
       0,     0,   359,   360,     0,   346,   347,   348,   349,   350,
     351,   352,   353,   354,   355,   356,   357,   358,     0,     0,
     359,   360,     0,     0,     0,   440,     0,     0,     0,     0,
       0,     0,     0,     0,   361,     0,   362,   363,   364,   365,
     366,   367,   368,   369,   370,   371,     0,     0,     0,     0,
       0,     0,   361,  -259,   362,   363,   364,   365,   366,   367,
     368,   369,   370,   371,   346,   347,   348,   349,   350,   351,
     352,   353,   354,   355,   356,   357,   358,     0,     0,   359,
     360,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,  -560,  -560,     0,     0,   359,   360,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   361,     0,   362,   363,   364,   365,   366,   367,   368,
     369,   370,   371,     0,     0,     0,     0,     0,     0,     0,
     362,   363,   364,   365,   366,   367,   368,   369,   370,   371
};

static const yytype_int16 yycheck[] =
{
       2,    83,    62,    27,    16,    17,    81,    82,    20,   208,
     255,     7,     7,    21,    22,   399,   289,    14,    14,    21,
     293,     5,     6,   313,   296,   428,    48,   611,    10,    13,
     110,    28,    28,    15,    22,    52,    16,    17,    28,   301,
      20,   625,   419,     4,   345,   619,   445,   484,    50,    51,
      65,   635,   383,   384,   628,   701,    16,    17,    54,    54,
      20,   778,   443,     2,   301,     4,   447,   689,    52,   685,
      50,    51,    65,   689,    80,   595,   596,    76,    27,    56,
      57,    58,    59,    15,   685,   701,    26,    16,   672,    26,
      98,   701,    76,   278,    25,    25,   104,   105,   374,   879,
      25,   776,   104,   540,    25,   141,   861,    29,    91,   145,
      98,   119,   112,    89,    89,   115,   116,   123,     9,    10,
     118,   397,    72,    91,    15,   254,   102,    25,    25,   204,
      37,    38,    25,    65,    18,   118,    20,   413,   345,   214,
     138,   141,   142,    58,    59,   145,   422,    25,   720,   372,
     118,   441,     0,   376,   726,   445,   379,   342,    48,   288,
     289,   137,   135,   112,   293,    91,   115,   116,   144,   144,
      16,    17,   952,    25,    20,   398,   383,   384,   128,   129,
     130,    51,   857,   112,   794,    55,   115,   116,   110,   412,
     945,   414,   118,   910,   143,   135,   145,   118,   135,   274,
     423,    37,    38,   140,    50,    55,   451,   138,   138,   138,
     486,   731,   484,   138,   143,    25,   145,   138,   109,   140,
     141,   111,   606,   298,   145,   515,   810,   209,   210,   875,
     226,   226,    15,   879,    58,    59,   498,   912,   145,   462,
     138,   138,   864,   236,    16,   138,    89,   259,   864,    28,
      89,   263,   254,   255,    89,    89,   278,   259,   657,   875,
     138,   498,   140,   879,   487,   280,    91,   868,   540,   944,
     202,   248,   709,   118,   875,   656,   208,    89,    89,   853,
     340,   138,    65,   263,    89,   345,   138,   280,   140,   314,
     102,   102,   317,   118,   319,    91,   321,   296,   323,    89,
      91,   144,   140,   263,   236,   144,   952,   145,   118,   144,
     144,   243,   296,   138,    91,    89,   396,   618,   209,   210,
     342,   450,   118,   383,   384,   137,   343,   118,   138,   306,
     138,   141,   144,   144,    89,   145,   952,   145,   277,   144,
     112,   118,   138,   115,   116,   118,   285,   138,   280,   331,
     332,   333,   334,    91,   144,   739,   288,   289,   648,   343,
      61,   293,   374,    64,    65,   655,   122,   657,   376,   330,
     144,   143,   374,   145,    17,    18,   267,   268,   615,   140,
     376,   965,   272,   379,   761,   397,   717,   140,   278,   144,
     398,   330,   723,   724,   667,   397,   335,    55,   330,    91,
     118,   413,   398,    89,   406,    55,   414,   652,   537,    91,
     422,   413,   113,   114,   439,   423,   102,   263,   414,    25,
     422,     2,    16,     4,     5,     6,   118,   423,     9,    10,
      25,   138,    13,    20,    15,    16,    17,   709,   714,    20,
     331,   332,   333,   334,   643,   336,   337,   831,   450,   451,
     853,   137,   342,   236,   462,   854,   591,   459,   144,   594,
     243,   458,   458,   443,   701,   138,   462,    48,   458,    91,
      26,    52,   145,   138,   486,   550,   738,   612,    16,   487,
     145,    62,   138,   482,   486,   484,   418,   419,   513,   820,
     713,   487,   715,   473,   340,    76,   118,   280,   482,   345,
     484,   738,   504,   138,   711,   507,   135,   509,    72,   400,
     717,   895,   118,    91,   643,    91,   723,   724,   112,   409,
     459,   115,   116,    91,   141,   770,    91,   417,   109,   468,
     111,   533,   138,    89,   145,   141,   468,   427,   667,   145,
     118,   540,   118,   567,   118,   142,   102,   330,   136,   143,
     118,   145,    55,   118,    25,   138,   540,    62,    72,    64,
      65,   585,    26,    72,   854,   282,   138,    89,    51,   286,
      53,    54,    55,    56,   112,   583,    72,   115,   116,   135,
     102,   137,    15,   591,   140,   431,   594,   611,   144,   591,
     493,    98,   594,   595,   596,   583,    13,    16,    63,    15,
     837,   625,   610,   591,   612,   143,   594,   145,   113,   114,
     612,   635,    26,   820,    91,   137,   618,   619,   199,   621,
     616,   616,   144,   605,   514,    89,   628,   100,   209,   210,
     126,   127,   128,   129,   130,   418,   419,   138,   102,   138,
     839,   118,   639,   639,   141,   727,   845,   118,   672,   639,
     652,   711,    91,    89,   136,   138,   638,   717,   718,   683,
     138,   138,   938,   723,   724,    61,   102,   138,    64,    65,
     141,   135,   604,   137,   145,    89,   656,   701,   259,   118,
     144,   118,   263,   138,   138,   468,   267,   268,   102,    51,
      51,   272,    53,    54,    55,    56,   277,   278,   138,   138,
      51,   137,   714,   138,   285,    44,    26,   715,   144,   118,
     709,   643,   714,    15,   605,   296,   939,   113,   114,   715,
      18,   135,    15,   137,   112,   709,   140,   115,   116,   731,
     144,   448,   136,    89,   136,   667,    51,   454,    53,    54,
      55,    56,   744,   138,    89,   747,   102,   638,   465,   330,
     331,   332,   333,   334,   335,   336,   337,   102,   136,   340,
     820,   342,   343,   120,   345,   142,    15,   749,   770,    89,
     794,   710,   618,    92,   677,   678,   112,   138,    89,   115,
     116,   137,   102,    89,   786,   787,   810,   789,   144,   791,
     792,   102,   137,   374,   796,   140,   102,   799,   800,   144,
      14,   733,   383,   384,    15,    15,   138,   143,   740,   145,
     383,   384,   702,   797,   138,   135,   397,   137,   399,   400,
     140,   604,   539,   898,   144,    91,   137,   141,   409,   761,
     143,   137,   413,   144,    89,   138,   417,   138,   144,   729,
     730,   422,   415,   416,   138,   123,   427,   102,    63,    64,
      65,   853,   118,   138,   838,   138,   746,   138,   749,   138,
      51,    15,    53,    54,    55,    56,    15,    89,   758,   759,
      15,   136,   138,   776,    15,   778,   766,    15,   459,   138,
     102,   112,   137,    15,   115,   116,   136,   468,   123,   144,
     463,   915,   782,   783,    63,    64,    65,   614,   113,   114,
      55,   482,    93,   484,   136,   486,    15,   839,    99,   100,
     138,    55,    89,   845,    62,   137,    64,    65,   920,   921,
     922,   923,   144,   925,   926,   102,   938,   929,    15,   931,
     932,   939,    72,   514,   125,   138,   938,   128,   940,   941,
     830,   965,   138,   939,   113,   114,   138,    87,    88,   666,
     733,   138,   842,    15,   857,   858,   140,   740,   140,   540,
     137,   459,   138,    13,   681,   113,   114,   144,     6,   941,
     728,   973,   974,   975,   976,   977,   945,    51,   761,    53,
      54,    55,    56,   985,   677,   125,   126,   127,   128,   129,
     130,   507,   940,   509,   238,   313,     7,    16,    17,   875,
      51,    20,    53,    54,    55,    56,   837,   910,   685,   912,
      -1,   901,    -1,   903,    72,    -1,   906,    -1,    51,    93,
      53,    54,    55,    56,   605,   606,    45,    46,    -1,    87,
      88,    50,    51,    89,    51,    -1,    53,    54,    55,    56,
      -1,   944,    93,    62,    63,    -1,   102,    -1,    99,   100,
      89,    51,    -1,    53,    54,    55,    56,   638,   775,    -1,
      93,    -1,    -1,   102,    -1,    -1,    99,   100,   126,   127,
     128,   129,   130,    -1,   125,    -1,    93,   128,    -1,    -1,
      -1,   137,    99,   100,    63,    64,    65,    66,   144,    63,
      64,    65,   125,    93,   145,   128,    -1,    -1,   137,    51,
     100,    53,    54,    55,    56,   144,    -1,   140,   125,    -1,
     689,   128,    -1,   692,    -1,    -1,    -1,   834,    -1,    -1,
      -1,   702,   701,   140,    -1,   125,    -1,    -1,   709,   710,
     711,    -1,    -1,   714,   113,   114,   717,   718,    72,   113,
     114,    93,   723,   724,   717,   718,    -1,    99,   729,   730,
     723,   724,    -1,    87,    88,    -1,    -1,    -1,   739,     2,
      -1,     4,     5,     6,    -1,   746,    -1,    -1,   749,    -1,
      13,    63,    64,    65,    66,    -1,    -1,   758,   759,   752,
     753,    -1,   755,   756,    -1,   766,    63,    64,    65,   123,
     124,   125,   126,   127,   128,   129,   130,    -1,    -1,    -1,
      -1,   782,   783,    -1,    -1,    48,    -1,    -1,    -1,    52,
      40,    41,    42,    43,    44,    -1,   797,    -1,    -1,    -1,
      -1,   113,   114,    -1,    -1,   244,   245,   246,   247,    -1,
     249,    -1,    -1,    76,    -1,    -1,   113,   114,    -1,   820,
     259,    -1,    -1,    -1,   263,    -1,    -1,   820,    -1,   830,
     831,    -1,     2,    -1,     4,    -1,    -1,   838,    63,    64,
      65,   842,    -1,    13,    -1,    63,    64,    65,   111,    -1,
     786,   787,    -1,   789,   847,   791,   792,    -1,    -1,    -1,
     796,    -1,    -1,   799,   800,   864,    -1,   866,    -1,    -1,
      -1,   870,    -1,    -1,    -1,    -1,    -1,    -1,    48,    -1,
     879,    -1,   881,    63,    64,    65,    -1,    -1,   113,   114,
      -1,    -1,    -1,    -1,   895,   113,   114,    63,    64,    65,
     901,   340,   903,    -1,    -1,   906,   345,   346,   347,   348,
     349,   350,   351,   352,   353,   354,   355,   356,   357,   358,
     359,   360,   361,   362,   363,   364,   365,   366,   367,   368,
     369,   370,   371,   113,   114,   374,   199,   938,    -1,    -1,
      -1,   111,    -1,    -1,   383,   384,    -1,   113,   114,   948,
      -1,    -1,    -1,   952,    -1,   954,    -1,    -1,   397,    -1,
     959,    -1,     2,    -1,     4,     5,     6,     7,    -1,    -1,
      -1,    -1,   411,    13,   413,    -1,   415,   416,    -1,    -1,
      -1,    -1,   981,   422,   920,   921,   922,   923,    -1,   925,
     926,    -1,   431,   929,    -1,   931,   932,    -1,    -1,   438,
      -1,   440,    -1,    -1,   443,    -1,   445,    -1,    48,   272,
      -1,    -1,    52,    -1,   277,   278,    51,    -1,    53,    54,
      55,    56,   285,    -1,   463,    -1,    -1,    -1,    -1,   199,
      -1,    -1,    -1,   296,   473,    -1,    76,   973,   974,   975,
     976,   977,    -1,    -1,    -1,    -1,    -1,   486,    -1,   985,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    93,    -1,
      -1,    -1,    -1,    -1,    99,    -1,   505,   330,    -1,    -1,
      -1,   111,   335,    -1,    -1,    -1,    -1,    -1,    -1,   342,
     343,    -1,   345,    -1,   523,   524,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   534,    -1,    -1,    -1,    -1,
      -1,    -1,   272,    -1,    -1,    -1,    -1,   277,   278,    -1,
      -1,    -1,    -1,    -1,    -1,   285,    -1,    -1,    -1,    -1,
     383,   384,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   399,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   409,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   417,    -1,    -1,    -1,    -1,   199,
     330,    -1,    -1,    -1,   427,   335,    -1,    -1,    -1,    -1,
      -1,    -1,   342,    -1,    -1,   345,    -1,    -1,    -1,   618,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   459,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   468,    -1,   646,    -1,     2,
     649,     4,    -1,   383,   384,    -1,    -1,   656,   657,   482,
      -1,   484,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   399,
      -1,    -1,   272,    -1,    -1,    -1,    -1,   277,   278,   409,
      -1,    -1,    -1,    -1,    -1,   285,    -1,   417,    -1,    -1,
      -1,   514,    -1,    -1,    -1,    48,   296,   427,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   706,    -1,    -1,
      -1,    -1,   711,   712,    -1,   714,    -1,   540,   717,   718,
      -1,    -1,    -1,    -1,   723,   724,    -1,    -1,    -1,   459,
     330,    -1,    -1,    -1,    -1,   335,    -1,    -1,   468,    -1,
      -1,    -1,   342,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   752,   753,    -1,   755,   756,   111,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   765,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   606,   514,    72,    73,    74,    75,    76,
      77,    78,    79,    80,    81,    82,    83,    84,    -1,   399,
      87,    88,    -1,    -1,   803,    -1,    -1,    -1,    -1,   409,
      -1,    -1,    -1,    -1,   813,    -1,    -1,   417,    -1,    -1,
      -1,   820,    -1,    -1,    -1,    -1,    -1,   427,    -1,    -1,
      -1,    -1,   119,    -1,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   130,    -1,    -1,   199,    -1,   847,    -1,
      -1,    -1,    -1,    -1,    -1,   854,    -1,    -1,   145,   459,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   468,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   606,    -1,    -1,   702,
      -1,    -1,   482,    -1,   484,    -1,   709,   710,   711,    -1,
      -1,    -1,    -1,    -1,   717,    -1,    -1,    -1,    -1,    -1,
     723,   724,    -1,    -1,    -1,    -1,   729,   730,    -1,    -1,
      -1,    -1,    -1,    -1,   514,    -1,   739,    -1,    -1,   272,
      -1,    -1,    -1,   746,   277,   278,    -1,    -1,    -1,    -1,
      -1,    -1,   285,    -1,    -1,   758,   759,    -1,    -1,   938,
     540,    -1,    -1,   766,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   782,
     783,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   702,    -1,   797,    -1,    -1,   330,    -1,    -1,
     710,   711,   335,    -1,    -1,    -1,    -1,   717,    -1,   342,
      -1,    -1,   345,   723,   724,    -1,    -1,   820,    -1,   729,
     730,    -1,    -1,    -1,    -1,    -1,   606,   830,   831,   739,
      -1,    -1,    -1,    -1,    -1,   838,   746,    -1,    -1,   842,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   758,   759,
     383,   384,    -1,    -1,    -1,    -1,   766,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   399,    -1,    -1,    -1,
      -1,    -1,   782,   783,    -1,    -1,   409,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   417,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   895,    -1,   427,    -1,    -1,    -1,   901,    -1,
     903,    -1,    -1,   906,    -1,    -1,    -1,    -1,    -1,    -1,
     820,    -1,    -1,    -1,    -1,    -1,     5,     6,    -1,    -1,
     830,   831,   702,    -1,    13,    -1,   459,    -1,   838,   709,
     710,    -1,   842,    -1,    -1,   468,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   729,
     730,    -1,    -1,    -1,    -1,    -1,    45,    46,    -1,   739,
      -1,    50,    51,    52,    -1,    -1,   746,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    63,    -1,    -1,    -1,   758,   759,
      -1,   514,    -1,    -1,    -1,   895,   766,    76,    -1,    -1,
      -1,   901,     0,   903,    -1,    -1,   906,    -1,    -1,    -1,
      -1,    -1,   782,   783,    -1,    13,    14,    15,    16,    17,
      18,    -1,    20,    -1,    -1,    -1,    -1,   797,    26,    27,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    37,
      38,    -1,    40,    41,    42,    43,    44,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     830,   831,    -1,    -1,    -1,    -1,    -1,    -1,   838,    -1,
      -1,    -1,   842,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   606,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    89,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   102,    -1,    72,    73,    74,    75,
      76,    77,    78,    79,   112,    81,    82,   115,   116,    -1,
      -1,    87,    88,    -1,    -1,   895,    -1,    -1,    -1,    -1,
      -1,   901,    -1,   903,    -1,    -1,   906,   135,   136,    -1,
      -1,    -1,   140,   141,    -1,   143,   144,   145,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   121,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   244,   245,   246,   247,    -1,
     249,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   702,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   710,   711,    -1,
      -1,    -1,    -1,    -1,   717,    -1,    -1,    -1,    -1,    -1,
     723,   724,    -1,    -1,    -1,    -1,   729,   730,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   739,   296,    -1,    -1,
      -1,    -1,    -1,   746,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   758,   759,    -1,    -1,    -1,
      -1,    -1,    -1,   766,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   782,
     783,    -1,    -1,    -1,   343,    -1,    -1,   346,   347,   348,
     349,   350,   351,   352,   353,   354,   355,   356,   357,   358,
     359,   360,   361,   362,   363,   364,   365,   366,   367,   368,
     369,   370,   371,    -1,    -1,    -1,    -1,   820,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   830,   831,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   842,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   411,    -1,    -1,    -1,   415,   416,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   431,    -1,    -1,    -1,    -1,    -1,    -1,   438,
      -1,   440,    -1,    -1,   443,    -1,   445,    -1,    -1,    -1,
      -1,    -1,   895,    -1,    -1,    -1,    -1,    -1,   901,    -1,
     903,    -1,    -1,   906,   463,    44,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   473,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   482,    -1,   484,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    72,    73,    74,    75,    76,    77,    78,
      79,    80,    81,    82,    83,    84,   505,    -1,    87,    88,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   523,   524,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   534,    -1,    -1,    -1,    -1,
     119,   540,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   138,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     0,
       1,    -1,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    12,    -1,    -1,    -1,    -1,    -1,    -1,    19,    -1,
      21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,    30,
      31,    32,    33,    34,    35,    36,    -1,    -1,    39,    -1,
      -1,    -1,    -1,    -1,    45,    46,    47,    48,    49,   618,
      51,    52,    53,    54,    55,    56,    -1,    58,    59,    60,
      -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,    70,
      71,    -1,    -1,    -1,    -1,    -1,    -1,   646,    -1,    -1,
     649,    -1,    -1,    -1,    -1,    -1,    -1,   656,   657,    90,
      -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,    -1,
     101,    -1,   103,   104,   105,   106,   107,   108,    -1,    -1,
     111,   112,    -1,    -1,   115,   116,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     131,   132,   133,    -1,    -1,    -1,    -1,   706,    -1,    -1,
     709,    -1,   143,   712,   145,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,     0,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   752,   753,    -1,   755,   756,    13,    14,
      15,    16,    17,    18,    -1,    20,   765,    -1,    -1,    -1,
      -1,    -1,    27,    28,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    37,    38,    -1,    40,    41,    42,    43,    44,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   797,    -1,
      -1,    -1,    -1,    -1,   803,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   813,    -1,    -1,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      -1,    -1,    87,    88,    89,    -1,    -1,    92,    -1,   838,
      -1,    -1,    -1,    98,    -1,    -1,    -1,   102,   847,    -1,
      -1,    -1,    -1,    -1,    -1,   854,    -1,   112,    -1,    -1,
     115,   116,    -1,    -1,   119,    -1,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,    -1,    -1,     0,    -1,
      -1,   136,   137,   138,    -1,   140,   141,   142,   143,   144,
     145,    13,    14,    15,    -1,    17,    18,    -1,    20,    -1,
      -1,    -1,    -1,    -1,    26,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    37,    38,    -1,    40,    41,
      42,    43,    44,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      72,    73,    74,    75,    76,    77,    78,    79,    80,    81,
      82,    83,    84,    -1,    -1,    87,    88,    89,    -1,    91,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     102,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     112,    -1,    -1,   115,   116,    -1,   118,   119,    -1,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,    -1,
      -1,     0,    -1,   135,   136,   137,   138,    -1,    -1,   141,
      -1,   143,   144,   145,    13,    14,    15,    -1,    17,    18,
      -1,    20,    -1,    -1,    -1,    -1,    -1,    26,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    37,    38,
      -1,    40,    41,    42,    43,    44,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    72,    73,    74,    75,    76,    77,    78,
      79,    80,    81,    82,    83,    84,    -1,    -1,    87,    88,
      89,    -1,    91,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   102,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   112,    -1,    -1,   115,   116,    -1,   118,
     119,    -1,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,    -1,    -1,     0,    -1,   135,   136,   137,   138,
      -1,    -1,   141,    -1,   143,   144,   145,    13,    14,    15,
      -1,    17,    18,    -1,    20,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    37,    38,    -1,    40,    41,    42,    43,    44,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    72,    73,    74,    75,
      76,    77,    78,    79,    80,    81,    82,    83,    84,    -1,
      -1,    87,    88,    89,    -1,    91,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   102,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   112,    -1,    -1,   115,
     116,    -1,   118,   119,    -1,   121,   122,   123,   124,   125,
     126,   127,   128,   129,   130,    -1,    -1,     0,    -1,    -1,
     136,   137,   138,    -1,    -1,   141,    -1,   143,   144,   145,
      13,    14,    15,    -1,    17,    18,    -1,    20,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    37,    38,    -1,    40,    41,    42,
      43,    44,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    72,
      73,    74,    75,    76,    77,    78,    79,    80,    81,    82,
      83,    84,    -1,    -1,    87,    88,    89,    -1,    91,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   102,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   112,
      -1,    -1,   115,   116,    -1,   118,   119,    -1,   121,   122,
     123,   124,   125,   126,   127,   128,   129,   130,    -1,    -1,
      -1,    -1,    -1,   136,   137,   138,    -1,    -1,   141,    -1,
     143,   144,   145,     1,    -1,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    12,    13,    14,    15,    -1,    -1,
      18,    19,    -1,    21,    22,    23,    24,    -1,    -1,    -1,
      -1,    -1,    30,    31,    32,    33,    34,    35,    36,    -1,
      -1,    39,    -1,    -1,    -1,    -1,    -1,    45,    -1,    47,
      48,    49,    -1,    51,    52,    53,    54,    55,    56,    -1,
      58,    59,    60,    -1,    -1,    63,    -1,    -1,    -1,    67,
      68,    -1,    70,    71,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    90,    -1,    -1,    93,    94,    -1,    96,    97,
      -1,    99,    -1,   101,    -1,   103,   104,   105,   106,   107,
     108,    -1,    -1,   111,   112,    -1,    -1,   115,   116,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   131,   132,   133,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   143,     1,   145,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    -1,    -1,
      15,    -1,    17,    18,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      45,    -1,    47,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    -1,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    99,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,   112,    -1,    -1,
     115,   116,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   131,   132,   133,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   143,     1,
     145,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      12,    -1,    -1,    15,    -1,    -1,    18,    19,    20,    21,
      22,    23,    24,    -1,    -1,    -1,    -1,    -1,    30,    31,
      32,    33,    34,    35,    36,    -1,    -1,    39,    -1,    -1,
      -1,    -1,    -1,    45,    -1,    47,    48,    49,    -1,    51,
      52,    53,    54,    55,    56,    -1,    58,    59,    60,    -1,
      -1,    63,    -1,    -1,    -1,    67,    68,    -1,    70,    71,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,
      -1,    93,    94,    -1,    96,    97,    -1,    99,    -1,   101,
      -1,   103,   104,   105,   106,   107,   108,    -1,    -1,   111,
     112,    -1,    -1,   115,   116,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   131,
     132,   133,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   143,     1,   145,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    -1,    -1,    15,    -1,    -1,    18,
      19,    -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,
      -1,    30,    31,    32,    33,    34,    35,    36,    -1,    -1,
      39,    -1,    -1,    -1,    -1,    -1,    45,    -1,    47,    48,
      49,    -1,    51,    52,    53,    54,    55,    56,    -1,    58,
      59,    60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,
      -1,    70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,
      99,    -1,   101,    -1,   103,   104,   105,   106,   107,   108,
      -1,    -1,   111,   112,    -1,    -1,   115,   116,     1,    -1,
       3,     4,     5,     6,     7,     8,     9,    10,    11,    12,
      -1,    -1,   131,   132,   133,    -1,    19,    -1,    21,    22,
      23,    24,    -1,    -1,   143,    -1,   145,    30,    31,    32,
      33,    34,    35,    36,    -1,    -1,    39,    -1,    -1,    -1,
      -1,    -1,    45,    46,    47,    48,    49,    -1,    51,    52,
      53,    54,    55,    56,    -1,    58,    59,    60,    -1,    -1,
      63,    -1,    -1,    -1,    67,    68,    -1,    70,    71,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,
      93,    94,    -1,    96,    97,    -1,    99,    -1,   101,    -1,
     103,   104,   105,   106,   107,   108,    -1,    -1,   111,   112,
      -1,    -1,   115,   116,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   131,   132,
     133,    -1,    -1,   136,    -1,    -1,    -1,    -1,    -1,    -1,
     143,     1,   145,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    -1,    14,    15,    -1,    -1,    -1,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    45,    -1,    47,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    -1,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,
      -1,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,   112,    -1,    -1,   115,   116,     1,    -1,     3,
       4,     5,     6,     7,     8,     9,    10,    11,    12,    -1,
      -1,   131,   132,   133,    -1,    19,    -1,    21,    22,    23,
      24,    -1,    -1,   143,    -1,   145,    30,    31,    32,    33,
      34,    35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,
      -1,    45,    -1,    47,    48,    49,    -1,    51,    52,    53,
      54,    55,    56,    -1,    58,    59,    60,    -1,    -1,    63,
      -1,    -1,    -1,    67,    68,    -1,    70,    71,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,
      94,    -1,    96,    97,    -1,    99,    -1,   101,    -1,   103,
     104,   105,   106,   107,   108,    -1,    -1,   111,   112,    -1,
      -1,   115,   116,     1,    -1,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    12,    -1,    -1,   131,   132,   133,
      -1,    19,    -1,    21,    22,    23,    24,   141,    -1,   143,
      -1,   145,    30,    31,    32,    33,    34,    35,    36,    -1,
      -1,    39,    -1,    -1,    -1,    -1,    -1,    45,    -1,    47,
      48,    49,    -1,    51,    52,    53,    54,    55,    56,    -1,
      58,    59,    60,    -1,    -1,    63,    -1,    -1,    -1,    67,
      68,    -1,    70,    71,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    90,    -1,    -1,    93,    94,    -1,    96,    97,
      -1,    99,    -1,   101,    -1,   103,   104,   105,   106,   107,
     108,    -1,    -1,   111,   112,    -1,    -1,   115,   116,     1,
      -1,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      12,    -1,    -1,   131,   132,   133,    -1,    19,    -1,    21,
      22,    23,    24,   141,    -1,   143,    -1,   145,    30,    31,
      32,    33,    34,    35,    36,    -1,    -1,    39,    -1,    -1,
      -1,    -1,    -1,    45,    -1,    47,    48,    49,    -1,    51,
      52,    53,    54,    55,    56,    -1,    58,    59,    60,    -1,
      -1,    63,    -1,    -1,    -1,    67,    68,    -1,    70,    71,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,
      -1,    93,    94,    -1,    96,    97,    -1,    99,    -1,   101,
      -1,   103,   104,   105,   106,   107,   108,    -1,    -1,   111,
     112,    -1,    -1,   115,   116,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   131,
     132,   133,    -1,    -1,   136,    -1,    -1,    -1,    -1,    -1,
      -1,   143,     1,   145,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    12,    -1,    -1,    15,    -1,    -1,    -1,
      19,    -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,
      -1,    30,    31,    32,    33,    34,    35,    36,    -1,    -1,
      39,    -1,    -1,    -1,    -1,    -1,    45,    -1,    47,    48,
      49,    -1,    51,    52,    53,    54,    55,    56,    -1,    58,
      59,    60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,
      -1,    70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,
      99,    -1,   101,    -1,   103,   104,   105,   106,   107,   108,
      -1,    -1,   111,   112,    -1,    -1,   115,   116,    -1,    -1,
       3,     4,     5,     6,     7,     8,     9,    10,    11,    12,
      -1,    -1,   131,   132,   133,    -1,    19,    -1,    21,    22,
      23,    24,    -1,    -1,   143,    -1,   145,    30,    31,    32,
      33,    34,    35,    36,    -1,    -1,    39,    -1,    -1,    -1,
      -1,    -1,    45,    46,    47,    48,    49,    -1,    51,    52,
      53,    54,    55,    56,    -1,    58,    59,    60,    -1,    -1,
      63,    -1,    -1,    -1,    67,    68,    -1,    70,    71,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,
      93,    94,    -1,    96,    97,    -1,    99,    -1,   101,    -1,
     103,   104,   105,   106,   107,   108,    -1,    -1,   111,   112,
      -1,    -1,   115,   116,    -1,    -1,     3,     4,     5,     6,
       7,     8,     9,    10,    11,    12,    -1,    -1,   131,   132,
     133,    -1,    19,    -1,    21,    22,    23,    24,    -1,    -1,
     143,    -1,   145,    30,    31,    32,    33,    34,    35,    36,
      -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,    45,    -1,
      47,    48,    49,    -1,    51,    52,    53,    54,    55,    56,
      -1,    58,    59,    60,    -1,    -1,    63,    -1,    -1,    -1,
      67,    68,    -1,    70,    71,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    90,    -1,    -1,    93,    94,    -1,    96,
      97,    -1,    99,    -1,   101,    -1,   103,   104,   105,   106,
     107,   108,    -1,    -1,   111,   112,    -1,    -1,   115,   116,
      -1,    -1,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    -1,    -1,    -1,   131,   132,   133,    -1,    19,    -1,
      21,    22,    23,    24,    -1,    -1,   143,    -1,   145,    30,
      31,    32,    33,    34,    35,    36,    -1,    -1,    39,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,    -1,
      51,    52,    53,    54,    55,    56,    -1,    58,    59,    60,
      -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,    70,
      71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    90,
      -1,    -1,    93,    94,    -1,    96,    97,    -1,    -1,    -1,
     101,    -1,   103,   104,   105,   106,   107,   108,    -1,    -1,
     111,   112,    -1,    -1,   115,   116,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
     131,   132,   133,    -1,    19,    -1,    21,    22,    23,    24,
      -1,    -1,   143,    -1,   145,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    -1,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    -1,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   131,   132,   133,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     145,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    -1,    -1,    -1,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    -1,    -1,
      -1,    -1,    -1,    45,    46,    47,    48,    49,    50,    51,
      52,    53,    54,    55,    56,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,    71,
      72,    73,    74,    75,    76,    77,    78,    -1,    -1,    81,
      82,    -1,    -1,    85,    86,    87,    88,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    99,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,    -1,
     132,   133,    -1,    -1,    -1,    -1,    -1,   139,   140,     3,
       4,     5,     6,     7,     8,     9,    10,    11,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    19,    -1,    21,    22,    23,
      24,    -1,    26,    -1,    -1,    -1,    30,    31,    32,    33,
      34,    35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    -1,    -1,    63,
      -1,    -1,    66,    67,    68,    -1,    70,    71,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,
      94,    -1,    96,    97,    -1,    99,   100,   101,    -1,   103,
     104,   105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,
      -1,    -1,    -1,    -1,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,
      19,   135,    21,    22,    23,    24,   140,    26,    -1,    -1,
      -1,    30,    31,    32,    33,    34,    35,    36,    -1,    -1,
      39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,
      49,    -1,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    -1,    -1,    63,    -1,    -1,    66,    67,    68,
      -1,    70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,
      99,   100,   101,    -1,   103,   104,   105,   106,   107,   108,
      -1,    -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,
       4,     5,     6,     7,     8,     9,    10,    11,    -1,    -1,
      -1,    -1,   131,   132,   133,    19,   135,    21,    22,    23,
      24,   140,    26,    -1,    -1,    -1,    30,    31,    32,    33,
      34,    35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    -1,    -1,    63,
      -1,    -1,    66,    67,    68,    -1,    70,    71,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,
      94,    -1,    96,    97,    -1,    99,   100,   101,    -1,   103,
     104,   105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,
      -1,    -1,    -1,    -1,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,
      19,   135,    21,    22,    23,    24,   140,    -1,    -1,    -1,
      -1,    30,    31,    32,    33,    34,    35,    36,    -1,    -1,
      39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,
      49,    -1,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    -1,    -1,    63,    -1,    -1,    66,    67,    68,
      -1,    70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    90,    91,    -1,    93,    94,    -1,    96,    97,    -1,
      99,   100,   101,    -1,   103,   104,   105,   106,   107,   108,
      -1,    -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,   118,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   131,   132,   133,    -1,    -1,    -1,    -1,    -1,
      -1,   140,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    19,    -1,
      21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,    30,
      31,    32,    33,    34,    35,    36,    -1,    -1,    39,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,    -1,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      -1,    -1,    63,    -1,    -1,    66,    67,    68,    -1,    70,
      71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    90,
      91,    -1,    93,    94,    -1,    96,    97,    -1,    99,   100,
     101,    -1,   103,   104,   105,   106,   107,   108,    -1,    -1,
     111,    -1,    -1,    -1,    -1,    -1,    -1,   118,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     131,   132,   133,    -1,    -1,    -1,    -1,    -1,    -1,   140,
       3,     4,     5,     6,     7,     8,     9,    10,    11,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    19,    -1,    21,    22,
      23,    24,    -1,    -1,    -1,    -1,    -1,    30,    31,    32,
      33,    34,    35,    36,    -1,    -1,    39,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    48,    49,    -1,    51,    52,
      53,    54,    55,    56,    57,    58,    59,    60,    -1,    -1,
      63,    -1,    -1,    66,    67,    68,    -1,    70,    71,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,
      93,    94,    -1,    96,    97,    -1,    99,   100,   101,    -1,
     103,   104,   105,   106,   107,   108,    -1,    -1,   111,    -1,
      -1,    -1,    -1,    -1,    -1,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    -1,    -1,    -1,    -1,   131,   132,
     133,    19,    -1,    21,    22,    23,    24,   140,    -1,    -1,
      -1,    -1,    30,    31,    32,    33,    34,    35,    36,    -1,
      -1,    39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      48,    49,    -1,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    -1,    -1,    63,    -1,    -1,    66,    67,
      68,    -1,    70,    71,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    90,    -1,    -1,    93,    94,    -1,    96,    97,
      -1,    99,   100,   101,    -1,   103,   104,   105,   106,   107,
     108,    -1,    -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,
       3,     4,     5,     6,     7,     8,     9,    10,    11,    -1,
      -1,    -1,    -1,   131,   132,   133,    19,    -1,    21,    22,
      23,    24,   140,    -1,    -1,    -1,    -1,    30,    31,    32,
      33,    34,    35,    36,    -1,    -1,    39,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    48,    49,    -1,    51,    52,
      53,    54,    55,    56,    57,    58,    59,    60,    -1,    -1,
      63,    -1,    -1,    66,    67,    68,    -1,    70,    71,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,
      93,    94,    -1,    96,    97,    -1,    99,   100,   101,    -1,
     103,   104,   105,   106,   107,   108,    -1,    -1,   111,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   131,   132,
     133,    -1,    -1,    -1,    -1,    -1,    -1,   140,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    -1,    -1,    -1,    -1,    -1,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    -1,    -1,    -1,    -1,    -1,    -1,    63,    -1,
      -1,    -1,    -1,    -1,    -1,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    -1,    -1,    81,    82,    -1,    -1,
      85,    86,    87,    88,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    99,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   107,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,    -1,   132,   133,    -1,
      -1,    -1,    -1,    -1,   139,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    -1,
      -1,    -1,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    -1,    -1,    -1,    -1,    -1,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    -1,
      -1,    -1,    -1,    -1,    -1,    63,    -1,    -1,    -1,    -1,
      -1,    -1,    70,    71,    72,    73,    74,    75,    76,    77,
      78,    -1,    -1,    81,    82,    -1,    -1,    85,    86,    87,
      88,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    99,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   107,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   121,   122,   123,   124,   125,   126,   127,
     128,   129,   130,    -1,   132,   133,    -1,    -1,    -1,    -1,
      -1,   139,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    -1,    -1,    -1,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    -1,
      -1,    -1,    -1,    -1,    45,    46,    47,    48,    49,    50,
      51,    52,    -1,    -1,    55,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,
      71,    72,    73,    74,    75,    76,    77,    78,    -1,    -1,
      81,    82,    -1,    -1,    85,    86,    87,    88,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    99,    -1,
      -1,    -1,   103,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130,
      -1,   132,   133,    -1,    -1,    -1,    -1,    -1,   139,     3,
       4,     5,     6,     7,     8,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    -1,    -1,    -1,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    -1,    -1,    -1,    -1,
      -1,    45,    46,    47,    48,    49,    50,    51,    52,    -1,
      -1,    55,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    -1,    -1,    81,    82,    -1,
      -1,    85,    86,    87,    88,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    99,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   130,    -1,   132,   133,
      -1,    -1,    -1,    -1,    -1,   139,     3,     4,     5,     6,
       7,     8,     9,    10,    11,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    19,    -1,    21,    22,    23,    24,    -1,    -1,
      -1,    -1,    -1,    30,    31,    32,    33,    34,    35,    36,
      -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    48,    49,    -1,    51,    52,    53,    54,    55,    56,
      -1,    58,    59,    60,    -1,    -1,    63,    -1,    -1,    -1,
      67,    68,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    90,    -1,    -1,    93,    94,    -1,    96,
      97,    -1,    -1,    -1,   101,    -1,   103,   104,   105,   106,
     107,   108,    -1,    -1,   111,    -1,    -1,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    19,   131,    21,    22,    23,    24,    -1,
      -1,   138,    -1,    -1,    30,    31,    32,    33,    34,    35,
      36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    48,    49,    -1,    51,    52,    53,    54,    55,
      56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,    -1,
      -1,    67,    68,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,    -1,
      96,    97,    -1,    -1,    -1,   101,    -1,   103,   104,   105,
     106,   107,   108,    -1,    -1,   111,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    19,   131,    21,    22,    23,    24,
      -1,    -1,   138,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    66,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    -1,   100,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,   112,    -1,    -1,
     115,   116,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    45,    46,    47,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    -1,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,
      -1,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,   131,   132,   133,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    66,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    -1,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,   112,    -1,    -1,
     115,   116,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    66,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,
     100,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    -1,    -1,
      -1,   131,   132,   133,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      45,    -1,    47,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    -1,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    99,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,    -1,
      -1,    -1,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    66,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,
     100,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,   131,   132,   133,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    66,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    99,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,    -1,
      -1,    -1,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    66,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,
      -1,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,   131,   132,   133,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    66,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    -1,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,    -1,
      -1,    -1,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    -1,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,
      -1,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,   131,   132,   133,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    -1,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    99,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,    -1,
      -1,    -1,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    -1,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,
      -1,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,   131,   132,   133,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    -1,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    99,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,    -1,
      -1,    -1,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    -1,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    99,
      -1,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,   131,   132,   133,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    -1,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    -1,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,    -1,
      -1,    -1,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    -1,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,
      70,    71,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    -1,
      -1,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,   131,   132,   133,    19,    -1,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    -1,    67,    68,    -1,    70,    71,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    -1,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,    -1,
      -1,    -1,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    -1,    -1,    -1,   131,   132,   133,    19,
      -1,    21,    22,    23,    24,    -1,    -1,    -1,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    -1,    -1,    39,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      -1,    51,    52,    53,    54,    55,    56,    -1,    58,    59,
      60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    87,    -1,    -1,
      90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,    -1,
      -1,   101,    -1,   103,   104,   105,   106,   107,   108,    -1,
      -1,   111,    -1,    -1,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      19,   131,    21,    22,    23,    24,    -1,    -1,    -1,    -1,
      -1,    30,    31,    32,    33,    34,    35,    36,    -1,    -1,
      39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    48,
      49,    -1,    51,    52,    53,    54,    55,    56,    -1,    58,
      59,    60,    -1,    -1,    63,    -1,    -1,    -1,    67,    68,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    90,    -1,    -1,    93,    94,    -1,    96,    97,    -1,
      99,    -1,   101,    -1,   103,   104,   105,   106,   107,   108,
      -1,    -1,   111,    -1,    -1,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    19,   131,    21,    22,    23,    24,    -1,    -1,    -1,
      -1,    -1,    30,    31,    32,    33,    34,    35,    36,    -1,
      -1,    39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      48,    49,    -1,    51,    52,    53,    54,    55,    56,    -1,
      58,    59,    60,    -1,    -1,    63,    -1,    -1,    -1,    67,
      68,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    90,    -1,    -1,    93,    94,    -1,    96,    97,
      -1,    99,    -1,   101,    -1,   103,   104,   105,   106,   107,
     108,    -1,    -1,   111,    -1,    -1,     3,     4,     5,     6,
       7,     8,     9,    10,    11,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    19,   131,    21,    22,    23,    24,    -1,    -1,
      -1,    -1,    -1,    30,    31,    32,    33,    34,    35,    36,
      -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    48,    49,    -1,    51,    52,    53,    54,    55,    56,
      -1,    58,    59,    60,    -1,    -1,    63,    -1,    -1,    -1,
      67,    68,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    90,    -1,    -1,    93,    94,    -1,    96,
      97,    -1,    -1,    -1,   101,    -1,   103,   104,   105,   106,
     107,   108,    -1,    -1,   111,    -1,    -1,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    19,   131,    21,    22,    23,    24,    -1,
      -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,    35,
      36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    48,    49,    -1,    51,    52,    53,    54,    55,
      56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,    -1,
      -1,    67,    68,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,    -1,
      96,    97,    -1,    -1,    -1,   101,    -1,   103,   104,   105,
     106,   107,   108,    -1,    -1,   111,    -1,    -1,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    19,   131,    21,    22,    23,    24,
      -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,    34,
      35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,    54,
      55,    56,    -1,    58,    59,    60,    -1,    -1,    63,    -1,
      -1,    -1,    67,    68,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,    94,
      -1,    96,    97,    -1,    -1,    -1,   101,    -1,   103,   104,
     105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,     3,
       4,     5,     6,     7,     8,     9,    10,    11,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    19,   131,    21,    22,    23,
      24,    -1,    -1,    -1,    -1,    -1,    30,    31,    32,    33,
      34,    35,    36,    -1,    -1,    39,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    48,    49,    -1,    51,    52,    53,
      54,    55,    56,    -1,    58,    59,    60,    -1,    -1,    63,
      -1,    -1,    -1,    67,    68,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    90,    -1,    -1,    93,
      94,    -1,    96,    97,    51,    52,    -1,   101,    55,   103,
     104,   105,   106,   107,   108,    -1,    -1,   111,    -1,    -1,
      -1,    -1,    -1,    70,    71,    72,    73,    74,    75,    76,
      77,    78,    -1,    -1,    81,    82,    -1,   131,    85,    86,
      87,    88,    -1,    -1,    -1,    72,    73,    74,    75,    76,
      77,    78,    99,    -1,    81,    82,    -1,    -1,    -1,    -1,
      87,    88,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   130,    -1,   132,   133,    51,    52,    -1,
      -1,    55,   139,   140,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   130,    -1,    -1,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    -1,    -1,    81,    82,    -1,
      -1,    85,    86,    87,    88,    -1,    -1,    -1,    72,    73,
      74,    75,    76,    77,    78,    99,    -1,    81,    82,    -1,
      -1,    -1,    -1,    87,    88,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   130,    -1,   132,   133,
      51,    52,    -1,    -1,    55,   139,   140,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   130,    -1,    -1,    70,
      71,    72,    73,    74,    75,    76,    77,    78,    -1,    -1,
      81,    82,    -1,    -1,    85,    86,    87,    88,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    99,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130,
      -1,   132,   133,    51,    52,    -1,    -1,    55,   139,   140,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    70,    71,    72,    73,    74,    75,    76,    77,
      78,    -1,    -1,    81,    82,    -1,    -1,    85,    86,    87,
      88,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    99,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   121,   122,   123,   124,   125,   126,   127,
     128,   129,   130,    -1,   132,   133,    51,    52,    -1,    -1,
      55,   139,   140,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    -1,    -1,    81,    82,    -1,    -1,
      85,    86,    87,    88,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    99,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,    -1,   132,   133,    51,
      52,    -1,    -1,    55,   139,   140,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,    71,
      72,    73,    74,    75,    76,    77,    78,    -1,    -1,    81,
      82,    -1,    -1,    85,    86,    87,    88,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    99,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,    -1,
     132,   133,    51,    52,    -1,    -1,    55,   139,   140,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      -1,    -1,    81,    82,    -1,    -1,    85,    86,    87,    88,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      99,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,    -1,   132,   133,    51,    52,    -1,    -1,    55,
     139,   140,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    70,    71,    72,    73,    74,    75,
      76,    77,    78,    -1,    -1,    81,    82,    -1,    -1,    85,
      86,    87,    88,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    99,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   121,   122,   123,   124,   125,
     126,   127,   128,   129,   130,    -1,   132,   133,    51,    52,
      -1,    -1,    55,   139,   140,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,    71,    72,
      73,    74,    75,    76,    77,    78,    -1,    -1,    81,    82,
      -1,    -1,    85,    86,    87,    88,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    99,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   121,   122,
     123,   124,   125,   126,   127,   128,   129,   130,    -1,   132,
     133,    51,    52,    -1,    -1,    55,   139,   140,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      70,    71,    72,    73,    74,    75,    76,    77,    78,    -1,
      -1,    81,    82,    -1,    -1,    85,    86,    87,    88,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    99,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   121,   122,   123,   124,   125,   126,   127,   128,   129,
     130,    -1,   132,   133,    51,    52,    -1,    -1,    55,   139,
     140,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    70,    71,    72,    73,    74,    75,    76,
      77,    78,    -1,    -1,    81,    82,    -1,    -1,    85,    86,
      87,    88,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    99,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   130,    -1,   132,   133,    51,    52,    -1,
      -1,    55,   139,   140,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    -1,    -1,    81,    82,    -1,
      -1,    85,    86,    87,    88,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    99,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   130,    -1,   132,   133,
      51,    52,    -1,    -1,    55,   139,   140,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,
      71,    72,    73,    74,    75,    76,    77,    78,    -1,    -1,
      81,    82,    -1,    -1,    85,    86,    87,    88,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    99,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130,
      -1,   132,   133,    51,    52,    -1,    -1,    55,   139,   140,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    70,    71,    72,    73,    74,    75,    76,    77,
      78,    -1,    -1,    81,    82,    -1,    -1,    85,    86,    87,
      88,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    99,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   121,   122,   123,   124,   125,   126,   127,
     128,   129,   130,    -1,   132,   133,    51,    52,    -1,    -1,
      55,   139,   140,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    -1,    -1,    81,    82,    -1,    -1,
      85,    86,    87,    88,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    99,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,    -1,   132,   133,    51,
      52,    -1,    -1,    55,   139,   140,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,    71,
      72,    73,    74,    75,    76,    77,    78,    -1,    -1,    81,
      82,    -1,    -1,    85,    86,    87,    88,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    99,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      44,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,    -1,
     132,   133,    -1,    -1,    -1,    -1,    -1,   139,    72,    73,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    -1,    -1,    87,    88,    72,    73,    74,    75,    76,
      77,    78,    79,    80,    81,    82,    83,    84,    -1,    -1,
      87,    88,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   119,    -1,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   130,    -1,    -1,    -1,
      -1,    -1,   119,    -1,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   130,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   138,    72,    73,    74,    75,    76,    77,    78,    79,
      80,    81,    82,    83,    84,    -1,    -1,    87,    88,    -1,
      72,    73,    74,    75,    76,    77,    78,    79,    80,    81,
      82,    83,    84,    -1,    -1,    87,    88,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   119,
      -1,   121,   122,   123,   124,   125,   126,   127,   128,   129,
     130,    -1,    -1,    -1,    -1,    -1,    -1,   119,   138,   121,
     122,   123,   124,   125,   126,   127,   128,   129,   130,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   138,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      -1,    -1,    87,    88,    -1,    72,    73,    74,    75,    76,
      77,    78,    79,    80,    81,    82,    83,    84,    -1,    -1,
      87,    88,    -1,    -1,    -1,    92,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   119,    -1,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,    -1,    -1,    -1,    -1,
      -1,    -1,   119,   138,   121,   122,   123,   124,   125,   126,
     127,   128,   129,   130,    72,    73,    74,    75,    76,    77,
      78,    79,    80,    81,    82,    83,    84,    -1,    -1,    87,
      88,    72,    73,    74,    75,    76,    77,    78,    79,    80,
      81,    82,    83,    84,    -1,    -1,    87,    88,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   119,    -1,   121,   122,   123,   124,   125,   126,   127,
     128,   129,   130,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint16 yystos[] =
{
       0,   147,   148,     0,     1,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    12,    19,    21,    22,    23,    24,
      30,    31,    32,    33,    34,    35,    36,    39,    45,    46,
      47,    48,    49,    51,    52,    53,    54,    55,    56,    58,
      59,    60,    63,    67,    68,    70,    71,    90,    93,    94,
      96,    97,    99,   101,   103,   104,   105,   106,   107,   108,
     111,   131,   132,   133,   149,   150,   151,   156,   158,   160,
     162,   163,   166,   167,   169,   170,   171,   173,   174,   183,
     197,   218,   237,   238,   248,   249,   253,   254,   255,   261,
     262,   263,   265,   266,   267,   268,   269,   270,   294,   308,
     151,    21,    22,    30,    31,    32,    39,    51,    55,    87,
      90,    93,   131,   175,   176,   197,   218,   267,   270,   294,
     176,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    45,    46,    47,    48,    49,
      50,    51,    52,    55,    70,    71,    72,    73,    74,    75,
      76,    77,    78,    81,    82,    85,    86,    87,    88,    99,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     132,   133,   139,   140,   177,   181,   182,   269,   289,   198,
      90,   160,   161,   174,   218,   267,   268,   270,   161,   204,
     206,    90,   167,   174,   218,   223,   267,   270,    33,    34,
      35,    36,    48,    49,    51,    55,   103,   177,   178,   179,
     263,   112,   115,   116,   143,   145,   161,   257,   258,   259,
     300,   305,   306,   307,    57,    66,    99,   100,   107,   132,
     166,   183,   189,   192,   195,   292,   293,   189,   189,   140,
     186,   187,   190,   191,   308,   186,   190,   140,   301,   306,
     178,   152,   135,   183,   218,   183,    55,     1,    93,   154,
     155,   156,   168,   169,   308,   199,   201,   184,   195,   292,
     308,   183,   291,   292,   308,    90,   138,   173,   218,   267,
     270,   202,    53,    54,    56,    63,   107,   177,   264,    62,
      64,    65,   113,   114,   250,   251,    63,   250,    63,   250,
      63,   250,    61,   250,    58,    59,   162,   183,   183,   300,
     307,    40,    41,    42,    43,    44,    37,    38,    28,   235,
     118,   138,    93,    99,   170,   118,    72,    73,    74,    75,
      76,    77,    78,    79,    80,    81,    82,    83,    84,    87,
      88,   119,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,    89,   102,   137,   144,   298,    89,   298,   299,
      26,   135,   239,    91,    91,   186,   190,   239,   160,    51,
      55,   175,    58,    59,   122,   271,    89,   137,   298,   213,
     290,   214,    89,   144,   297,   153,   154,    55,    16,   219,
     305,   118,    89,   137,   298,    91,    91,   219,   161,   161,
      55,    89,   137,   298,    25,   107,   138,   260,   300,   112,
     259,    20,   242,   305,   183,   183,   183,   183,    66,   250,
      92,   138,   193,   194,   308,   138,   193,   194,   188,   189,
     195,   292,   308,   189,   160,   301,   302,   160,   157,   135,
     154,    89,   298,    91,   156,   168,   141,   300,   307,   302,
     156,   302,   142,   194,   304,   306,   194,   304,   136,   304,
      55,   170,   171,   172,   138,    89,   137,   298,    51,    53,
      54,    55,    56,    93,    99,   100,   125,   128,   140,   233,
     274,   275,   276,   277,   278,   279,   280,   283,   284,   285,
     286,   287,    63,   250,   252,   256,   257,    62,   251,    63,
      63,    63,    61,    72,    72,   151,   161,   161,   161,   161,
     156,   160,   160,   236,    99,   162,   183,   195,   196,   168,
     138,   173,   138,   158,   159,   162,   174,   183,   185,   196,
     218,   270,   183,   183,   183,   183,   183,   183,   183,   183,
     183,   183,   183,   183,   183,   183,   183,   183,   183,   183,
     183,   183,   183,   183,   183,   183,   183,   183,    51,    52,
      55,   181,   186,   295,   296,   188,    51,    52,    55,   181,
     186,   295,    51,    55,   295,   241,   240,   159,   183,   185,
     159,   185,    98,   164,   211,   272,   210,    51,    55,   175,
     295,   188,   295,   153,   160,   215,   216,    15,    13,   244,
     308,   154,    16,    51,    55,   188,    51,    55,   154,    27,
     220,   305,   220,    51,    55,   188,    51,    55,   208,   180,
     154,   242,   183,   195,    15,   183,    66,   183,   256,    99,
     183,   192,   292,   293,   302,   138,   194,   138,   302,   141,
     178,   149,   136,   185,   302,   156,   200,   292,   170,   172,
      51,    55,   188,    51,    55,   118,    51,    93,    99,   224,
     225,   226,   276,   274,   203,   138,   288,   308,   183,   138,
     288,    51,   138,   288,    51,    63,   154,   257,   183,   183,
      80,   123,   228,   229,   308,   183,   194,   302,   172,   138,
      44,   118,    44,    89,   137,   298,   301,    91,    91,   186,
     190,   301,   303,    91,    91,   187,   190,   187,   190,   228,
     228,   165,   305,   161,   153,   303,    15,   302,   140,   273,
     274,   177,   183,   196,   245,   308,    18,   222,   308,    17,
     221,   222,    91,    91,   303,    91,    91,   222,   205,   207,
     303,   161,   178,   136,    15,   194,   219,   183,   183,   193,
     292,   136,   302,   304,   303,   226,   138,   276,   138,   302,
     230,   301,    29,   110,   234,   277,   283,   285,   287,   278,
     280,   285,   278,   136,   227,   230,   278,   279,   281,   282,
     285,   287,   154,    99,   183,   172,   156,   183,    51,    55,
     188,    51,    55,   120,   159,   185,   162,   185,   164,   142,
      91,   159,   185,   159,   185,   164,   239,   235,   154,   154,
     228,   212,   305,    15,   274,   153,   305,   217,    92,   246,
     308,   154,    14,   247,   308,   161,    15,    91,    15,   154,
     154,   220,   183,   154,   138,   302,   225,   138,    99,   224,
     141,   143,   154,   154,   138,   288,   138,   288,   138,   288,
     138,   288,   288,   230,   123,   138,   288,    90,   218,   138,
     288,   138,   288,    15,   183,   303,   183,   159,   185,    15,
     136,   154,   153,   302,    15,   273,    90,   174,   218,   267,
     270,   219,   154,   219,    15,    15,   209,   222,   242,   243,
     138,   225,   138,   276,    51,   231,   232,   275,    15,   136,
     278,   285,   278,   278,   123,   282,   285,    55,    89,   278,
     281,   285,   278,   136,    15,   153,    55,    89,   137,   298,
     154,   154,   154,   225,   138,   138,   301,   288,   138,   288,
     288,   288,   138,   288,   138,   288,    51,    55,   288,   138,
     288,   288,    15,    51,    55,   188,    51,    55,   244,   221,
      15,   225,   232,   278,   278,   285,   278,   278,   303,   288,
     288,   138,   288,   288,   288,   278,   288
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (p, YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, p)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, p); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, parser_state *p)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, p)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    parser_state *p;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (p);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, parser_state *p)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, p)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    parser_state *p;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, p);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule, parser_state *p)
#else
static void
yy_reduce_print (yyvsp, yyrule, p)
    YYSTYPE *yyvsp;
    int yyrule;
    parser_state *p;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       , p);
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule, p); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, parser_state *p)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, p)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    parser_state *p;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (p);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (parser_state *p);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */






/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (parser_state *p)
#else
int
yyparse (p)
    parser_state *p;
#endif
#endif
{
  /* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;

  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 1199 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lstate = EXPR_BEG;
                      if (!p->locals) p->locals = cons(0,0);
                    ;}
    break;

  case 3:
#line 1204 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->tree = new_scope(p, (yyvsp[(2) - (2)].nd));
                      NODE_LINENO(p->tree, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 4:
#line 1211 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (2)].nd);
                    ;}
    break;

  case 5:
#line 1217 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_begin(p, 0);
                    ;}
    break;

  case 6:
#line 1221 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_begin(p, (yyvsp[(1) - (1)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 7:
#line 1226 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), newline_node((yyvsp[(3) - (3)].nd)));
                    ;}
    break;

  case 8:
#line 1230 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_begin(p, 0);
                    ;}
    break;

  case 10:
#line 1237 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = local_switch(p);
                    ;}
    break;

  case 11:
#line 1241 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "BEGIN not supported");
                      local_resume(p, (yyvsp[(2) - (5)].nd));
                      (yyval.nd) = 0;
                    ;}
    break;

  case 12:
#line 1252 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if ((yyvsp[(2) - (4)].nd)) {
                        (yyval.nd) = new_rescue(p, (yyvsp[(1) - (4)].nd), (yyvsp[(2) - (4)].nd), (yyvsp[(3) - (4)].nd));
                        NODE_LINENO((yyval.nd), (yyvsp[(1) - (4)].nd));
                      }
                      else if ((yyvsp[(3) - (4)].nd)) {
                        yywarn(p, "else without rescue is useless");
                        (yyval.nd) = push((yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].nd));
                      }
                      else {
                        (yyval.nd) = (yyvsp[(1) - (4)].nd);
                      }
                      if ((yyvsp[(4) - (4)].nd)) {
                        if ((yyval.nd)) {
                          (yyval.nd) = new_ensure(p, (yyval.nd), (yyvsp[(4) - (4)].nd));
                        }
                        else {
                          (yyval.nd) = push((yyvsp[(4) - (4)].nd), new_nil(p));
                        }
                      }
                    ;}
    break;

  case 13:
#line 1276 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (2)].nd);
                    ;}
    break;

  case 14:
#line 1282 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_begin(p, 0);
                    ;}
    break;

  case 15:
#line 1286 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_begin(p, (yyvsp[(1) - (1)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 16:
#line 1291 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), newline_node((yyvsp[(3) - (3)].nd)));
                    ;}
    break;

  case 17:
#line 1295 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_begin(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 18:
#line 1300 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {p->lstate = EXPR_FNAME;;}
    break;

  case 19:
#line 1301 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_alias(p, (yyvsp[(2) - (4)].id), (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 20:
#line 1305 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 21:
#line 1309 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_if(p, cond((yyvsp[(3) - (3)].nd)), (yyvsp[(1) - (3)].nd), 0);
                    ;}
    break;

  case 22:
#line 1313 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_unless(p, cond((yyvsp[(3) - (3)].nd)), (yyvsp[(1) - (3)].nd), 0);
                    ;}
    break;

  case 23:
#line 1317 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_while(p, cond((yyvsp[(3) - (3)].nd)), (yyvsp[(1) - (3)].nd));
                    ;}
    break;

  case 24:
#line 1321 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_until(p, cond((yyvsp[(3) - (3)].nd)), (yyvsp[(1) - (3)].nd));
                    ;}
    break;

  case 25:
#line 1325 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_mod_rescue(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 26:
#line 1329 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "END not supported");
                      (yyval.nd) = new_postexe(p, (yyvsp[(3) - (4)].nd));
                    ;}
    break;

  case 28:
#line 1335 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_masgn(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 29:
#line 1339 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_asgn(p, (yyvsp[(1) - (3)].nd), new_array(p, (yyvsp[(3) - (3)].nd)));
                    ;}
    break;

  case 30:
#line 1343 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_masgn(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 31:
#line 1347 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_masgn(p, (yyvsp[(1) - (3)].nd), new_array(p, (yyvsp[(3) - (3)].nd)));
                    ;}
    break;

  case 33:
#line 1354 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_asgn(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 34:
#line 1358 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, (yyvsp[(1) - (3)].nd), (yyvsp[(2) - (3)].id), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 35:
#line 1362 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, new_call(p, (yyvsp[(1) - (6)].nd), intern("[]",2), (yyvsp[(3) - (6)].nd), '.'), (yyvsp[(5) - (6)].id), (yyvsp[(6) - (6)].nd));
                    ;}
    break;

  case 36:
#line 1366 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), 0, (yyvsp[(2) - (5)].num)), (yyvsp[(4) - (5)].id), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 37:
#line 1370 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), 0, (yyvsp[(2) - (5)].num)), (yyvsp[(4) - (5)].id), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 38:
#line 1374 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "constant re-assignment");
                      (yyval.nd) = 0;
                    ;}
    break;

  case 39:
#line 1379 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), 0, tCOLON2), (yyvsp[(4) - (5)].id), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 40:
#line 1383 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      backref_error(p, (yyvsp[(1) - (3)].nd));
                      (yyval.nd) = new_begin(p, 0);
                    ;}
    break;

  case 42:
#line 1391 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_mod_rescue(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 45:
#line 1400 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_and(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 46:
#line 1404 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_or(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 47:
#line 1408 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, cond((yyvsp[(3) - (3)].nd)), "!");
                    ;}
    break;

  case 48:
#line 1412 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, cond((yyvsp[(2) - (2)].nd)), "!");
                    ;}
    break;

  case 50:
#line 1419 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if (!(yyvsp[(1) - (1)].nd)) (yyval.nd) = new_nil(p);
                      else {
                        (yyval.nd) = (yyvsp[(1) - (1)].nd);
                      }
                    ;}
    break;

  case 54:
#line 1433 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].id), (yyvsp[(4) - (4)].nd), (yyvsp[(2) - (4)].num));
                    ;}
    break;

  case 55:
#line 1439 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_nest(p);
                    ;}
    break;

  case 56:
#line 1445 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_block(p, (yyvsp[(3) - (5)].nd), (yyvsp[(4) - (5)].nd));
                      local_unnest(p);
                    ;}
    break;

  case 57:
#line 1452 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_fcall(p, (yyvsp[(1) - (2)].id), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 58:
#line 1456 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      args_with_block(p, (yyvsp[(2) - (3)].nd), (yyvsp[(3) - (3)].nd));
                      (yyval.nd) = new_fcall(p, (yyvsp[(1) - (3)].id), (yyvsp[(2) - (3)].nd));
                    ;}
    break;

  case 59:
#line 1461 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].id), (yyvsp[(4) - (4)].nd), (yyvsp[(2) - (4)].num));
                    ;}
    break;

  case 60:
#line 1465 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      args_with_block(p, (yyvsp[(4) - (5)].nd), (yyvsp[(5) - (5)].nd));
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), (yyvsp[(4) - (5)].nd), (yyvsp[(2) - (5)].num));
                   ;}
    break;

  case 61:
#line 1470 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].id), (yyvsp[(4) - (4)].nd), tCOLON2);
                    ;}
    break;

  case 62:
#line 1474 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      args_with_block(p, (yyvsp[(4) - (5)].nd), (yyvsp[(5) - (5)].nd));
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), (yyvsp[(4) - (5)].nd), tCOLON2);
                    ;}
    break;

  case 63:
#line 1479 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_super(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 64:
#line 1483 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_yield(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 65:
#line 1487 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_return(p, ret_args(p, (yyvsp[(2) - (2)].nd)));
                    ;}
    break;

  case 66:
#line 1491 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_break(p, ret_args(p, (yyvsp[(2) - (2)].nd)));
                    ;}
    break;

  case 67:
#line 1495 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_next(p, ret_args(p, (yyvsp[(2) - (2)].nd)));
                    ;}
    break;

  case 68:
#line 1501 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (1)].nd);
                    ;}
    break;

  case 69:
#line 1505 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (3)].nd);
                    ;}
    break;

  case 71:
#line 1512 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (3)].nd);
                    ;}
    break;

  case 72:
#line 1518 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 73:
#line 1522 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1(push((yyvsp[(1) - (2)].nd),(yyvsp[(2) - (2)].nd)));
                    ;}
    break;

  case 74:
#line 1526 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list2((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 75:
#line 1530 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3((yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].nd), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 76:
#line 1534 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list2((yyvsp[(1) - (2)].nd), new_nil(p));
                    ;}
    break;

  case 77:
#line 1538 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3((yyvsp[(1) - (4)].nd), new_nil(p), (yyvsp[(4) - (4)].nd));
                    ;}
    break;

  case 78:
#line 1542 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list2(0, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 79:
#line 1546 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3(0, (yyvsp[(2) - (4)].nd), (yyvsp[(4) - (4)].nd));
                    ;}
    break;

  case 80:
#line 1550 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list2(0, new_nil(p));
                    ;}
    break;

  case 81:
#line 1554 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3(0, new_nil(p), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 83:
#line 1561 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_masgn(p, (yyvsp[(2) - (3)].nd), NULL);
                    ;}
    break;

  case 84:
#line 1567 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (2)].nd));
                    ;}
    break;

  case 85:
#line 1571 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), (yyvsp[(2) - (3)].nd));
                    ;}
    break;

  case 86:
#line 1577 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 87:
#line 1581 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (2)].nd), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 88:
#line 1587 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      assignable(p, (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 89:
#line 1591 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), intern("[]",2), (yyvsp[(3) - (4)].nd), '.');
                    ;}
    break;

  case 90:
#line 1595 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id), 0, (yyvsp[(2) - (3)].num));
                    ;}
    break;

  case 91:
#line 1599 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id), 0, tCOLON2);
                    ;}
    break;

  case 92:
#line 1603 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id), 0, (yyvsp[(2) - (3)].num));
                    ;}
    break;

  case 93:
#line 1607 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "dynamic constant assignment");
                      (yyval.nd) = new_colon2(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id));
                    ;}
    break;

  case 94:
#line 1613 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "dynamic constant assignment");
                      (yyval.nd) = new_colon3(p, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 95:
#line 1619 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      backref_error(p, (yyvsp[(1) - (1)].nd));
                      (yyval.nd) = 0;
                    ;}
    break;

  case 96:
#line 1626 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      assignable(p, (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 97:
#line 1630 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), intern("[]",2), (yyvsp[(3) - (4)].nd), '.');
                    ;}
    break;

  case 98:
#line 1634 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id), 0, (yyvsp[(2) - (3)].num));
                    ;}
    break;

  case 99:
#line 1638 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id), 0, tCOLON2);
                    ;}
    break;

  case 100:
#line 1642 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id), 0, (yyvsp[(2) - (3)].num));
                    ;}
    break;

  case 101:
#line 1646 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "dynamic constant assignment");
                      (yyval.nd) = new_colon2(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id));
                    ;}
    break;

  case 102:
#line 1652 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "dynamic constant assignment");
                      (yyval.nd) = new_colon3(p, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 103:
#line 1658 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      backref_error(p, (yyvsp[(1) - (1)].nd));
                      (yyval.nd) = 0;
                    ;}
    break;

  case 104:
#line 1665 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "class/module name must be CONSTANT");
                    ;}
    break;

  case 106:
#line 1672 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons((node*)1, nsym((yyvsp[(2) - (2)].id)));
                    ;}
    break;

  case 107:
#line 1676 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons((node*)0, nsym((yyvsp[(1) - (1)].id)));
                    ;}
    break;

  case 108:
#line 1680 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(1) - (3)].nd));
                      (yyval.nd) = cons((yyvsp[(1) - (3)].nd), nsym((yyvsp[(3) - (3)].id)));
                    ;}
    break;

  case 112:
#line 1690 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lstate = EXPR_ENDFN;
                      (yyval.id) = (yyvsp[(1) - (1)].id);
                    ;}
    break;

  case 113:
#line 1695 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lstate = EXPR_ENDFN;
                      (yyval.id) = (yyvsp[(1) - (1)].id);
                    ;}
    break;

  case 116:
#line 1706 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_undef(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 117:
#line 1709 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {p->lstate = EXPR_FNAME;;}
    break;

  case 118:
#line 1710 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (4)].nd), nsym((yyvsp[(4) - (4)].id)));
                    ;}
    break;

  case 119:
#line 1715 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('|');   ;}
    break;

  case 120:
#line 1716 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('^');   ;}
    break;

  case 121:
#line 1717 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('&');   ;}
    break;

  case 122:
#line 1718 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("<=>",3); ;}
    break;

  case 123:
#line 1719 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("==",2);  ;}
    break;

  case 124:
#line 1720 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("===",3); ;}
    break;

  case 125:
#line 1721 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("=~",2);  ;}
    break;

  case 126:
#line 1722 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("!~",2);  ;}
    break;

  case 127:
#line 1723 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('>');   ;}
    break;

  case 128:
#line 1724 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern(">=",2);  ;}
    break;

  case 129:
#line 1725 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('<');   ;}
    break;

  case 130:
#line 1726 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("<=",2);  ;}
    break;

  case 131:
#line 1727 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("!=",2);  ;}
    break;

  case 132:
#line 1728 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("<<",2);  ;}
    break;

  case 133:
#line 1729 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern(">>",2);  ;}
    break;

  case 134:
#line 1730 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('+');   ;}
    break;

  case 135:
#line 1731 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('-');   ;}
    break;

  case 136:
#line 1732 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('*');   ;}
    break;

  case 137:
#line 1733 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('*');   ;}
    break;

  case 138:
#line 1734 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('/');   ;}
    break;

  case 139:
#line 1735 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('%');   ;}
    break;

  case 140:
#line 1736 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("**",2);  ;}
    break;

  case 141:
#line 1737 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('!');   ;}
    break;

  case 142:
#line 1738 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('~');   ;}
    break;

  case 143:
#line 1739 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("+@",2);  ;}
    break;

  case 144:
#line 1740 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("-@",2);  ;}
    break;

  case 145:
#line 1741 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("[]",2);  ;}
    break;

  case 146:
#line 1742 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern("[]=",3); ;}
    break;

  case 147:
#line 1743 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    { (yyval.id) = intern_c('`');   ;}
    break;

  case 188:
#line 1761 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_asgn(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 189:
#line 1765 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, (yyvsp[(1) - (3)].nd), (yyvsp[(2) - (3)].id), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 190:
#line 1769 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, new_call(p, (yyvsp[(1) - (6)].nd), intern("[]",2), (yyvsp[(3) - (6)].nd), '.'), (yyvsp[(5) - (6)].id), (yyvsp[(6) - (6)].nd));
                    ;}
    break;

  case 191:
#line 1773 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), 0, (yyvsp[(2) - (5)].num)), (yyvsp[(4) - (5)].id), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 192:
#line 1777 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), 0, (yyvsp[(2) - (5)].num)), (yyvsp[(4) - (5)].id), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 193:
#line 1781 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_op_asgn(p, new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), 0, tCOLON2), (yyvsp[(4) - (5)].id), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 194:
#line 1785 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "constant re-assignment");
                      (yyval.nd) = new_begin(p, 0);
                    ;}
    break;

  case 195:
#line 1790 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "constant re-assignment");
                      (yyval.nd) = new_begin(p, 0);
                    ;}
    break;

  case 196:
#line 1795 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      backref_error(p, (yyvsp[(1) - (3)].nd));
                      (yyval.nd) = new_begin(p, 0);
                    ;}
    break;

  case 197:
#line 1800 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_dot2(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 198:
#line 1804 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_dot3(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 199:
#line 1808 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "+", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 200:
#line 1812 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "-", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 201:
#line 1816 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "*", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 202:
#line 1820 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "/", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 203:
#line 1824 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "%", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 204:
#line 1828 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "**", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 205:
#line 1832 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, call_bin_op(p, (yyvsp[(2) - (4)].nd), "**", (yyvsp[(4) - (4)].nd)), "-@");
                    ;}
    break;

  case 206:
#line 1836 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, call_bin_op(p, (yyvsp[(2) - (4)].nd), "**", (yyvsp[(4) - (4)].nd)), "-@");
                    ;}
    break;

  case 207:
#line 1840 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, (yyvsp[(2) - (2)].nd), "+@");
                    ;}
    break;

  case 208:
#line 1844 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, (yyvsp[(2) - (2)].nd), "-@");
                    ;}
    break;

  case 209:
#line 1848 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "|", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 210:
#line 1852 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "^", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 211:
#line 1856 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "&", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 212:
#line 1860 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "<=>", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 213:
#line 1864 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), ">", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 214:
#line 1868 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), ">=", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 215:
#line 1872 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "<", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 216:
#line 1876 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "<=", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 217:
#line 1880 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "==", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 218:
#line 1884 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "===", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 219:
#line 1888 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "!=", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 220:
#line 1892 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "=~", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 221:
#line 1896 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "!~", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 222:
#line 1900 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, cond((yyvsp[(2) - (2)].nd)), "!");
                    ;}
    break;

  case 223:
#line 1904 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, cond((yyvsp[(2) - (2)].nd)), "~");
                    ;}
    break;

  case 224:
#line 1908 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), "<<", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 225:
#line 1912 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_bin_op(p, (yyvsp[(1) - (3)].nd), ">>", (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 226:
#line 1916 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_and(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 227:
#line 1920 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_or(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 228:
#line 1924 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_if(p, cond((yyvsp[(1) - (6)].nd)), (yyvsp[(3) - (6)].nd), (yyvsp[(6) - (6)].nd));
                    ;}
    break;

  case 229:
#line 1928 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (1)].nd);
                    ;}
    break;

  case 231:
#line 1935 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (2)].nd);
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (2)].nd));
                    ;}
    break;

  case 232:
#line 1940 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (4)].nd), new_hash(p, (yyvsp[(3) - (4)].nd)));
                    ;}
    break;

  case 233:
#line 1944 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons(new_hash(p, (yyvsp[(1) - (2)].nd)), 0);
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (2)].nd));
                    ;}
    break;

  case 234:
#line 1951 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (1)].nd);
                    ;}
    break;

  case 235:
#line 1955 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(1) - (3)].nd));
                      void_expr_error(p, (yyvsp[(3) - (3)].nd));
                      (yyval.nd) = new_mod_rescue(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 236:
#line 1963 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (3)].nd);
                    ;}
    break;

  case 241:
#line 1975 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons((yyvsp[(1) - (2)].nd),0);
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (2)].nd));
                    ;}
    break;

  case 242:
#line 1980 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons(push((yyvsp[(1) - (4)].nd), new_hash(p, (yyvsp[(3) - (4)].nd))), 0);
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (4)].nd));
                    ;}
    break;

  case 243:
#line 1985 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons(list1(new_hash(p, (yyvsp[(1) - (2)].nd))), 0);
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (2)].nd));
                    ;}
    break;

  case 244:
#line 1992 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(1) - (1)].nd));
                      (yyval.nd) = cons(list1((yyvsp[(1) - (1)].nd)), 0);
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 245:
#line 1998 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons((yyvsp[(1) - (2)].nd), (yyvsp[(2) - (2)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (2)].nd));
                    ;}
    break;

  case 246:
#line 2003 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons(list1(new_hash(p, (yyvsp[(1) - (2)].nd))), (yyvsp[(2) - (2)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (2)].nd));
                    ;}
    break;

  case 247:
#line 2008 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons(push((yyvsp[(1) - (4)].nd), new_hash(p, (yyvsp[(3) - (4)].nd))), (yyvsp[(4) - (4)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (4)].nd));
                    ;}
    break;

  case 248:
#line 2013 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons(0, (yyvsp[(1) - (1)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 249:
#line 2019 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.stack) = p->cmdarg_stack;
                      CMDARG_PUSH(1);
                    ;}
    break;

  case 250:
#line 2024 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->cmdarg_stack = (yyvsp[(1) - (2)].stack);
                      (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 251:
#line 2031 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_block_arg(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 252:
#line 2037 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 253:
#line 2041 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = 0;
                    ;}
    break;

  case 256:
#line 2051 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(1) - (1)].nd));
                      (yyval.nd) = cons((yyvsp[(1) - (1)].nd), 0);
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 257:
#line 2057 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(2) - (2)].nd));
                      (yyval.nd) = cons(new_splat(p, (yyvsp[(2) - (2)].nd)), 0);
                      NODE_LINENO((yyval.nd), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 258:
#line 2063 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(3) - (3)].nd));
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 259:
#line 2068 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(4) - (4)].nd));
                      (yyval.nd) = push((yyvsp[(1) - (4)].nd), new_splat(p, (yyvsp[(4) - (4)].nd)));
                    ;}
    break;

  case 260:
#line 2075 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(3) - (3)].nd));
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 261:
#line 2080 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(4) - (4)].nd));
                      (yyval.nd) = push((yyvsp[(1) - (4)].nd), new_splat(p, (yyvsp[(4) - (4)].nd)));
                    ;}
    break;

  case 262:
#line 2085 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(2) - (2)].nd));
                      (yyval.nd) = list1(new_splat(p, (yyvsp[(2) - (2)].nd)));
                    ;}
    break;

  case 270:
#line 2099 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_fcall(p, (yyvsp[(1) - (1)].id), 0);
                    ;}
    break;

  case 271:
#line 2103 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.stack) = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    ;}
    break;

  case 272:
#line 2109 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->cmdarg_stack = (yyvsp[(2) - (4)].stack);
                      (yyval.nd) = (yyvsp[(3) - (4)].nd);
                    ;}
    break;

  case 273:
#line 2114 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.stack) = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    ;}
    break;

  case 274:
#line 2118 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {p->lstate = EXPR_ENDARG;;}
    break;

  case 275:
#line 2119 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->cmdarg_stack = (yyvsp[(2) - (5)].stack);
                      (yyval.nd) = (yyvsp[(3) - (5)].nd);
                    ;}
    break;

  case 276:
#line 2123 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {p->lstate = EXPR_ENDARG;;}
    break;

  case 277:
#line 2124 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_nil(p);
                    ;}
    break;

  case 278:
#line 2128 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (3)].nd);
                    ;}
    break;

  case 279:
#line 2132 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_colon2(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id));
                    ;}
    break;

  case 280:
#line 2136 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_colon3(p, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 281:
#line 2140 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_array(p, (yyvsp[(2) - (3)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(2) - (3)].nd));
                    ;}
    break;

  case 282:
#line 2145 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_hash(p, (yyvsp[(2) - (3)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(2) - (3)].nd));
                    ;}
    break;

  case 283:
#line 2150 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_return(p, 0);
                    ;}
    break;

  case 284:
#line 2154 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_yield(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 285:
#line 2158 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, cond((yyvsp[(3) - (4)].nd)), "!");
                    ;}
    break;

  case 286:
#line 2162 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = call_uni_op(p, new_nil(p), "!");
                    ;}
    break;

  case 287:
#line 2166 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_fcall(p, (yyvsp[(1) - (2)].id), cons(0, (yyvsp[(2) - (2)].nd)));
                    ;}
    break;

  case 289:
#line 2171 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      call_with_block(p, (yyvsp[(1) - (2)].nd), (yyvsp[(2) - (2)].nd));
                      (yyval.nd) = (yyvsp[(1) - (2)].nd);
                    ;}
    break;

  case 290:
#line 2176 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_nest(p);
                      (yyval.num) = p->lpar_beg;
                      p->lpar_beg = ++p->paren_nest;
                    ;}
    break;

  case 291:
#line 2182 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.stack) = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    ;}
    break;

  case 292:
#line 2187 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lpar_beg = (yyvsp[(2) - (5)].num);
                      (yyval.nd) = new_lambda(p, (yyvsp[(3) - (5)].nd), (yyvsp[(5) - (5)].nd));
                      local_unnest(p);
                      p->cmdarg_stack = (yyvsp[(4) - (5)].stack);
                      CMDARG_LEXPOP();
                    ;}
    break;

  case 293:
#line 2198 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_if(p, cond((yyvsp[(2) - (6)].nd)), (yyvsp[(4) - (6)].nd), (yyvsp[(5) - (6)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (6)].num));
                    ;}
    break;

  case 294:
#line 2206 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_unless(p, cond((yyvsp[(2) - (6)].nd)), (yyvsp[(4) - (6)].nd), (yyvsp[(5) - (6)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (6)].num));
                    ;}
    break;

  case 295:
#line 2210 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {COND_PUSH(1);;}
    break;

  case 296:
#line 2210 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {COND_POP();;}
    break;

  case 297:
#line 2213 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_while(p, cond((yyvsp[(3) - (7)].nd)), (yyvsp[(6) - (7)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (7)].num));
                    ;}
    break;

  case 298:
#line 2217 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {COND_PUSH(1);;}
    break;

  case 299:
#line 2217 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {COND_POP();;}
    break;

  case 300:
#line 2220 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_until(p, cond((yyvsp[(3) - (7)].nd)), (yyvsp[(6) - (7)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (7)].num));
                    ;}
    break;

  case 301:
#line 2227 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_case(p, (yyvsp[(2) - (5)].nd), (yyvsp[(4) - (5)].nd));
                    ;}
    break;

  case 302:
#line 2231 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_case(p, 0, (yyvsp[(3) - (4)].nd));
                    ;}
    break;

  case 303:
#line 2235 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {COND_PUSH(1);;}
    break;

  case 304:
#line 2237 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {COND_POP();;}
    break;

  case 305:
#line 2240 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_for(p, (yyvsp[(2) - (9)].nd), (yyvsp[(5) - (9)].nd), (yyvsp[(8) - (9)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (9)].num));
                    ;}
    break;

  case 306:
#line 2246 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "class definition in method body");
                      (yyval.nd) = local_switch(p);
                    ;}
    break;

  case 307:
#line 2253 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_class(p, (yyvsp[(2) - (6)].nd), (yyvsp[(3) - (6)].nd), (yyvsp[(5) - (6)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (6)].num));
                      local_resume(p, (yyvsp[(4) - (6)].nd));
                    ;}
    break;

  case 308:
#line 2260 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.num) = p->in_def;
                      p->in_def = 0;
                    ;}
    break;

  case 309:
#line 2265 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons(local_switch(p), nint(p->in_single));
                      p->in_single = 0;
                    ;}
    break;

  case 310:
#line 2271 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_sclass(p, (yyvsp[(3) - (8)].nd), (yyvsp[(7) - (8)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (8)].num));
                      local_resume(p, (yyvsp[(6) - (8)].nd)->car);
                      p->in_def = (yyvsp[(4) - (8)].num);
                      p->in_single = intn((yyvsp[(6) - (8)].nd)->cdr);
                    ;}
    break;

  case 311:
#line 2280 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "module definition in method body");
                      (yyval.nd) = local_switch(p);
                    ;}
    break;

  case 312:
#line 2287 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_module(p, (yyvsp[(2) - (5)].nd), (yyvsp[(4) - (5)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (5)].num));
                      local_resume(p, (yyvsp[(3) - (5)].nd));
                    ;}
    break;

  case 313:
#line 2293 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.stack) = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    ;}
    break;

  case 314:
#line 2297 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->in_def++;
                      (yyval.nd) = local_switch(p);
                    ;}
    break;

  case 315:
#line 2304 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_def(p, (yyvsp[(2) - (7)].id), (yyvsp[(5) - (7)].nd), (yyvsp[(6) - (7)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (7)].num));
                      local_resume(p, (yyvsp[(4) - (7)].nd));
                      p->in_def--;
                      p->cmdarg_stack = (yyvsp[(3) - (7)].stack);
                    ;}
    break;

  case 316:
#line 2312 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lstate = EXPR_FNAME;
                      (yyval.stack) = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    ;}
    break;

  case 317:
#line 2318 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->in_single++;
                      p->lstate = EXPR_ENDFN; /* force for args */
                      (yyval.nd) = local_switch(p);
                    ;}
    break;

  case 318:
#line 2326 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_sdef(p, (yyvsp[(2) - (9)].nd), (yyvsp[(5) - (9)].id), (yyvsp[(7) - (9)].nd), (yyvsp[(8) - (9)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(1) - (9)].num));
                      local_resume(p, (yyvsp[(6) - (9)].nd));
                      p->in_single--;
                      p->cmdarg_stack = (yyvsp[(4) - (9)].stack);
                    ;}
    break;

  case 319:
#line 2334 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_break(p, 0);
                    ;}
    break;

  case 320:
#line 2338 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_next(p, 0);
                    ;}
    break;

  case 321:
#line 2342 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_redo(p);
                    ;}
    break;

  case 322:
#line 2346 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_retry(p);
                    ;}
    break;

  case 323:
#line 2352 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (1)].nd);
                      if (!(yyval.nd)) (yyval.nd) = new_nil(p);
                    ;}
    break;

  case 330:
#line 2371 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_if(p, cond((yyvsp[(2) - (5)].nd)), (yyvsp[(4) - (5)].nd), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 332:
#line 2378 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 333:
#line 2384 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1(list1((yyvsp[(1) - (1)].nd)));
                    ;}
    break;

  case 335:
#line 2391 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_arg(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 336:
#line 2395 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_masgn(p, (yyvsp[(2) - (3)].nd), 0);
                    ;}
    break;

  case 337:
#line 2401 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 338:
#line 2405 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 339:
#line 2411 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3((yyvsp[(1) - (1)].nd),0,0);
                    ;}
    break;

  case 340:
#line 2415 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3((yyvsp[(1) - (4)].nd), new_arg(p, (yyvsp[(4) - (4)].id)), 0);
                    ;}
    break;

  case 341:
#line 2419 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3((yyvsp[(1) - (6)].nd), new_arg(p, (yyvsp[(4) - (6)].id)), (yyvsp[(6) - (6)].nd));
                    ;}
    break;

  case 342:
#line 2423 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3((yyvsp[(1) - (3)].nd), (node*)-1, 0);
                    ;}
    break;

  case 343:
#line 2427 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3((yyvsp[(1) - (5)].nd), (node*)-1, (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 344:
#line 2431 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3(0, new_arg(p, (yyvsp[(2) - (2)].id)), 0);
                    ;}
    break;

  case 345:
#line 2435 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3(0, new_arg(p, (yyvsp[(2) - (4)].id)), (yyvsp[(4) - (4)].nd));
                    ;}
    break;

  case 346:
#line 2439 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3(0, (node*)-1, 0);
                    ;}
    break;

  case 347:
#line 2443 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list3(0, (node*)-1, (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 348:
#line 2449 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (6)].nd), (yyvsp[(3) - (6)].nd), (yyvsp[(5) - (6)].id), 0, (yyvsp[(6) - (6)].id));
                    ;}
    break;

  case 349:
#line 2453 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (8)].nd), (yyvsp[(3) - (8)].nd), (yyvsp[(5) - (8)].id), (yyvsp[(7) - (8)].nd), (yyvsp[(8) - (8)].id));
                    ;}
    break;

  case 350:
#line 2457 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].nd), 0, 0, (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 351:
#line 2461 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (6)].nd), (yyvsp[(3) - (6)].nd), 0, (yyvsp[(5) - (6)].nd), (yyvsp[(6) - (6)].id));
                    ;}
    break;

  case 352:
#line 2465 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (4)].nd), 0, (yyvsp[(3) - (4)].id), 0, (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 353:
#line 2469 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (2)].nd), 0, 0, 0, 0);
                    ;}
    break;

  case 354:
#line 2473 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (6)].nd), 0, (yyvsp[(3) - (6)].id), (yyvsp[(5) - (6)].nd), (yyvsp[(6) - (6)].id));
                    ;}
    break;

  case 355:
#line 2477 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (2)].nd), 0, 0, 0, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 356:
#line 2481 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].id), 0, (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 357:
#line 2485 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, (yyvsp[(1) - (6)].nd), (yyvsp[(3) - (6)].id), (yyvsp[(5) - (6)].nd), (yyvsp[(6) - (6)].id));
                    ;}
    break;

  case 358:
#line 2489 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, (yyvsp[(1) - (2)].nd), 0, 0, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 359:
#line 2493 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, (yyvsp[(1) - (4)].nd), 0, (yyvsp[(3) - (4)].nd), (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 360:
#line 2497 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, 0, (yyvsp[(1) - (2)].id), 0, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 361:
#line 2501 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, 0, (yyvsp[(1) - (4)].id), (yyvsp[(3) - (4)].nd), (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 362:
#line 2505 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, 0, 0, 0, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 364:
#line 2512 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->cmd_start = TRUE;
                      (yyval.nd) = (yyvsp[(1) - (1)].nd);
                    ;}
    break;

  case 365:
#line 2519 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = 0;
                    ;}
    break;

  case 366:
#line 2523 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = 0;
                    ;}
    break;

  case 367:
#line 2527 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (4)].nd);
                    ;}
    break;

  case 368:
#line 2534 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = 0;
                    ;}
    break;

  case 369:
#line 2538 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = 0;
                    ;}
    break;

  case 372:
#line 2548 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_add_f(p, (yyvsp[(1) - (1)].id));
                      new_bv(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 374:
#line 2556 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (4)].nd);
                    ;}
    break;

  case 375:
#line 2560 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (1)].nd);
                    ;}
    break;

  case 376:
#line 2566 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (3)].nd);
                    ;}
    break;

  case 377:
#line 2570 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (3)].nd);
                    ;}
    break;

  case 378:
#line 2576 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_nest(p);
                    ;}
    break;

  case 379:
#line 2582 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_block(p,(yyvsp[(3) - (5)].nd),(yyvsp[(4) - (5)].nd));
                      local_unnest(p);
                    ;}
    break;

  case 380:
#line 2589 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if ((yyvsp[(1) - (2)].nd)->car == (node*)NODE_YIELD) {
                        yyerror(p, "block given to yield");
                      }
                      else {
                        call_with_block(p, (yyvsp[(1) - (2)].nd), (yyvsp[(2) - (2)].nd));
                      }
                      (yyval.nd) = (yyvsp[(1) - (2)].nd);
                    ;}
    break;

  case 381:
#line 2599 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].id), (yyvsp[(4) - (4)].nd), (yyvsp[(2) - (4)].num));
                    ;}
    break;

  case 382:
#line 2603 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), (yyvsp[(4) - (5)].nd), (yyvsp[(2) - (5)].num));
                      call_with_block(p, (yyval.nd), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 383:
#line 2608 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (5)].nd), (yyvsp[(3) - (5)].id), (yyvsp[(4) - (5)].nd), (yyvsp[(2) - (5)].num));
                      call_with_block(p, (yyval.nd), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 384:
#line 2615 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_fcall(p, (yyvsp[(1) - (2)].id), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 385:
#line 2619 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].id), (yyvsp[(4) - (4)].nd), (yyvsp[(2) - (4)].num));
                    ;}
    break;

  case 386:
#line 2623 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].id), (yyvsp[(4) - (4)].nd), tCOLON2);
                    ;}
    break;

  case 387:
#line 2627 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].id), 0, tCOLON2);
                    ;}
    break;

  case 388:
#line 2631 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), intern("call",4), (yyvsp[(3) - (3)].nd), (yyvsp[(2) - (3)].num));
                    ;}
    break;

  case 389:
#line 2635 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (3)].nd), intern("call",4), (yyvsp[(3) - (3)].nd), tCOLON2);
                    ;}
    break;

  case 390:
#line 2639 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_super(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 391:
#line 2643 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_zsuper(p);
                    ;}
    break;

  case 392:
#line 2647 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_call(p, (yyvsp[(1) - (4)].nd), intern("[]",2), (yyvsp[(3) - (4)].nd), '.');
                    ;}
    break;

  case 393:
#line 2653 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_nest(p);
                      (yyval.num) = p->lineno;
                    ;}
    break;

  case 394:
#line 2659 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_block(p,(yyvsp[(3) - (5)].nd),(yyvsp[(4) - (5)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(2) - (5)].num));
                      local_unnest(p);
                    ;}
    break;

  case 395:
#line 2665 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_nest(p);
                      (yyval.num) = p->lineno;
                    ;}
    break;

  case 396:
#line 2671 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_block(p,(yyvsp[(3) - (5)].nd),(yyvsp[(4) - (5)].nd));
                      SET_LINENO((yyval.nd), (yyvsp[(2) - (5)].num));
                      local_unnest(p);
                    ;}
    break;

  case 397:
#line 2681 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = cons(cons((yyvsp[(2) - (5)].nd), (yyvsp[(4) - (5)].nd)), (yyvsp[(5) - (5)].nd));
                    ;}
    break;

  case 398:
#line 2687 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if ((yyvsp[(1) - (1)].nd)) {
                        (yyval.nd) = cons(cons(0, (yyvsp[(1) - (1)].nd)), 0);
                      }
                      else {
                        (yyval.nd) = 0;
                      }
                    ;}
    break;

  case 400:
#line 2701 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1(list3((yyvsp[(2) - (6)].nd), (yyvsp[(3) - (6)].nd), (yyvsp[(5) - (6)].nd)));
                      if ((yyvsp[(6) - (6)].nd)) (yyval.nd) = append((yyval.nd), (yyvsp[(6) - (6)].nd));
                    ;}
    break;

  case 402:
#line 2709 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                        (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 405:
#line 2717 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 407:
#line 2724 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 415:
#line 2739 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 416:
#line 2743 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_dstr(p, push((yyvsp[(2) - (3)].nd), (yyvsp[(3) - (3)].nd)));
                    ;}
    break;

  case 418:
#line 2750 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = append((yyvsp[(1) - (2)].nd), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 419:
#line 2756 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 420:
#line 2760 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = p->lex_strterm;
                      p->lex_strterm = NULL;
                    ;}
    break;

  case 421:
#line 2766 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lex_strterm = (yyvsp[(2) - (4)].nd);
                      (yyval.nd) = list2((yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].nd));
                    ;}
    break;

  case 422:
#line 2771 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1(new_literal_delim(p));
                    ;}
    break;

  case 423:
#line 2775 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1(new_literal_delim(p));
                    ;}
    break;

  case 424:
#line 2781 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                        (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 425:
#line 2785 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_dxstr(p, push((yyvsp[(2) - (3)].nd), (yyvsp[(3) - (3)].nd)));
                    ;}
    break;

  case 426:
#line 2791 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                        (yyval.nd) = (yyvsp[(2) - (2)].nd);
                    ;}
    break;

  case 427:
#line 2795 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_dregx(p, (yyvsp[(2) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 431:
#line 2808 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      parser_heredoc_info * inf = parsing_heredoc_inf(p);
                      inf->doc = push(inf->doc, new_str(p, "", 0));
                      heredoc_end(p);
                    ;}
    break;

  case 432:
#line 2814 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      heredoc_end(p);
                    ;}
    break;

  case 435:
#line 2824 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      parser_heredoc_info * inf = parsing_heredoc_inf(p);
                      inf->doc = push(inf->doc, (yyvsp[(1) - (1)].nd));
                      heredoc_treat_nextline(p);
                    ;}
    break;

  case 436:
#line 2830 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = p->lex_strterm;
                      p->lex_strterm = NULL;
                    ;}
    break;

  case 437:
#line 2836 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      parser_heredoc_info * inf = parsing_heredoc_inf(p);
                      p->lex_strterm = (yyvsp[(2) - (4)].nd);
                      inf->doc = push(push(inf->doc, (yyvsp[(1) - (4)].nd)), (yyvsp[(3) - (4)].nd));
                    ;}
    break;

  case 438:
#line 2844 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_words(p, list1((yyvsp[(2) - (2)].nd)));
                    ;}
    break;

  case 439:
#line 2848 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_words(p, push((yyvsp[(2) - (3)].nd), (yyvsp[(3) - (3)].nd)));
                    ;}
    break;

  case 440:
#line 2855 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_sym(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 441:
#line 2859 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lstate = EXPR_END;
                      (yyval.nd) = new_dsym(p, push((yyvsp[(3) - (4)].nd), (yyvsp[(4) - (4)].nd)));
                    ;}
    break;

  case 442:
#line 2866 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lstate = EXPR_END;
                      (yyval.id) = (yyvsp[(2) - (2)].id);
                    ;}
    break;

  case 447:
#line 2877 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.id) = new_strsym(p, (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 448:
#line 2881 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.id) = new_strsym(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 449:
#line 2887 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_symbols(p, list1((yyvsp[(2) - (2)].nd)));
                    ;}
    break;

  case 450:
#line 2891 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_symbols(p, push((yyvsp[(2) - (3)].nd), (yyvsp[(3) - (3)].nd)));
                    ;}
    break;

  case 453:
#line 2899 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = negate_lit(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 454:
#line 2903 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = negate_lit(p, (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 455:
#line 2909 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_lvar(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 456:
#line 2913 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_ivar(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 457:
#line 2917 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_gvar(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 458:
#line 2921 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_cvar(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 459:
#line 2925 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_const(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 460:
#line 2931 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      assignable(p, (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 461:
#line 2937 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = var_reference(p, (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 462:
#line 2941 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_nil(p);
                    ;}
    break;

  case 463:
#line 2945 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_self(p);
                    ;}
    break;

  case 464:
#line 2949 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_true(p);
                    ;}
    break;

  case 465:
#line 2953 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_false(p);
                    ;}
    break;

  case 466:
#line 2957 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      const char *fn = p->filename;
                      if (!fn) {
                        fn = "(null)";
                      }
                      (yyval.nd) = new_str(p, fn, strlen(fn));
                    ;}
    break;

  case 467:
#line 2965 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      char buf[16];

                      snprintf(buf, sizeof(buf), "%d", p->lineno);
                      (yyval.nd) = new_int(p, buf, 10);
                    ;}
    break;

  case 470:
#line 2978 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = 0;
                    ;}
    break;

  case 471:
#line 2982 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lstate = EXPR_BEG;
                      p->cmd_start = TRUE;
                    ;}
    break;

  case 472:
#line 2987 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(3) - (4)].nd);
                    ;}
    break;

  case 473:
#line 2998 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(2) - (3)].nd);
                      p->lstate = EXPR_BEG;
                      p->cmd_start = TRUE;
                    ;}
    break;

  case 474:
#line 3004 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (2)].nd);
                    ;}
    break;

  case 475:
#line 3010 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (6)].nd), (yyvsp[(3) - (6)].nd), (yyvsp[(5) - (6)].id), 0, (yyvsp[(6) - (6)].id));
                    ;}
    break;

  case 476:
#line 3014 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (8)].nd), (yyvsp[(3) - (8)].nd), (yyvsp[(5) - (8)].id), (yyvsp[(7) - (8)].nd), (yyvsp[(8) - (8)].id));
                    ;}
    break;

  case 477:
#line 3018 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].nd), 0, 0, (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 478:
#line 3022 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (6)].nd), (yyvsp[(3) - (6)].nd), 0, (yyvsp[(5) - (6)].nd), (yyvsp[(6) - (6)].id));
                    ;}
    break;

  case 479:
#line 3026 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (4)].nd), 0, (yyvsp[(3) - (4)].id), 0, (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 480:
#line 3030 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (6)].nd), 0, (yyvsp[(3) - (6)].id), (yyvsp[(5) - (6)].nd), (yyvsp[(6) - (6)].id));
                    ;}
    break;

  case 481:
#line 3034 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, (yyvsp[(1) - (2)].nd), 0, 0, 0, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 482:
#line 3038 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, (yyvsp[(1) - (4)].nd), (yyvsp[(3) - (4)].id), 0, (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 483:
#line 3042 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, (yyvsp[(1) - (6)].nd), (yyvsp[(3) - (6)].id), (yyvsp[(5) - (6)].nd), (yyvsp[(6) - (6)].id));
                    ;}
    break;

  case 484:
#line 3046 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, (yyvsp[(1) - (2)].nd), 0, 0, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 485:
#line 3050 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, (yyvsp[(1) - (4)].nd), 0, (yyvsp[(3) - (4)].nd), (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 486:
#line 3054 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, 0, (yyvsp[(1) - (2)].id), 0, (yyvsp[(2) - (2)].id));
                    ;}
    break;

  case 487:
#line 3058 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, 0, (yyvsp[(1) - (4)].id), (yyvsp[(3) - (4)].nd), (yyvsp[(4) - (4)].id));
                    ;}
    break;

  case 488:
#line 3062 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_args(p, 0, 0, 0, 0, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 489:
#line 3066 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_add_f(p, 0);
                      (yyval.nd) = new_args(p, 0, 0, 0, 0, 0);
                    ;}
    break;

  case 490:
#line 3073 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "formal argument cannot be a constant");
                      (yyval.nd) = 0;
                    ;}
    break;

  case 491:
#line 3078 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "formal argument cannot be an instance variable");
                      (yyval.nd) = 0;
                    ;}
    break;

  case 492:
#line 3083 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "formal argument cannot be a global variable");
                      (yyval.nd) = 0;
                    ;}
    break;

  case 493:
#line 3088 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      yyerror(p, "formal argument cannot be a class variable");
                      (yyval.nd) = 0;
                    ;}
    break;

  case 494:
#line 3095 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.id) = 0;
                    ;}
    break;

  case 495:
#line 3099 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_add_f(p, (yyvsp[(1) - (1)].id));
                      (yyval.id) = (yyvsp[(1) - (1)].id);
                    ;}
    break;

  case 496:
#line 3106 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_arg(p, (yyvsp[(1) - (1)].id));
                    ;}
    break;

  case 497:
#line 3110 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = new_masgn(p, (yyvsp[(2) - (3)].nd), 0);
                    ;}
    break;

  case 498:
#line 3116 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 499:
#line 3120 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 500:
#line 3126 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_add_f(p, (yyvsp[(1) - (2)].id));
                      (yyval.id) = (yyvsp[(1) - (2)].id);
                    ;}
    break;

  case 501:
#line 3133 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(2) - (2)].nd));
                      (yyval.nd) = cons(nsym((yyvsp[(1) - (2)].id)), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 502:
#line 3140 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(2) - (2)].nd));
                      (yyval.nd) = cons(nsym((yyvsp[(1) - (2)].id)), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 503:
#line 3147 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 504:
#line 3151 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 505:
#line 3157 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 506:
#line 3161 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 509:
#line 3171 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_add_f(p, (yyvsp[(2) - (2)].id));
                      (yyval.id) = (yyvsp[(2) - (2)].id);
                    ;}
    break;

  case 510:
#line 3176 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_add_f(p, 0);
                      (yyval.id) = -1;
                    ;}
    break;

  case 513:
#line 3187 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_add_f(p, (yyvsp[(2) - (2)].id));
                      (yyval.id) = (yyvsp[(2) - (2)].id);
                    ;}
    break;

  case 514:
#line 3194 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.id) = (yyvsp[(2) - (2)].id);
                    ;}
    break;

  case 515:
#line 3198 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      local_add_f(p, 0);
                      (yyval.id) = 0;
                    ;}
    break;

  case 516:
#line 3205 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (1)].nd);
                      if (!(yyval.nd)) (yyval.nd) = new_nil(p);
                    ;}
    break;

  case 517:
#line 3209 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {p->lstate = EXPR_BEG;;}
    break;

  case 518:
#line 3210 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      if ((yyvsp[(3) - (4)].nd) == 0) {
                        yyerror(p, "can't define singleton method for ().");
                      }
                      else {
                        switch ((enum node_type)intn((yyvsp[(3) - (4)].nd)->car)) {
                        case NODE_STR:
                        case NODE_DSTR:
                        case NODE_XSTR:
                        case NODE_DXSTR:
                        case NODE_DREGX:
                        case NODE_MATCH:
                        case NODE_FLOAT:
                        case NODE_ARRAY:
                        case NODE_HEREDOC:
                          yyerror(p, "can't define singleton method for literals");
                        default:
                          break;
                        }
                      }
                      (yyval.nd) = (yyvsp[(3) - (4)].nd);
                    ;}
    break;

  case 520:
#line 3236 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = (yyvsp[(1) - (2)].nd);
                    ;}
    break;

  case 521:
#line 3242 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = list1((yyvsp[(1) - (1)].nd));
                      NODE_LINENO((yyval.nd), (yyvsp[(1) - (1)].nd));
                    ;}
    break;

  case 522:
#line 3247 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = push((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 523:
#line 3253 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(1) - (3)].nd));
                      void_expr_error(p, (yyvsp[(3) - (3)].nd));
                      (yyval.nd) = cons((yyvsp[(1) - (3)].nd), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 524:
#line 3259 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(2) - (2)].nd));
                      (yyval.nd) = cons(new_sym(p, (yyvsp[(1) - (2)].id)), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 525:
#line 3264 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(2) - (2)].nd));
                      (yyval.nd) = cons(new_sym(p, new_strsym(p, (yyvsp[(1) - (2)].nd))), (yyvsp[(2) - (2)].nd));
                    ;}
    break;

  case 526:
#line 3269 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(3) - (3)].nd));
                      (yyval.nd) = cons(new_sym(p, new_strsym(p, (yyvsp[(2) - (3)].nd))), (yyvsp[(3) - (3)].nd));
                    ;}
    break;

  case 527:
#line 3274 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      void_expr_error(p, (yyvsp[(4) - (4)].nd));
                      (yyval.nd) = cons(new_dsym(p, push((yyvsp[(2) - (4)].nd), (yyvsp[(3) - (4)].nd))), (yyvsp[(4) - (4)].nd));
                    ;}
    break;

  case 540:
#line 3301 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.num) = '.';
                    ;}
    break;

  case 541:
#line 3305 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.num) = 0;
                    ;}
    break;

  case 543:
#line 3312 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.num) = tCOLON2;
                    ;}
    break;

  case 553:
#line 3336 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {yyerrok;;}
    break;

  case 556:
#line 3342 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      p->lineno++;
                      p->column = 0;
                    ;}
    break;

  case 559:
#line 3353 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"
    {
                      (yyval.nd) = 0;
                    ;}
    break;


/* Line 1267 of yacc.c.  */
#line 8719 "/Users/travisgalloway/github/h2o/mruby/host/mrbgems/mruby-compiler/core/y.tab.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (p, YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (p, yymsg);
	  }
	else
	  {
	    yyerror (p, YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, p);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp, p);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (p, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, p);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, p);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 3357 "/Users/travisgalloway/github/h2o/deps/mruby/mrbgems/mruby-compiler/core/parse.y"

#define pylval  (*((YYSTYPE*)(p->ylval)))

static void
yyerror(parser_state *p, const char *s)
{
  char* c;
  int n;

  if (! p->capture_errors) {
#ifndef MRB_DISABLE_STDIO
    if (p->filename) {
      fprintf(stderr, "%s:%d:%d: %s\n", p->filename, p->lineno, p->column, s);
    }
    else {
      fprintf(stderr, "line %d:%d: %s\n", p->lineno, p->column, s);
    }
#endif
  }
  else if (p->nerr < sizeof(p->error_buffer) / sizeof(p->error_buffer[0])) {
    n = strlen(s);
    c = (char *)parser_palloc(p, n + 1);
    memcpy(c, s, n + 1);
    p->error_buffer[p->nerr].message = c;
    p->error_buffer[p->nerr].lineno = p->lineno;
    p->error_buffer[p->nerr].column = p->column;
  }
  p->nerr++;
}

static void
yyerror_i(parser_state *p, const char *fmt, int i)
{
  char buf[256];

  snprintf(buf, sizeof(buf), fmt, i);
  yyerror(p, buf);
}

static void
yywarn(parser_state *p, const char *s)
{
  char* c;
  int n;

  if (! p->capture_errors) {
#ifndef MRB_DISABLE_STDIO
    if (p->filename) {
      fprintf(stderr, "%s:%d:%d: %s\n", p->filename, p->lineno, p->column, s);
    }
    else {
      fprintf(stderr, "line %d:%d: %s\n", p->lineno, p->column, s);
    }
#endif
  }
  else if (p->nwarn < sizeof(p->warn_buffer) / sizeof(p->warn_buffer[0])) {
    n = strlen(s);
    c = (char *)parser_palloc(p, n + 1);
    memcpy(c, s, n + 1);
    p->warn_buffer[p->nwarn].message = c;
    p->warn_buffer[p->nwarn].lineno = p->lineno;
    p->warn_buffer[p->nwarn].column = p->column;
  }
  p->nwarn++;
}

static void
yywarning(parser_state *p, const char *s)
{
  yywarn(p, s);
}

static void
yywarning_s(parser_state *p, const char *fmt, const char *s)
{
  char buf[256];

  snprintf(buf, sizeof(buf), fmt, s);
  yywarning(p, buf);
}

static void
backref_error(parser_state *p, node *n)
{
  int c;

  c = (int)(intptr_t)n->car;

  if (c == NODE_NTH_REF) {
    yyerror_i(p, "can't set variable $%" MRB_PRId, (mrb_int)(intptr_t)n->cdr);
  }
  else if (c == NODE_BACK_REF) {
    yyerror_i(p, "can't set variable $%c", (int)(intptr_t)n->cdr);
  }
  else {
    mrb_bug(p->mrb, "Internal error in backref_error() : n=>car == %S", mrb_fixnum_value(c));
  }
}

static void
void_expr_error(parser_state *p, node *n)
{
  int c;

  if (n == NULL) return;
  c = (int)(intptr_t)n->car;
  switch (c) {
  case NODE_BREAK:
  case NODE_RETURN:
  case NODE_NEXT:
  case NODE_REDO:
  case NODE_RETRY:
    yyerror(p, "void value expression");
    break;
  case NODE_AND:
  case NODE_OR:
    void_expr_error(p, n->cdr->car);
    void_expr_error(p, n->cdr->cdr);
    break;
  case NODE_BEGIN:
    if (n->cdr) {
      while (n->cdr) {
        n = n->cdr;
      }
      void_expr_error(p, n->car);
    }
    break;
  default:
    break;
  }
}

static void pushback(parser_state *p, int c);
static mrb_bool peeks(parser_state *p, const char *s);
static mrb_bool skips(parser_state *p, const char *s);

static inline int
nextc(parser_state *p)
{
  int c;

  if (p->pb) {
    node *tmp;

    c = (int)(intptr_t)p->pb->car;
    tmp = p->pb;
    p->pb = p->pb->cdr;
    cons_free(tmp);
  }
  else {
#ifndef MRB_DISABLE_STDIO
    if (p->f) {
      if (feof(p->f)) goto eof;
      c = fgetc(p->f);
      if (c == EOF) goto eof;
    }
    else
#endif
      if (!p->s || p->s >= p->send) {
        goto eof;
      }
      else {
        c = (unsigned char)*p->s++;
      }
  }
  if (c >= 0) {
    p->column++;
  }
  if (c == '\r') {
    c = nextc(p);
    if (c != '\n') {
      pushback(p, c);
      return '\r';
    }
    return c;
  }
  return c;

  eof:
  if (!p->cxt) return -1;
  else {
    if (p->cxt->partial_hook(p) < 0)
      return -1;                /* end of program(s) */
    return -2;                  /* end of a file in the program files */
  }
}

static void
pushback(parser_state *p, int c)
{
  if (c >= 0) {
    p->column--;
  }
  p->pb = cons((node*)(intptr_t)c, p->pb);
}

static void
skip(parser_state *p, char term)
{
  int c;

  for (;;) {
    c = nextc(p);
    if (c < 0) break;
    if (c == term) break;
  }
}

static int
peekc_n(parser_state *p, int n)
{
  node *list = 0;
  int c0;

  do {
    c0 = nextc(p);
    if (c0 == -1) return c0;    /* do not skip partial EOF */
    if (c0 >= 0) --p->column;
    list = push(list, (node*)(intptr_t)c0);
  } while(n--);
  if (p->pb) {
    p->pb = append((node*)list, p->pb);
  }
  else {
    p->pb = list;
  }
  return c0;
}

static mrb_bool
peek_n(parser_state *p, int c, int n)
{
  return peekc_n(p, n) == c && c >= 0;
}
#define peek(p,c) peek_n((p), (c), 0)

static mrb_bool
peeks(parser_state *p, const char *s)
{
  int len = strlen(s);

#ifndef MRB_DISABLE_STDIO
  if (p->f) {
    int n = 0;
    while (*s) {
      if (!peek_n(p, *s++, n++)) return FALSE;
    }
    return TRUE;
  }
  else
#endif
    if (p->s && p->s + len <= p->send) {
      if (memcmp(p->s, s, len) == 0) return TRUE;
    }
  return FALSE;
}

static mrb_bool
skips(parser_state *p, const char *s)
{
  int c;

  for (;;) {
    /* skip until first char */
    for (;;) {
      c = nextc(p);
      if (c < 0) return FALSE;
      if (c == '\n') {
        p->lineno++;
        p->column = 0;
      }
      if (c == *s) break;
    }
    s++;
    if (peeks(p, s)) {
      int len = strlen(s);

      while (len--) {
        if (nextc(p) == '\n') {
          p->lineno++;
          p->column = 0;
        }
      }
      return TRUE;
    }
    else{
      s--;
    }
  }
  return FALSE;
}


static int
newtok(parser_state *p)
{
  if (p->tokbuf != p->buf) {
    mrb_free(p->mrb, p->tokbuf);
    p->tokbuf = p->buf;
    p->tsiz = MRB_PARSER_TOKBUF_SIZE;
  }
  p->tidx = 0;
  return p->column - 1;
}

static void
tokadd(parser_state *p, int32_t c)
{
  char utf8[4];
  int i, len;

  /* mrb_assert(-0x10FFFF <= c && c <= 0xFF); */
  if (c >= 0) {
    /* Single byte from source or non-Unicode escape */
    utf8[0] = (char)c;
    len = 1;
  }
  else {
    /* Unicode character */
    c = -c;
    if (c < 0x80) {
      utf8[0] = (char)c;
      len = 1;
    }
    else if (c < 0x800) {
      utf8[0] = (char)(0xC0 | (c >> 6));
      utf8[1] = (char)(0x80 | (c & 0x3F));
      len = 2;
    }
    else if (c < 0x10000) {
      utf8[0] = (char)(0xE0 |  (c >> 12)        );
      utf8[1] = (char)(0x80 | ((c >>  6) & 0x3F));
      utf8[2] = (char)(0x80 | ( c        & 0x3F));
      len = 3;
    }
    else {
      utf8[0] = (char)(0xF0 |  (c >> 18)        );
      utf8[1] = (char)(0x80 | ((c >> 12) & 0x3F));
      utf8[2] = (char)(0x80 | ((c >>  6) & 0x3F));
      utf8[3] = (char)(0x80 | ( c        & 0x3F));
      len = 4;
    }
  }
  if (p->tidx+len >= p->tsiz) {
    if (p->tsiz >= MRB_PARSER_TOKBUF_MAX) {
      p->tidx += len;
      return;
    }
    p->tsiz *= 2;
    if (p->tokbuf == p->buf) {
      p->tokbuf = (char*)mrb_malloc(p->mrb, p->tsiz);
      memcpy(p->tokbuf, p->buf, MRB_PARSER_TOKBUF_SIZE);
    }
    else {
      p->tokbuf = (char*)mrb_realloc(p->mrb, p->tokbuf, p->tsiz);
    }
  }
  for (i = 0; i < len; i++) {
    p->tokbuf[p->tidx++] = utf8[i];
  }
}

static int
toklast(parser_state *p)
{
  return p->tokbuf[p->tidx-1];
}

static void
tokfix(parser_state *p)
{
  if (p->tidx >= MRB_PARSER_TOKBUF_MAX) {
    p->tidx = MRB_PARSER_TOKBUF_MAX-1;
    yyerror(p, "string too long (truncated)");
  }
  p->tokbuf[p->tidx] = '\0';
}

static const char*
tok(parser_state *p)
{
  return p->tokbuf;
}

static int
toklen(parser_state *p)
{
  return p->tidx;
}

#define IS_ARG() (p->lstate == EXPR_ARG || p->lstate == EXPR_CMDARG)
#define IS_END() (p->lstate == EXPR_END || p->lstate == EXPR_ENDARG || p->lstate == EXPR_ENDFN)
#define IS_BEG() (p->lstate == EXPR_BEG || p->lstate == EXPR_MID || p->lstate == EXPR_VALUE || p->lstate == EXPR_CLASS)
#define IS_SPCARG(c) (IS_ARG() && space_seen && !ISSPACE(c))
#define IS_LABEL_POSSIBLE() ((p->lstate == EXPR_BEG && !cmd_state) || IS_ARG())
#define IS_LABEL_SUFFIX(n) (peek_n(p, ':',(n)) && !peek_n(p, ':', (n)+1))

static int
scan_oct(const int *start, int len, int *retlen)
{
  const int *s = start;
  int retval = 0;

  /* mrb_assert(len <= 3) */
  while (len-- && *s >= '0' && *s <= '7') {
    retval <<= 3;
    retval |= *s++ - '0';
  }
  *retlen = s - start;

  return retval;
}

static int32_t
scan_hex(const int *start, int len, int *retlen)
{
  static const char hexdigit[] = "0123456789abcdef0123456789ABCDEF";
  const int *s = start;
  int32_t retval = 0;
  char *tmp;

  /* mrb_assert(len <= 8) */
  while (len-- && *s && (tmp = (char*)strchr(hexdigit, *s))) {
    retval <<= 4;
    retval |= (tmp - hexdigit) & 15;
    s++;
  }
  *retlen = s - start;

  return retval;
}

static int32_t
read_escape_unicode(parser_state *p, int limit)
{
  int32_t c;
  int buf[9];
  int i;

  /* Look for opening brace */
  i = 0;
  buf[0] = nextc(p);
  if (buf[0] < 0) goto eof;
  if (ISXDIGIT(buf[0])) {
    /* \uxxxx form */
    for (i=1; i<limit; i++) {
      buf[i] = nextc(p);
      if (buf[i] < 0) goto eof;
      if (!ISXDIGIT(buf[i])) {
        pushback(p, buf[i]);
        break;
      }
    }
  }
  else {
    pushback(p, buf[0]);
  }
  c = scan_hex(buf, i, &i);
  if (i == 0) {
  eof:
    yyerror(p, "Invalid escape character syntax");
    return -1;
  }
  if (c < 0 || c > 0x10FFFF || (c & 0xFFFFF800) == 0xD800) {
    yyerror(p, "Invalid Unicode code point");
    return -1;
  }
  return c;
}

/* Return negative to indicate Unicode code point */
static int32_t
read_escape(parser_state *p)
{
  int32_t c;

  switch (c = nextc(p)) {
  case '\\':/* Backslash */
    return c;

  case 'n':/* newline */
    return '\n';

  case 't':/* horizontal tab */
    return '\t';

  case 'r':/* carriage-return */
    return '\r';

  case 'f':/* form-feed */
    return '\f';

  case 'v':/* vertical tab */
    return '\13';

  case 'a':/* alarm(bell) */
    return '\007';

  case 'e':/* escape */
    return 033;

  case '0': case '1': case '2': case '3': /* octal constant */
  case '4': case '5': case '6': case '7':
  {
    int buf[3];
    int i;

    buf[0] = c;
    for (i=1; i<3; i++) {
      buf[i] = nextc(p);
      if (buf[i] < 0) goto eof;
      if (buf[i] < '0' || '7' < buf[i]) {
        pushback(p, buf[i]);
        break;
      }
    }
    c = scan_oct(buf, i, &i);
  }
  return c;

  case 'x':     /* hex constant */
  {
    int buf[2];
    int i;

    for (i=0; i<2; i++) {
      buf[i] = nextc(p);
      if (buf[i] < 0) goto eof;
      if (!ISXDIGIT(buf[i])) {
        pushback(p, buf[i]);
        break;
      }
    }
    c = scan_hex(buf, i, &i);
    if (i == 0) {
      yyerror(p, "Invalid escape character syntax");
      return 0;
    }
  }
  return c;

  case 'u':     /* Unicode */
    if (peek(p, '{')) {
      /* \u{xxxxxxxx} form */
      nextc(p);
      c = read_escape_unicode(p, 8);
      if (c < 0) return 0;
      if (nextc(p) != '}') goto eof;
    }
    else {
      c = read_escape_unicode(p, 4);
      if (c < 0) return 0;
    }
  return -c;

  case 'b':/* backspace */
    return '\010';

  case 's':/* space */
    return ' ';

  case 'M':
    if ((c = nextc(p)) != '-') {
      yyerror(p, "Invalid escape character syntax");
      pushback(p, c);
      return '\0';
    }
    if ((c = nextc(p)) == '\\') {
      return read_escape(p) | 0x80;
    }
    else if (c < 0) goto eof;
    else {
      return ((c & 0xff) | 0x80);
    }

  case 'C':
    if ((c = nextc(p)) != '-') {
      yyerror(p, "Invalid escape character syntax");
      pushback(p, c);
      return '\0';
    }
  case 'c':
    if ((c = nextc(p))== '\\') {
      c = read_escape(p);
    }
    else if (c == '?')
      return 0177;
    else if (c < 0) goto eof;
    return c & 0x9f;

    eof:
  case -1:
  case -2:                      /* end of a file */
    yyerror(p, "Invalid escape character syntax");
    return '\0';

  default:
    return c;
  }
}

static int
parse_string(parser_state *p)
{
  int c;
  string_type type = (string_type)(intptr_t)p->lex_strterm->car;
  int nest_level = (intptr_t)p->lex_strterm->cdr->car;
  int beg = (intptr_t)p->lex_strterm->cdr->cdr->car;
  int end = (intptr_t)p->lex_strterm->cdr->cdr->cdr;
  parser_heredoc_info *hinf = (type & STR_FUNC_HEREDOC) ? parsing_heredoc_inf(p) : NULL;
  int cmd_state = p->cmd_start;

  if (beg == 0) beg = -3;       /* should never happen */
  if (end == 0) end = -3;
  newtok(p);
  while ((c = nextc(p)) != end || nest_level != 0) {
    if (hinf && (c == '\n' || c < 0)) {
      mrb_bool line_head;
      tokadd(p, '\n');
      tokfix(p);
      p->lineno++;
      p->column = 0;
      line_head = hinf->line_head;
      hinf->line_head = TRUE;
      if (line_head) {
        /* check whether end of heredoc */
        const char *s = tok(p);
        int len = toklen(p);
        if (hinf->allow_indent) {
          while (ISSPACE(*s) && len > 0) {
            ++s;
            --len;
          }
        }
        if ((len-1 == hinf->term_len) && (strncmp(s, hinf->term, len-1) == 0)) {
          if (c < 0) {
            p->parsing_heredoc = NULL;
          }
          else {
            return tHEREDOC_END;
          }
        }
      }
      if (c < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "can't find heredoc delimiter \"%s\" anywhere before EOF", hinf->term);
        yyerror(p, buf);
        return 0;
      }
      pylval.nd = new_str(p, tok(p), toklen(p));
      return tHD_STRING_MID;
    }
    if (c < 0) {
      yyerror(p, "unterminated string meets end of file");
      return 0;
    }
    else if (c == beg) {
      nest_level++;
      p->lex_strterm->cdr->car = (node*)(intptr_t)nest_level;
    }
    else if (c == end) {
      nest_level--;
      p->lex_strterm->cdr->car = (node*)(intptr_t)nest_level;
    }
    else if (c == '\\') {
      c = nextc(p);
      if (type & STR_FUNC_EXPAND) {
        if (c == end || c == beg) {
          tokadd(p, c);
        }
        else if (c == '\n') {
          p->lineno++;
          p->column = 0;
          if (type & STR_FUNC_ARRAY) {
            tokadd(p, '\n');
          }
        }
        else if (type & STR_FUNC_REGEXP) {
          tokadd(p, '\\');
          tokadd(p, c);
        }
        else if (c == 'u' && peek(p, '{')) {
          /* \u{xxxx xxxx xxxx} form */
          nextc(p);
          while (1) {
            do c = nextc(p); while (ISSPACE(c));
            if (c == '}') break;
            pushback(p, c);
            c = read_escape_unicode(p, 8);
            if (c < 0) break;
            tokadd(p, -c);
          }
          if (hinf)
            hinf->line_head = FALSE;
        }
        else {
          pushback(p, c);
          tokadd(p, read_escape(p));
          if (hinf)
            hinf->line_head = FALSE;
        }
      }
      else {
        if (c != beg && c != end) {
          if (c == '\n') {
            p->lineno++;
            p->column = 0;
          }
          if (!(c == '\\' || ((type & STR_FUNC_ARRAY) && ISSPACE(c)))) {
            tokadd(p, '\\');
          }
        }
        tokadd(p, c);
      }
      continue;
    }
    else if ((c == '#') && (type & STR_FUNC_EXPAND)) {
      c = nextc(p);
      if (c == '{') {
        tokfix(p);
        p->lstate = EXPR_BEG;
        p->cmd_start = TRUE;
        pylval.nd = new_str(p, tok(p), toklen(p));
        if (hinf) {
          hinf->line_head = FALSE;
          return tHD_STRING_PART;
        }
        return tSTRING_PART;
      }
      tokadd(p, '#');
      pushback(p, c);
      continue;
    }
    if ((type & STR_FUNC_ARRAY) && ISSPACE(c)) {
      if (toklen(p) == 0) {
        do {
          if (c == '\n') {
            p->lineno++;
            p->column = 0;
            heredoc_treat_nextline(p);
            if (p->parsing_heredoc != NULL) {
              return tHD_LITERAL_DELIM;
            }
          }
          c = nextc(p);
        } while (ISSPACE(c));
        pushback(p, c);
        return tLITERAL_DELIM;
      }
      else {
        pushback(p, c);
        tokfix(p);
        pylval.nd = new_str(p, tok(p), toklen(p));
        return tSTRING_MID;
      }
    }
    if (c == '\n') {
      p->lineno++;
      p->column = 0;
    }
    tokadd(p, c);
  }

  tokfix(p);
  p->lstate = EXPR_END;
  end_strterm(p);

  if (type & STR_FUNC_XQUOTE) {
    pylval.nd = new_xstr(p, tok(p), toklen(p));
    return tXSTRING;
  }

  if (type & STR_FUNC_REGEXP) {
    int f = 0;
    int re_opt;
    char *s = strndup(tok(p), toklen(p));
    char flags[3];
    char *flag = flags;
    char enc = '\0';
    char *encp;
    char *dup;

    newtok(p);
    while (re_opt = nextc(p), re_opt >= 0 && ISALPHA(re_opt)) {
      switch (re_opt) {
      case 'i': f |= 1; break;
      case 'x': f |= 2; break;
      case 'm': f |= 4; break;
      case 'u': f |= 16; break;
      case 'n': f |= 32; break;
      default: tokadd(p, re_opt); break;
      }
    }
    pushback(p, re_opt);
    if (toklen(p)) {
      char msg[128];
      tokfix(p);
      snprintf(msg, sizeof(msg), "unknown regexp option%s - %s",
          toklen(p) > 1 ? "s" : "", tok(p));
      yyerror(p, msg);
    }
    if (f != 0) {
      if (f & 1) *flag++ = 'i';
      if (f & 2) *flag++ = 'x';
      if (f & 4) *flag++ = 'm';
      if (f & 16) enc = 'u';
      if (f & 32) enc = 'n';
    }
    if (flag > flags) {
      dup = strndup(flags, (size_t)(flag - flags));
    }
    else {
      dup = NULL;
    }
    if (enc) {
      encp = strndup(&enc, 1);
    }
    else {
      encp = NULL;
    }
    pylval.nd = new_regx(p, s, dup, encp);

    return tREGEXP;
  }
  pylval.nd = new_str(p, tok(p), toklen(p));
  if (IS_LABEL_POSSIBLE()) {
    if (IS_LABEL_SUFFIX(0)) {
      p->lstate = EXPR_BEG;
      nextc(p);
      return tLABEL_END;
    }
  }

  return tSTRING;
}


static int
heredoc_identifier(parser_state *p)
{
  int c;
  int type = str_heredoc;
  mrb_bool indent = FALSE;
  mrb_bool quote = FALSE;
  node *newnode;
  parser_heredoc_info *info;

  c = nextc(p);
  if (ISSPACE(c) || c == '=') {
    pushback(p, c);
    return 0;
  }
  if (c == '-') {
    indent = TRUE;
    c = nextc(p);
  }
  if (c == '\'' || c == '"') {
    int term = c;
    if (c == '\'')
      quote = TRUE;
    newtok(p);
    while ((c = nextc(p)) >= 0 && c != term) {
      if (c == '\n') {
        c = -1;
        break;
      }
      tokadd(p, c);
    }
    if (c < 0) {
      yyerror(p, "unterminated here document identifier");
      return 0;
    }
  }
  else {
    if (c < 0) {
      return 0;                 /* missing here document identifier */
    }
    if (! identchar(c)) {
      pushback(p, c);
      if (indent) pushback(p, '-');
      return 0;
    }
    newtok(p);
    do {
      tokadd(p, c);
    } while ((c = nextc(p)) >= 0 && identchar(c));
    pushback(p, c);
  }
  tokfix(p);
  newnode = new_heredoc(p);
  info = (parser_heredoc_info*)newnode->cdr;
  info->term = strndup(tok(p), toklen(p));
  info->term_len = toklen(p);
  if (! quote)
    type |= STR_FUNC_EXPAND;
  info->type = (string_type)type;
  info->allow_indent = indent;
  info->line_head = TRUE;
  info->doc = NULL;
  p->heredocs_from_nextline = push(p->heredocs_from_nextline, newnode);
  p->lstate = EXPR_END;

  pylval.nd = newnode;
  return tHEREDOC_BEG;
}

static int
arg_ambiguous(parser_state *p)
{
  yywarning(p, "ambiguous first argument; put parentheses or even spaces");
  return 1;
}

#include "lex.def"

static int
parser_yylex(parser_state *p)
{
  int32_t c;
  int space_seen = 0;
  int cmd_state;
  enum mrb_lex_state_enum last_state;
  int token_column;

  if (p->lex_strterm) {
    if (is_strterm_type(p, STR_FUNC_HEREDOC)) {
      if (p->parsing_heredoc != NULL)
        return parse_string(p);
    }
    else
      return parse_string(p);
  }
  cmd_state = p->cmd_start;
  p->cmd_start = FALSE;
  retry:
  last_state = p->lstate;
  switch (c = nextc(p)) {
  case '\004':  /* ^D */
  case '\032':  /* ^Z */
  case '\0':    /* NUL */
  case -1:      /* end of script. */
    if (p->heredocs_from_nextline)
      goto maybe_heredoc;
    return 0;

  /* white spaces */
  case ' ': case '\t': case '\f': case '\r':
  case '\13':   /* '\v' */
    space_seen = 1;
    goto retry;

  case '#':     /* it's a comment */
    skip(p, '\n');
    /* fall through */
  case -2:      /* end of a file */
  case '\n':
    maybe_heredoc:
    heredoc_treat_nextline(p);
  switch (p->lstate) {
  case EXPR_BEG:
  case EXPR_FNAME:
  case EXPR_DOT:
  case EXPR_CLASS:
  case EXPR_VALUE:
    p->lineno++;
    p->column = 0;
    if (p->parsing_heredoc != NULL) {
      if (p->lex_strterm) {
        return parse_string(p);
      }
    }
    goto retry;
  default:
    break;
  }
  if (p->parsing_heredoc != NULL) {
    return '\n';
  }
  while ((c = nextc(p))) {
    switch (c) {
    case ' ': case '\t': case '\f': case '\r':
    case '\13': /* '\v' */
      space_seen = 1;
      break;
    case '.':
      if ((c = nextc(p)) != '.') {
        pushback(p, c);
        pushback(p, '.');
        goto retry;
      }
    case -1:                  /* EOF */
    case -2:                  /* end of a file */
      goto normal_newline;
    default:
      pushback(p, c);
      goto normal_newline;
    }
  }
  normal_newline:
  p->cmd_start = TRUE;
  p->lstate = EXPR_BEG;
  return '\n';

  case '*':
    if ((c = nextc(p)) == '*') {
      if ((c = nextc(p)) == '=') {
        pylval.id = intern("**",2);
        p->lstate = EXPR_BEG;
        return tOP_ASGN;
      }
      pushback(p, c);
      c = tPOW;
    }
    else {
      if (c == '=') {
        pylval.id = intern_c('*');
        p->lstate = EXPR_BEG;
        return tOP_ASGN;
      }
      pushback(p, c);
      if (IS_SPCARG(c)) {
        yywarning(p, "'*' interpreted as argument prefix");
        c = tSTAR;
      }
      else if (IS_BEG()) {
        c = tSTAR;
      }
      else {
        c = '*';
      }
    }
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    return c;

  case '!':
    c = nextc(p);
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
      if (c == '@') {
        return '!';
      }
    }
    else {
      p->lstate = EXPR_BEG;
    }
    if (c == '=') {
      return tNEQ;
    }
    if (c == '~') {
      return tNMATCH;
    }
    pushback(p, c);
    return '!';

  case '=':
    if (p->column == 1) {
      static const char begin[] = "begin";
      static const char end[] = "\n=end";
      if (peeks(p, begin)) {
        c = peekc_n(p, sizeof(begin)-1);
        if (c < 0 || ISSPACE(c)) {
          do {
            if (!skips(p, end)) {
              yyerror(p, "embedded document meets end of file");
              return 0;
            }
            c = nextc(p);
          } while (!(c < 0 || ISSPACE(c)));
          if (c != '\n') skip(p, '\n');
          p->lineno++;
          p->column = 0;
          goto retry;
        }
      }
    }
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    if ((c = nextc(p)) == '=') {
      if ((c = nextc(p)) == '=') {
        return tEQQ;
      }
      pushback(p, c);
      return tEQ;
    }
    if (c == '~') {
      return tMATCH;
    }
    else if (c == '>') {
      return tASSOC;
    }
    pushback(p, c);
    return '=';

  case '<':
    c = nextc(p);
    if (c == '<' &&
        p->lstate != EXPR_DOT &&
        p->lstate != EXPR_CLASS &&
        !IS_END() &&
        (!IS_ARG() || space_seen)) {
      int token = heredoc_identifier(p);
      if (token)
        return token;
    }
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
      if (p->lstate == EXPR_CLASS) {
        p->cmd_start = TRUE;
      }
    }
    if (c == '=') {
      if ((c = nextc(p)) == '>') {
        return tCMP;
      }
      pushback(p, c);
      return tLEQ;
    }
    if (c == '<') {
      if ((c = nextc(p)) == '=') {
        pylval.id = intern("<<",2);
        p->lstate = EXPR_BEG;
        return tOP_ASGN;
      }
      pushback(p, c);
      return tLSHFT;
    }
    pushback(p, c);
    return '<';

  case '>':
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    if ((c = nextc(p)) == '=') {
      return tGEQ;
    }
    if (c == '>') {
      if ((c = nextc(p)) == '=') {
        pylval.id = intern(">>",2);
        p->lstate = EXPR_BEG;
        return tOP_ASGN;
      }
      pushback(p, c);
      return tRSHFT;
    }
    pushback(p, c);
    return '>';

  case '"':
    p->lex_strterm = new_strterm(p, str_dquote, '"', 0);
    return tSTRING_BEG;

  case '\'':
    p->lex_strterm = new_strterm(p, str_squote, '\'', 0);
    return parse_string(p);

  case '`':
    if (p->lstate == EXPR_FNAME) {
      p->lstate = EXPR_ENDFN;
      return '`';
    }
    if (p->lstate == EXPR_DOT) {
      if (cmd_state)
        p->lstate = EXPR_CMDARG;
      else
        p->lstate = EXPR_ARG;
      return '`';
    }
    p->lex_strterm = new_strterm(p, str_xquote, '`', 0);
    return tXSTRING_BEG;

  case '?':
    if (IS_END()) {
      p->lstate = EXPR_VALUE;
      return '?';
    }
    c = nextc(p);
    if (c < 0) {
      yyerror(p, "incomplete character syntax");
      return 0;
    }
    if (ISSPACE(c)) {
      if (!IS_ARG()) {
        int c2;
        switch (c) {
        case ' ':
          c2 = 's';
          break;
        case '\n':
          c2 = 'n';
          break;
        case '\t':
          c2 = 't';
          break;
        case '\v':
          c2 = 'v';
          break;
        case '\r':
          c2 = 'r';
          break;
        case '\f':
          c2 = 'f';
          break;
        default:
          c2 = 0;
          break;
        }
        if (c2) {
          char buf[256];
          snprintf(buf, sizeof(buf), "invalid character syntax; use ?\\%c", c2);
          yyerror(p, buf);
        }
      }
      ternary:
      pushback(p, c);
      p->lstate = EXPR_VALUE;
      return '?';
    }
    newtok(p);
    /* need support UTF-8 if configured */
    if ((isalnum(c) || c == '_')) {
      int c2 = nextc(p);
      pushback(p, c2);
      if ((isalnum(c2) || c2 == '_')) {
        goto ternary;
      }
    }
    if (c == '\\') {
      c = read_escape(p);
      tokadd(p, c);
    }
    else {
      tokadd(p, c);
    }
    tokfix(p);
    pylval.nd = new_str(p, tok(p), toklen(p));
    p->lstate = EXPR_END;
    return tCHAR;

  case '&':
    if ((c = nextc(p)) == '&') {
      p->lstate = EXPR_BEG;
      if ((c = nextc(p)) == '=') {
        pylval.id = intern("&&",2);
        p->lstate = EXPR_BEG;
        return tOP_ASGN;
      }
      pushback(p, c);
      return tANDOP;
    }
    else if (c == '.') {
      p->lstate = EXPR_DOT;
      return tANDDOT;
    }
    else if (c == '=') {
      pylval.id = intern_c('&');
      p->lstate = EXPR_BEG;
      return tOP_ASGN;
    }
    pushback(p, c);
    if (IS_SPCARG(c)) {
      yywarning(p, "'&' interpreted as argument prefix");
      c = tAMPER;
    }
    else if (IS_BEG()) {
      c = tAMPER;
    }
    else {
      c = '&';
    }
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    return c;

  case '|':
    if ((c = nextc(p)) == '|') {
      p->lstate = EXPR_BEG;
      if ((c = nextc(p)) == '=') {
        pylval.id = intern("||",2);
        p->lstate = EXPR_BEG;
        return tOP_ASGN;
      }
      pushback(p, c);
      return tOROP;
    }
    if (c == '=') {
      pylval.id = intern_c('|');
      p->lstate = EXPR_BEG;
      return tOP_ASGN;
    }
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    pushback(p, c);
    return '|';

  case '+':
    c = nextc(p);
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
      if (c == '@') {
        return tUPLUS;
      }
      pushback(p, c);
      return '+';
    }
    if (c == '=') {
      pylval.id = intern_c('+');
      p->lstate = EXPR_BEG;
      return tOP_ASGN;
    }
    if (IS_BEG() || (IS_SPCARG(c) && arg_ambiguous(p))) {
      p->lstate = EXPR_BEG;
      pushback(p, c);
      if (c >= 0 && ISDIGIT(c)) {
        c = '+';
        goto start_num;
      }
      return tUPLUS;
    }
    p->lstate = EXPR_BEG;
    pushback(p, c);
    return '+';

  case '-':
    c = nextc(p);
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
      if (c == '@') {
        return tUMINUS;
      }
      pushback(p, c);
      return '-';
    }
    if (c == '=') {
      pylval.id = intern_c('-');
      p->lstate = EXPR_BEG;
      return tOP_ASGN;
    }
    if (c == '>') {
      p->lstate = EXPR_ENDFN;
      return tLAMBDA;
    }
    if (IS_BEG() || (IS_SPCARG(c) && arg_ambiguous(p))) {
      p->lstate = EXPR_BEG;
      pushback(p, c);
      if (c >= 0 && ISDIGIT(c)) {
        return tUMINUS_NUM;
      }
      return tUMINUS;
    }
    p->lstate = EXPR_BEG;
    pushback(p, c);
    return '-';

  case '.':
    p->lstate = EXPR_BEG;
    if ((c = nextc(p)) == '.') {
      if ((c = nextc(p)) == '.') {
        return tDOT3;
      }
      pushback(p, c);
      return tDOT2;
    }
    pushback(p, c);
    if (c >= 0 && ISDIGIT(c)) {
      yyerror(p, "no .<digit> floating literal anymore; put 0 before dot");
    }
    p->lstate = EXPR_DOT;
    return '.';

    start_num:
  case '0': case '1': case '2': case '3': case '4':
  case '5': case '6': case '7': case '8': case '9':
  {
    int is_float, seen_point, seen_e, nondigit;

    is_float = seen_point = seen_e = nondigit = 0;
    p->lstate = EXPR_END;
    newtok(p);
    if (c == '-' || c == '+') {
      tokadd(p, c);
      c = nextc(p);
    }
    if (c == '0') {
#define no_digits() do {yyerror(p,"numeric literal without digits"); return 0;} while (0)
      int start = toklen(p);
      c = nextc(p);
      if (c == 'x' || c == 'X') {
        /* hexadecimal */
        c = nextc(p);
        if (c >= 0 && ISXDIGIT(c)) {
          do {
            if (c == '_') {
              if (nondigit) break;
              nondigit = c;
              continue;
            }
            if (!ISXDIGIT(c)) break;
            nondigit = 0;
            tokadd(p, tolower(c));
          } while ((c = nextc(p)) >= 0);
        }
        pushback(p, c);
        tokfix(p);
        if (toklen(p) == start) {
          no_digits();
        }
        else if (nondigit) goto trailing_uc;
        pylval.nd = new_int(p, tok(p), 16);
        return tINTEGER;
      }
      if (c == 'b' || c == 'B') {
        /* binary */
        c = nextc(p);
        if (c == '0' || c == '1') {
          do {
            if (c == '_') {
              if (nondigit) break;
              nondigit = c;
              continue;
            }
            if (c != '0' && c != '1') break;
            nondigit = 0;
            tokadd(p, c);
          } while ((c = nextc(p)) >= 0);
        }
        pushback(p, c);
        tokfix(p);
        if (toklen(p) == start) {
          no_digits();
        }
        else if (nondigit) goto trailing_uc;
        pylval.nd = new_int(p, tok(p), 2);
        return tINTEGER;
      }
      if (c == 'd' || c == 'D') {
        /* decimal */
        c = nextc(p);
        if (c >= 0 && ISDIGIT(c)) {
          do {
            if (c == '_') {
              if (nondigit) break;
              nondigit = c;
              continue;
            }
            if (!ISDIGIT(c)) break;
            nondigit = 0;
            tokadd(p, c);
          } while ((c = nextc(p)) >= 0);
        }
        pushback(p, c);
        tokfix(p);
        if (toklen(p) == start) {
          no_digits();
        }
        else if (nondigit) goto trailing_uc;
        pylval.nd = new_int(p, tok(p), 10);
        return tINTEGER;
      }
      if (c == '_') {
        /* 0_0 */
        goto octal_number;
      }
      if (c == 'o' || c == 'O') {
        /* prefixed octal */
        c = nextc(p);
        if (c < 0 || c == '_' || !ISDIGIT(c)) {
          no_digits();
        }
      }
      if (c >= '0' && c <= '7') {
        /* octal */
        octal_number:
        do {
          if (c == '_') {
            if (nondigit) break;
            nondigit = c;
            continue;
          }
          if (c < '0' || c > '9') break;
          if (c > '7') goto invalid_octal;
          nondigit = 0;
          tokadd(p, c);
        } while ((c = nextc(p)) >= 0);

        if (toklen(p) > start) {
          pushback(p, c);
          tokfix(p);
          if (nondigit) goto trailing_uc;
          pylval.nd = new_int(p, tok(p), 8);
          return tINTEGER;
        }
        if (nondigit) {
          pushback(p, c);
          goto trailing_uc;
        }
      }
      if (c > '7' && c <= '9') {
        invalid_octal:
        yyerror(p, "Invalid octal digit");
      }
      else if (c == '.' || c == 'e' || c == 'E') {
        tokadd(p, '0');
      }
      else {
        pushback(p, c);
        pylval.nd = new_int(p, "0", 10);
        return tINTEGER;
      }
    }

    for (;;) {
      switch (c) {
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
        nondigit = 0;
        tokadd(p, c);
        break;

      case '.':
        if (nondigit) goto trailing_uc;
        if (seen_point || seen_e) {
          goto decode_num;
        }
        else {
          int c0 = nextc(p);
          if (c0 < 0 || !ISDIGIT(c0)) {
            pushback(p, c0);
            goto decode_num;
          }
          c = c0;
        }
        tokadd(p, '.');
        tokadd(p, c);
        is_float++;
        seen_point++;
        nondigit = 0;
        break;

      case 'e':
      case 'E':
        if (nondigit) {
          pushback(p, c);
          c = nondigit;
          goto decode_num;
        }
        if (seen_e) {
          goto decode_num;
        }
        tokadd(p, c);
        seen_e++;
        is_float++;
        nondigit = c;
        c = nextc(p);
        if (c != '-' && c != '+') continue;
        tokadd(p, c);
        nondigit = c;
        break;

      case '_':       /* '_' in number just ignored */
        if (nondigit) goto decode_num;
        nondigit = c;
        break;

      default:
        goto decode_num;
      }
      c = nextc(p);
    }

    decode_num:
    pushback(p, c);
    if (nondigit) {
      trailing_uc:
      yyerror_i(p, "trailing '%c' in number", nondigit);
    }
    tokfix(p);
    if (is_float) {
      double d;
      char *endp;

      errno = 0;
      d = mrb_float_read(tok(p), &endp);
      if (d == 0 && endp == tok(p)) {
        yywarning_s(p, "corrupted float value %s", tok(p));
      }
      else if (errno == ERANGE) {
        yywarning_s(p, "float %s out of range", tok(p));
        errno = 0;
      }
      pylval.nd = new_float(p, tok(p));
      return tFLOAT;
    }
    pylval.nd = new_int(p, tok(p), 10);
    return tINTEGER;
  }

  case ')':
  case ']':
    p->paren_nest--;
    /* fall through */
  case '}':
    COND_LEXPOP();
    CMDARG_LEXPOP();
    if (c == ')')
      p->lstate = EXPR_ENDFN;
    else
      p->lstate = EXPR_ENDARG;
    return c;

  case ':':
    c = nextc(p);
    if (c == ':') {
      if (IS_BEG() || p->lstate == EXPR_CLASS || IS_SPCARG(-1)) {
        p->lstate = EXPR_BEG;
        return tCOLON3;
      }
      p->lstate = EXPR_DOT;
      return tCOLON2;
    }
    if (IS_END() || ISSPACE(c)) {
      pushback(p, c);
      p->lstate = EXPR_BEG;
      return ':';
    }
    pushback(p, c);
    p->lstate = EXPR_FNAME;
    return tSYMBEG;

  case '/':
    if (IS_BEG()) {
      p->lex_strterm = new_strterm(p, str_regexp, '/', 0);
      return tREGEXP_BEG;
    }
    if ((c = nextc(p)) == '=') {
      pylval.id = intern_c('/');
      p->lstate = EXPR_BEG;
      return tOP_ASGN;
    }
    pushback(p, c);
    if (IS_SPCARG(c)) {
      p->lex_strterm = new_strterm(p, str_regexp, '/', 0);
      return tREGEXP_BEG;
    }
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    return '/';

  case '^':
    if ((c = nextc(p)) == '=') {
      pylval.id = intern_c('^');
      p->lstate = EXPR_BEG;
      return tOP_ASGN;
    }
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    pushback(p, c);
    return '^';

  case ';':
    p->lstate = EXPR_BEG;
    return ';';

  case ',':
    p->lstate = EXPR_BEG;
    return ',';

  case '~':
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      if ((c = nextc(p)) != '@') {
        pushback(p, c);
      }
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    return '~';

  case '(':
    if (IS_BEG()) {
      c = tLPAREN;
    }
    else if (IS_SPCARG(-1)) {
      c = tLPAREN_ARG;
    }
    p->paren_nest++;
    COND_PUSH(0);
    CMDARG_PUSH(0);
    p->lstate = EXPR_BEG;
    return c;

  case '[':
    p->paren_nest++;
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
      if ((c = nextc(p)) == ']') {
        if ((c = nextc(p)) == '=') {
          return tASET;
        }
        pushback(p, c);
        return tAREF;
      }
      pushback(p, c);
      return '[';
    }
    else if (IS_BEG()) {
      c = tLBRACK;
    }
    else if (IS_ARG() && space_seen) {
      c = tLBRACK;
    }
    p->lstate = EXPR_BEG;
    COND_PUSH(0);
    CMDARG_PUSH(0);
    return c;

  case '{':
    if (p->lpar_beg && p->lpar_beg == p->paren_nest) {
      p->lstate = EXPR_BEG;
      p->lpar_beg = 0;
      p->paren_nest--;
      COND_PUSH(0);
      CMDARG_PUSH(0);
      return tLAMBEG;
    }
    if (IS_ARG() || p->lstate == EXPR_END || p->lstate == EXPR_ENDFN)
      c = '{';          /* block (primary) */
    else if (p->lstate == EXPR_ENDARG)
      c = tLBRACE_ARG;  /* block (expr) */
    else
      c = tLBRACE;      /* hash */
    COND_PUSH(0);
    CMDARG_PUSH(0);
    p->lstate = EXPR_BEG;
    return c;

  case '\\':
    c = nextc(p);
    if (c == '\n') {
      p->lineno++;
      p->column = 0;
      space_seen = 1;
      goto retry; /* skip \\n */
    }
    pushback(p, c);
    return '\\';

  case '%':
    if (IS_BEG()) {
      int term;
      int paren;

      c = nextc(p);
      quotation:
      if (c < 0 || !ISALNUM(c)) {
        term = c;
        c = 'Q';
      }
      else {
        term = nextc(p);
        if (isalnum(term)) {
          yyerror(p, "unknown type of %string");
          return 0;
        }
      }
      if (c < 0 || term < 0) {
        yyerror(p, "unterminated quoted string meets end of file");
        return 0;
      }
      paren = term;
      if (term == '(') term = ')';
      else if (term == '[') term = ']';
      else if (term == '{') term = '}';
      else if (term == '<') term = '>';
      else paren = 0;

      switch (c) {
      case 'Q':
        p->lex_strterm = new_strterm(p, str_dquote, term, paren);
        return tSTRING_BEG;

      case 'q':
        p->lex_strterm = new_strterm(p, str_squote, term, paren);
        return parse_string(p);

      case 'W':
        p->lex_strterm = new_strterm(p, str_dword, term, paren);
        return tWORDS_BEG;

      case 'w':
        p->lex_strterm = new_strterm(p, str_sword, term, paren);
        return tWORDS_BEG;

      case 'x':
        p->lex_strterm = new_strterm(p, str_xquote, term, paren);
        return tXSTRING_BEG;

      case 'r':
        p->lex_strterm = new_strterm(p, str_regexp, term, paren);
        return tREGEXP_BEG;

      case 's':
        p->lex_strterm = new_strterm(p, str_ssym, term, paren);
        return tSYMBEG;

      case 'I':
        p->lex_strterm = new_strterm(p, str_dsymbols, term, paren);
        return tSYMBOLS_BEG;

      case 'i':
        p->lex_strterm = new_strterm(p, str_ssymbols, term, paren);
        return tSYMBOLS_BEG;

      default:
        yyerror(p, "unknown type of %string");
        return 0;
      }
    }
    if ((c = nextc(p)) == '=') {
      pylval.id = intern_c('%');
      p->lstate = EXPR_BEG;
      return tOP_ASGN;
    }
    if (IS_SPCARG(c)) {
      goto quotation;
    }
    if (p->lstate == EXPR_FNAME || p->lstate == EXPR_DOT) {
      p->lstate = EXPR_ARG;
    }
    else {
      p->lstate = EXPR_BEG;
    }
    pushback(p, c);
    return '%';

  case '$':
    p->lstate = EXPR_END;
    token_column = newtok(p);
    c = nextc(p);
    if (c < 0) {
      yyerror(p, "incomplete global variable syntax");
      return 0;
    }
    switch (c) {
    case '_':     /* $_: last read line string */
      c = nextc(p);
      if (c >= 0 && identchar(c)) { /* if there is more after _ it is a variable */
        tokadd(p, '$');
        tokadd(p, c);
        break;
      }
      pushback(p, c);
      c = '_';
      /* fall through */
    case '~':     /* $~: match-data */
    case '*':     /* $*: argv */
    case '$':     /* $$: pid */
    case '?':     /* $?: last status */
    case '!':     /* $!: error string */
    case '@':     /* $@: error position */
    case '/':     /* $/: input record separator */
    case '\\':    /* $\: output record separator */
    case ';':     /* $;: field separator */
    case ',':     /* $,: output field separator */
    case '.':     /* $.: last read line number */
    case '=':     /* $=: ignorecase */
    case ':':     /* $:: load path */
    case '<':     /* $<: reading filename */
    case '>':     /* $>: default output handle */
    case '\"':    /* $": already loaded files */
      tokadd(p, '$');
      tokadd(p, c);
      tokfix(p);
      pylval.id = intern_cstr(tok(p));
      return tGVAR;

    case '-':
      tokadd(p, '$');
      tokadd(p, c);
      c = nextc(p);
      pushback(p, c);
      gvar:
      tokfix(p);
      pylval.id = intern_cstr(tok(p));
      return tGVAR;

    case '&':     /* $&: last match */
    case '`':     /* $`: string before last match */
    case '\'':    /* $': string after last match */
    case '+':     /* $+: string matches last pattern */
      if (last_state == EXPR_FNAME) {
        tokadd(p, '$');
        tokadd(p, c);
        goto gvar;
      }
      pylval.nd = new_back_ref(p, c);
      return tBACK_REF;

    case '1': case '2': case '3':
    case '4': case '5': case '6':
    case '7': case '8': case '9':
      do {
        tokadd(p, c);
        c = nextc(p);
      } while (c >= 0 && isdigit(c));
      pushback(p, c);
      if (last_state == EXPR_FNAME) goto gvar;
      tokfix(p);
      {
        unsigned long n = strtoul(tok(p), NULL, 10);
        if (n > INT_MAX) {
          yyerror_i(p, "capture group index must be <= %d", INT_MAX);
          return 0;
        }
        pylval.nd = new_nth_ref(p, (int)n);
      }
      return tNTH_REF;

    default:
      if (!identchar(c)) {
        pushback(p,  c);
        return '$';
      }
      /* fall through */
    case '0':
      tokadd(p, '$');
    }
    break;

    case '@':
      c = nextc(p);
      token_column = newtok(p);
      tokadd(p, '@');
      if (c == '@') {
        tokadd(p, '@');
        c = nextc(p);
      }
      if (c < 0) {
        if (p->tidx == 1) {
          yyerror(p, "incomplete instance variable syntax");
        }
        else {
          yyerror(p, "incomplete class variable syntax");
        }
        return 0;
      }
      else if (isdigit(c)) {
        if (p->tidx == 1) {
          yyerror_i(p, "'@%c' is not allowed as an instance variable name", c);
        }
        else {
          yyerror_i(p, "'@@%c' is not allowed as a class variable name", c);
        }
        return 0;
      }
      if (!identchar(c)) {
        pushback(p, c);
        return '@';
      }
      break;

    case '_':
      token_column = newtok(p);
      break;

    default:
      if (!identchar(c)) {
        yyerror_i(p,  "Invalid char '\\x%02X' in expression", c);
        goto retry;
      }

      token_column = newtok(p);
      break;
  }

  do {
    tokadd(p, c);
    c = nextc(p);
    if (c < 0) break;
  } while (identchar(c));
  if (token_column == 0 && toklen(p) == 7 && (c < 0 || c == '\n') &&
      strncmp(tok(p), "__END__", toklen(p)) == 0)
    return -1;

  switch (tok(p)[0]) {
  case '@': case '$':
    pushback(p, c);
    break;
  default:
    if ((c == '!' || c == '?') && !peek(p, '=')) {
      tokadd(p, c);
    }
    else {
      pushback(p, c);
    }
  }
  tokfix(p);
  {
    int result = 0;

    switch (tok(p)[0]) {
    case '$':
      p->lstate = EXPR_END;
      result = tGVAR;
      break;
    case '@':
      p->lstate = EXPR_END;
      if (tok(p)[1] == '@')
        result = tCVAR;
      else
        result = tIVAR;
      break;

    default:
      if (toklast(p) == '!' || toklast(p) == '?') {
        result = tFID;
      }
      else {
        if (p->lstate == EXPR_FNAME) {
          if ((c = nextc(p)) == '=' && !peek(p, '~') && !peek(p, '>') &&
              (!peek(p, '=') || (peek_n(p, '>', 1)))) {
            result = tIDENTIFIER;
            tokadd(p, c);
            tokfix(p);
          }
          else {
            pushback(p, c);
          }
        }
        if (result == 0 && ISUPPER(tok(p)[0])) {
          result = tCONSTANT;
        }
        else {
          result = tIDENTIFIER;
        }
      }

      if (IS_LABEL_POSSIBLE()) {
        if (IS_LABEL_SUFFIX(0)) {
          p->lstate = EXPR_BEG;
          nextc(p);
          tokfix(p);
          pylval.id = intern_cstr(tok(p));
          return tLABEL;
        }
      }
      if (p->lstate != EXPR_DOT) {
        const struct kwtable *kw;

        /* See if it is a reserved word.  */
        kw = mrb_reserved_word(tok(p), toklen(p));
        if (kw) {
          enum mrb_lex_state_enum state = p->lstate;
          pylval.num = p->lineno;
          p->lstate = kw->state;
          if (state == EXPR_FNAME) {
            pylval.id = intern_cstr(kw->name);
            return kw->id[0];
          }
          if (p->lstate == EXPR_BEG) {
            p->cmd_start = TRUE;
          }
          if (kw->id[0] == keyword_do) {
            if (p->lpar_beg && p->lpar_beg == p->paren_nest) {
              p->lpar_beg = 0;
              p->paren_nest--;
              return keyword_do_LAMBDA;
            }
            if (COND_P()) return keyword_do_cond;
            if (CMDARG_P() && state != EXPR_CMDARG)
              return keyword_do_block;
            if (state == EXPR_ENDARG || state == EXPR_BEG)
              return keyword_do_block;
            return keyword_do;
          }
          if (state == EXPR_BEG || state == EXPR_VALUE)
            return kw->id[0];
          else {
            if (kw->id[0] != kw->id[1])
              p->lstate = EXPR_BEG;
            return kw->id[1];
          }
        }
      }

      if (IS_BEG() || p->lstate == EXPR_DOT || IS_ARG()) {
        if (cmd_state) {
          p->lstate = EXPR_CMDARG;
        }
        else {
          p->lstate = EXPR_ARG;
        }
      }
      else if (p->lstate == EXPR_FNAME) {
        p->lstate = EXPR_ENDFN;
      }
      else {
        p->lstate = EXPR_END;
      }
    }
    {
      mrb_sym ident = intern_cstr(tok(p));

      pylval.id = ident;
#if 0
      if (last_state != EXPR_DOT && islower(tok(p)[0]) && lvar_defined(ident)) {
        p->lstate = EXPR_END;
      }
#endif
    }
    return result;
  }
}

static int
yylex(void *lval, parser_state *p)
{
  p->ylval = lval;
  return parser_yylex(p);
}

static void
parser_init_cxt(parser_state *p, mrbc_context *cxt)
{
  if (!cxt) return;
  if (cxt->filename) mrb_parser_set_filename(p, cxt->filename);
  if (cxt->lineno) p->lineno = cxt->lineno;
  if (cxt->syms) {
    int i;

    p->locals = cons(0,0);
    for (i=0; i<cxt->slen; i++) {
      local_add_f(p, cxt->syms[i]);
    }
  }
  p->capture_errors = cxt->capture_errors;
  p->no_optimize = cxt->no_optimize;
  if (cxt->partial_hook) {
    p->cxt = cxt;
  }
}

static void
parser_update_cxt(parser_state *p, mrbc_context *cxt)
{
  node *n, *n0;
  int i = 0;

  if (!cxt) return;
  if ((int)(intptr_t)p->tree->car != NODE_SCOPE) return;
  n0 = n = p->tree->cdr->car;
  while (n) {
    i++;
    n = n->cdr;
  }
  cxt->syms = (mrb_sym *)mrb_realloc(p->mrb, cxt->syms, i*sizeof(mrb_sym));
  cxt->slen = i;
  for (i=0, n=n0; n; i++,n=n->cdr) {
    cxt->syms[i] = sym(n->car);
  }
}

void mrb_codedump_all(mrb_state*, struct RProc*);
void mrb_parser_dump(mrb_state *mrb, node *tree, int offset);

MRB_API void
mrb_parser_parse(parser_state *p, mrbc_context *c)
{
  struct mrb_jmpbuf buf1;
  p->jmp = &buf1;

  MRB_TRY(p->jmp) {
    int n;

    p->cmd_start = TRUE;
    p->in_def = p->in_single = 0;
    p->nerr = p->nwarn = 0;
    p->lex_strterm = NULL;

    parser_init_cxt(p, c);

    if (p->mrb->jmp) {
      n = yyparse(p);
    }
    else {
      struct mrb_jmpbuf buf2;

      p->mrb->jmp = &buf2;
      MRB_TRY(p->mrb->jmp) {
        n = yyparse(p);
      }
      MRB_CATCH(p->mrb->jmp) {
        p->nerr++;
      }
      MRB_END_EXC(p->mrb->jmp);
      p->mrb->jmp = 0;
    }
    if (n != 0 || p->nerr > 0) {
      p->tree = 0;
      return;
    }
    if (!p->tree) {
      p->tree = new_nil(p);
    }
    parser_update_cxt(p, c);
    if (c && c->dump_result) {
      mrb_parser_dump(p->mrb, p->tree, 0);
    }
  }
  MRB_CATCH(p->jmp) {
    yyerror(p, "memory allocation error");
    p->nerr++;
    p->tree = 0;
    return;
  }
  MRB_END_EXC(p->jmp);
}

MRB_API parser_state*
mrb_parser_new(mrb_state *mrb)
{
  mrb_pool *pool;
  parser_state *p;
  static const parser_state parser_state_zero = { 0 };

  pool = mrb_pool_open(mrb);
  if (!pool) return NULL;
  p = (parser_state *)mrb_pool_alloc(pool, sizeof(parser_state));
  if (!p) return NULL;

  *p = parser_state_zero;
  p->mrb = mrb;
  p->pool = pool;

  p->s = p->send = NULL;
#ifndef MRB_DISABLE_STDIO
  p->f = NULL;
#endif

  p->cmd_start = TRUE;
  p->in_def = p->in_single = 0;

  p->capture_errors = FALSE;
  p->lineno = 1;
  p->column = 0;
#if defined(PARSER_TEST) || defined(PARSER_DEBUG)
  yydebug = 1;
#endif
  p->tsiz = MRB_PARSER_TOKBUF_SIZE;
  p->tokbuf = p->buf;

  p->lex_strterm = NULL;
  p->all_heredocs = p->parsing_heredoc = NULL;
  p->lex_strterm_before_heredoc = NULL;

  p->current_filename_index = -1;
  p->filename_table = NULL;
  p->filename_table_length = 0;

  return p;
}

MRB_API void
mrb_parser_free(parser_state *p) {
  if (p->tokbuf != p->buf) {
    mrb_free(p->mrb, p->tokbuf);
  }
  mrb_pool_close(p->pool);
}

MRB_API mrbc_context*
mrbc_context_new(mrb_state *mrb)
{
  return (mrbc_context *)mrb_calloc(mrb, 1, sizeof(mrbc_context));
}

MRB_API void
mrbc_context_free(mrb_state *mrb, mrbc_context *cxt)
{
  mrb_free(mrb, cxt->filename);
  mrb_free(mrb, cxt->syms);
  mrb_free(mrb, cxt);
}

MRB_API const char*
mrbc_filename(mrb_state *mrb, mrbc_context *c, const char *s)
{
  if (s) {
    int len = strlen(s);
    char *p = (char *)mrb_malloc(mrb, len + 1);

    memcpy(p, s, len + 1);
    if (c->filename) {
      mrb_free(mrb, c->filename);
    }
    c->filename = p;
  }
  return c->filename;
}

MRB_API void
mrbc_partial_hook(mrb_state *mrb, mrbc_context *c, int (*func)(struct mrb_parser_state*), void *data)
{
  c->partial_hook = func;
  c->partial_data = data;
}

MRB_API void
mrb_parser_set_filename(struct mrb_parser_state *p, const char *f)
{
  mrb_sym sym;
  size_t i;
  mrb_sym* new_table;

  sym = mrb_intern_cstr(p->mrb, f);
  p->filename = mrb_sym2name_len(p->mrb, sym, NULL);
  p->lineno = (p->filename_table_length > 0)? 0 : 1;

  for (i = 0; i < p->filename_table_length; ++i) {
    if (p->filename_table[i] == sym) {
      p->current_filename_index = i;
      return;
    }
  }

  p->current_filename_index = p->filename_table_length++;

  new_table = (mrb_sym*)parser_palloc(p, sizeof(mrb_sym) * p->filename_table_length);
  if (p->filename_table) {
    memmove(new_table, p->filename_table, sizeof(mrb_sym) * p->filename_table_length);
  }
  p->filename_table = new_table;
  p->filename_table[p->filename_table_length - 1] = sym;
}

MRB_API char const*
mrb_parser_get_filename(struct mrb_parser_state* p, uint16_t idx) {
  if (idx >= p->filename_table_length) { return NULL; }
  else {
    return mrb_sym2name_len(p->mrb, p->filename_table[idx], NULL);
  }
}

#ifndef MRB_DISABLE_STDIO
MRB_API parser_state*
mrb_parse_file(mrb_state *mrb, FILE *f, mrbc_context *c)
{
  parser_state *p;

  p = mrb_parser_new(mrb);
  if (!p) return NULL;
  p->s = p->send = NULL;
  p->f = f;

  mrb_parser_parse(p, c);
  return p;
}
#endif

MRB_API parser_state*
mrb_parse_nstring(mrb_state *mrb, const char *s, int len, mrbc_context *c)
{
  parser_state *p;

  p = mrb_parser_new(mrb);
  if (!p) return NULL;
  p->s = s;
  p->send = s + len;

  mrb_parser_parse(p, c);
  return p;
}

MRB_API parser_state*
mrb_parse_string(mrb_state *mrb, const char *s, mrbc_context *c)
{
  return mrb_parse_nstring(mrb, s, strlen(s), c);
}

MRB_API mrb_value
mrb_load_exec(mrb_state *mrb, struct mrb_parser_state *p, mrbc_context *c)
{
  struct RClass *target = mrb->object_class;
  struct RProc *proc;
  mrb_value v;
  unsigned int keep = 0;

  if (!p) {
    return mrb_undef_value();
  }
  if (!p->tree || p->nerr) {
    if (p->capture_errors) {
      char buf[256];
      int n;

      n = snprintf(buf, sizeof(buf), "line %d: %s\n",
          p->error_buffer[0].lineno, p->error_buffer[0].message);
      mrb->exc = mrb_obj_ptr(mrb_exc_new(mrb, E_SYNTAX_ERROR, buf, n));
      mrb_parser_free(p);
      return mrb_undef_value();
    }
    else {
      if (mrb->exc == NULL) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_SYNTAX_ERROR, "syntax error"));
      }
      mrb_parser_free(p);
      return mrb_undef_value();
    }
  }
  proc = mrb_generate_code(mrb, p);
  mrb_parser_free(p);
  if (proc == NULL) {
    if (mrb->exc == NULL) {
      mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_SCRIPT_ERROR, "codegen error"));
    }
    return mrb_undef_value();
  }
  if (c) {
    if (c->dump_result) mrb_codedump_all(mrb, proc);
    if (c->no_exec) return mrb_obj_value(proc);
    if (c->target_class) {
      target = c->target_class;
    }
    if (c->keep_lv) {
      keep = c->slen + 1;
    }
    else {
      c->keep_lv = TRUE;
    }
  }
  proc->target_class = target;
  if (mrb->c->ci) {
    mrb->c->ci->target_class = target;
  }
  v = mrb_top_run(mrb, proc, mrb_top_self(mrb), keep);
  if (mrb->exc) return mrb_nil_value();
  return v;
}

#ifndef MRB_DISABLE_STDIO
MRB_API mrb_value
mrb_load_file_cxt(mrb_state *mrb, FILE *f, mrbc_context *c)
{
  return mrb_load_exec(mrb, mrb_parse_file(mrb, f, c), c);
}

MRB_API mrb_value
mrb_load_file(mrb_state *mrb, FILE *f)
{
  return mrb_load_file_cxt(mrb, f, NULL);
}
#endif

MRB_API mrb_value
mrb_load_nstring_cxt(mrb_state *mrb, const char *s, int len, mrbc_context *c)
{
  return mrb_load_exec(mrb, mrb_parse_nstring(mrb, s, len, c), c);
}

MRB_API mrb_value
mrb_load_nstring(mrb_state *mrb, const char *s, int len)
{
  return mrb_load_nstring_cxt(mrb, s, len, NULL);
}

MRB_API mrb_value
mrb_load_string_cxt(mrb_state *mrb, const char *s, mrbc_context *c)
{
  return mrb_load_nstring_cxt(mrb, s, strlen(s), c);
}

MRB_API mrb_value
mrb_load_string(mrb_state *mrb, const char *s)
{
  return mrb_load_string_cxt(mrb, s, NULL);
}

#ifndef MRB_DISABLE_STDIO

static void
dump_prefix(node *tree, int offset)
{
  printf("%05d ", tree->lineno);
  while (offset--) {
    putc(' ', stdout);
    putc(' ', stdout);
  }
}

static void
dump_recur(mrb_state *mrb, node *tree, int offset)
{
  while (tree) {
    mrb_parser_dump(mrb, tree->car, offset);
    tree = tree->cdr;
  }
}

#endif

void
mrb_parser_dump(mrb_state *mrb, node *tree, int offset)
{
#ifndef MRB_DISABLE_STDIO
  int nodetype;

  if (!tree) return;
  again:
  dump_prefix(tree, offset);
  nodetype = (int)(intptr_t)tree->car;
  tree = tree->cdr;
  switch (nodetype) {
  case NODE_BEGIN:
    printf("NODE_BEGIN:\n");
    dump_recur(mrb, tree, offset+1);
    break;

  case NODE_RESCUE:
    printf("NODE_RESCUE:\n");
    if (tree->car) {
      dump_prefix(tree, offset+1);
      printf("body:\n");
      mrb_parser_dump(mrb, tree->car, offset+2);
    }
    tree = tree->cdr;
    if (tree->car) {
      node *n2 = tree->car;

      dump_prefix(n2, offset+1);
      printf("rescue:\n");
      while (n2) {
        node *n3 = n2->car;
        if (n3->car) {
          dump_prefix(n2, offset+2);
          printf("handle classes:\n");
          dump_recur(mrb, n3->car, offset+3);
        }
        if (n3->cdr->car) {
          dump_prefix(n3, offset+2);
          printf("exc_var:\n");
          mrb_parser_dump(mrb, n3->cdr->car, offset+3);
        }
        if (n3->cdr->cdr->car) {
          dump_prefix(n3, offset+2);
          printf("rescue body:\n");
          mrb_parser_dump(mrb, n3->cdr->cdr->car, offset+3);
        }
        n2 = n2->cdr;
      }
    }
    tree = tree->cdr;
    if (tree->car) {
      dump_prefix(tree, offset+1);
      printf("else:\n");
      mrb_parser_dump(mrb, tree->car, offset+2);
    }
    break;

  case NODE_ENSURE:
    printf("NODE_ENSURE:\n");
    dump_prefix(tree, offset+1);
    printf("body:\n");
    mrb_parser_dump(mrb, tree->car, offset+2);
    dump_prefix(tree, offset+1);
    printf("ensure:\n");
    mrb_parser_dump(mrb, tree->cdr->cdr, offset+2);
    break;

  case NODE_LAMBDA:
    printf("NODE_BLOCK:\n");
    goto block;

  case NODE_BLOCK:
    block:
    printf("NODE_BLOCK:\n");
    tree = tree->cdr;
    if (tree->car) {
      node *n = tree->car;

      if (n->car) {
        dump_prefix(n, offset+1);
        printf("mandatory args:\n");
        dump_recur(mrb, n->car, offset+2);
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("optional args:\n");
        {
          node *n2 = n->car;

          while (n2) {
            dump_prefix(n2, offset+2);
            printf("%s=", mrb_sym2name(mrb, sym(n2->car->car)));
            mrb_parser_dump(mrb, n2->car->cdr, 0);
            n2 = n2->cdr;
          }
        }
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("rest=*%s\n", mrb_sym2name(mrb, sym(n->car)));
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("post mandatory args:\n");
        dump_recur(mrb, n->car, offset+2);
      }
      if (n->cdr) {
        dump_prefix(n, offset+1);
        printf("blk=&%s\n", mrb_sym2name(mrb, sym(n->cdr)));
      }
    }
    dump_prefix(tree, offset+1);
    printf("body:\n");
    mrb_parser_dump(mrb, tree->cdr->car, offset+2);
    break;

  case NODE_IF:
    printf("NODE_IF:\n");
    dump_prefix(tree, offset+1);
    printf("cond:\n");
    mrb_parser_dump(mrb, tree->car, offset+2);
    dump_prefix(tree, offset+1);
    printf("then:\n");
    mrb_parser_dump(mrb, tree->cdr->car, offset+2);
    if (tree->cdr->cdr->car) {
      dump_prefix(tree, offset+1);
      printf("else:\n");
      mrb_parser_dump(mrb, tree->cdr->cdr->car, offset+2);
    }
    break;

  case NODE_AND:
    printf("NODE_AND:\n");
    mrb_parser_dump(mrb, tree->car, offset+1);
    mrb_parser_dump(mrb, tree->cdr, offset+1);
    break;

  case NODE_OR:
    printf("NODE_OR:\n");
    mrb_parser_dump(mrb, tree->car, offset+1);
    mrb_parser_dump(mrb, tree->cdr, offset+1);
    break;

  case NODE_CASE:
    printf("NODE_CASE:\n");
    if (tree->car) {
      mrb_parser_dump(mrb, tree->car, offset+1);
    }
    tree = tree->cdr;
    while (tree) {
      dump_prefix(tree, offset+1);
      printf("case:\n");
      dump_recur(mrb, tree->car->car, offset+2);
      dump_prefix(tree, offset+1);
      printf("body:\n");
      mrb_parser_dump(mrb, tree->car->cdr, offset+2);
      tree = tree->cdr;
    }
    break;

  case NODE_WHILE:
    printf("NODE_WHILE:\n");
    dump_prefix(tree, offset+1);
    printf("cond:\n");
    mrb_parser_dump(mrb, tree->car, offset+2);
    dump_prefix(tree, offset+1);
    printf("body:\n");
    mrb_parser_dump(mrb, tree->cdr, offset+2);
    break;

  case NODE_UNTIL:
    printf("NODE_UNTIL:\n");
    dump_prefix(tree, offset+1);
    printf("cond:\n");
    mrb_parser_dump(mrb, tree->car, offset+2);
    dump_prefix(tree, offset+1);
    printf("body:\n");
    mrb_parser_dump(mrb, tree->cdr, offset+2);
    break;

  case NODE_FOR:
    printf("NODE_FOR:\n");
    dump_prefix(tree, offset+1);
    printf("var:\n");
    {
      node *n2 = tree->car;

      if (n2->car) {
        dump_prefix(n2, offset+2);
        printf("pre:\n");
        dump_recur(mrb, n2->car, offset+3);
      }
      n2 = n2->cdr;
      if (n2) {
        if (n2->car) {
          dump_prefix(n2, offset+2);
          printf("rest:\n");
          mrb_parser_dump(mrb, n2->car, offset+3);
        }
        n2 = n2->cdr;
        if (n2) {
          if (n2->car) {
            dump_prefix(n2, offset+2);
            printf("post:\n");
            dump_recur(mrb, n2->car, offset+3);
          }
        }
      }
    }
    tree = tree->cdr;
    dump_prefix(tree, offset+1);
    printf("in:\n");
    mrb_parser_dump(mrb, tree->car, offset+2);
    tree = tree->cdr;
    dump_prefix(tree, offset+1);
    printf("do:\n");
    mrb_parser_dump(mrb, tree->car, offset+2);
    break;

  case NODE_SCOPE:
    printf("NODE_SCOPE:\n");
    {
      node *n2 = tree->car;
      mrb_bool first_lval = TRUE;

      if (n2 && (n2->car || n2->cdr)) {
        dump_prefix(n2, offset+1);
        printf("local variables:\n");
        dump_prefix(n2, offset+2);
        while (n2) {
          if (n2->car) {
            if (!first_lval) printf(", ");
            printf("%s", mrb_sym2name(mrb, sym(n2->car)));
            first_lval = FALSE;
          }
          n2 = n2->cdr;
        }
        printf("\n");
      }
    }
    tree = tree->cdr;
    offset++;
    goto again;

  case NODE_FCALL:
  case NODE_CALL:
  case NODE_SCALL:
    switch (nodetype) {
    case NODE_FCALL:
      printf("NODE_FCALL:\n"); break;
    case NODE_CALL:
      printf("NODE_CALL(.):\n"); break;
    case NODE_SCALL:
      printf("NODE_SCALL(&.):\n"); break;
    default:
      break;
    }
    mrb_parser_dump(mrb, tree->car, offset+1);
    dump_prefix(tree, offset+1);
    printf("method='%s' (%d)\n",
        mrb_sym2name(mrb, sym(tree->cdr->car)),
        (int)(intptr_t)tree->cdr->car);
    tree = tree->cdr->cdr->car;
    if (tree) {
      dump_prefix(tree, offset+1);
      printf("args:\n");
      dump_recur(mrb, tree->car, offset+2);
      if (tree->cdr) {
        dump_prefix(tree, offset+1);
        printf("block:\n");
        mrb_parser_dump(mrb, tree->cdr, offset+2);
      }
    }
    break;

  case NODE_DOT2:
    printf("NODE_DOT2:\n");
    mrb_parser_dump(mrb, tree->car, offset+1);
    mrb_parser_dump(mrb, tree->cdr, offset+1);
    break;

  case NODE_DOT3:
    printf("NODE_DOT3:\n");
    mrb_parser_dump(mrb, tree->car, offset+1);
    mrb_parser_dump(mrb, tree->cdr, offset+1);
    break;

  case NODE_COLON2:
    printf("NODE_COLON2:\n");
    mrb_parser_dump(mrb, tree->car, offset+1);
    dump_prefix(tree, offset+1);
    printf("::%s\n", mrb_sym2name(mrb, sym(tree->cdr)));
    break;

  case NODE_COLON3:
    printf("NODE_COLON3: ::%s\n", mrb_sym2name(mrb, sym(tree)));
    break;

  case NODE_ARRAY:
    printf("NODE_ARRAY:\n");
    dump_recur(mrb, tree, offset+1);
    break;

  case NODE_HASH:
    printf("NODE_HASH:\n");
    while (tree) {
      dump_prefix(tree, offset+1);
      printf("key:\n");
      mrb_parser_dump(mrb, tree->car->car, offset+2);
      dump_prefix(tree, offset+1);
      printf("value:\n");
      mrb_parser_dump(mrb, tree->car->cdr, offset+2);
      tree = tree->cdr;
    }
    break;

  case NODE_SPLAT:
    printf("NODE_SPLAT:\n");
    mrb_parser_dump(mrb, tree, offset+1);
    break;

  case NODE_ASGN:
    printf("NODE_ASGN:\n");
    dump_prefix(tree, offset+1);
    printf("lhs:\n");
    mrb_parser_dump(mrb, tree->car, offset+2);
    dump_prefix(tree, offset+1);
    printf("rhs:\n");
    mrb_parser_dump(mrb, tree->cdr, offset+2);
    break;

  case NODE_MASGN:
    printf("NODE_MASGN:\n");
    dump_prefix(tree, offset+1);
    printf("mlhs:\n");
    {
      node *n2 = tree->car;

      if (n2->car) {
        dump_prefix(tree, offset+2);
        printf("pre:\n");
        dump_recur(mrb, n2->car, offset+3);
      }
      n2 = n2->cdr;
      if (n2) {
        if (n2->car) {
          dump_prefix(n2, offset+2);
          printf("rest:\n");
          if (n2->car == (node*)-1) {
            dump_prefix(n2, offset+2);
            printf("(empty)\n");
          }
          else {
            mrb_parser_dump(mrb, n2->car, offset+3);
          }
        }
        n2 = n2->cdr;
        if (n2) {
          if (n2->car) {
            dump_prefix(n2, offset+2);
            printf("post:\n");
            dump_recur(mrb, n2->car, offset+3);
          }
        }
      }
    }
    dump_prefix(tree, offset+1);
    printf("rhs:\n");
    mrb_parser_dump(mrb, tree->cdr, offset+2);
    break;

  case NODE_OP_ASGN:
    printf("NODE_OP_ASGN:\n");
    dump_prefix(tree, offset+1);
    printf("lhs:\n");
    mrb_parser_dump(mrb, tree->car, offset+2);
    tree = tree->cdr;
    dump_prefix(tree, offset+1);
    printf("op='%s' (%d)\n", mrb_sym2name(mrb, sym(tree->car)), (int)(intptr_t)tree->car);
    tree = tree->cdr;
    mrb_parser_dump(mrb, tree->car, offset+1);
    break;

  case NODE_SUPER:
    printf("NODE_SUPER:\n");
    if (tree) {
      dump_prefix(tree, offset+1);
      printf("args:\n");
      dump_recur(mrb, tree->car, offset+2);
      if (tree->cdr) {
        dump_prefix(tree, offset+1);
        printf("block:\n");
        mrb_parser_dump(mrb, tree->cdr, offset+2);
      }
    }
    break;

  case NODE_ZSUPER:
    printf("NODE_ZSUPER\n");
    break;

  case NODE_RETURN:
    printf("NODE_RETURN:\n");
    mrb_parser_dump(mrb, tree, offset+1);
    break;

  case NODE_YIELD:
    printf("NODE_YIELD:\n");
    dump_recur(mrb, tree, offset+1);
    break;

  case NODE_BREAK:
    printf("NODE_BREAK:\n");
    mrb_parser_dump(mrb, tree, offset+1);
    break;

  case NODE_NEXT:
    printf("NODE_NEXT:\n");
    mrb_parser_dump(mrb, tree, offset+1);
    break;

  case NODE_REDO:
    printf("NODE_REDO\n");
    break;

  case NODE_RETRY:
    printf("NODE_RETRY\n");
    break;

  case NODE_LVAR:
    printf("NODE_LVAR %s\n", mrb_sym2name(mrb, sym(tree)));
    break;

  case NODE_GVAR:
    printf("NODE_GVAR %s\n", mrb_sym2name(mrb, sym(tree)));
    break;

  case NODE_IVAR:
    printf("NODE_IVAR %s\n", mrb_sym2name(mrb, sym(tree)));
    break;

  case NODE_CVAR:
    printf("NODE_CVAR %s\n", mrb_sym2name(mrb, sym(tree)));
    break;

  case NODE_CONST:
    printf("NODE_CONST %s\n", mrb_sym2name(mrb, sym(tree)));
    break;

  case NODE_MATCH:
    printf("NODE_MATCH:\n");
    dump_prefix(tree, offset + 1);
    printf("lhs:\n");
    mrb_parser_dump(mrb, tree->car, offset + 2);
    dump_prefix(tree, offset + 1);
    printf("rhs:\n");
    mrb_parser_dump(mrb, tree->cdr, offset + 2);
    break;

  case NODE_BACK_REF:
    printf("NODE_BACK_REF: $%c\n", (int)(intptr_t)tree);
    break;

  case NODE_NTH_REF:
    printf("NODE_NTH_REF: $%" MRB_PRId "\n", (mrb_int)(intptr_t)tree);
    break;

  case NODE_ARG:
    printf("NODE_ARG %s\n", mrb_sym2name(mrb, sym(tree)));
    break;

  case NODE_BLOCK_ARG:
    printf("NODE_BLOCK_ARG:\n");
    mrb_parser_dump(mrb, tree, offset+1);
    break;

  case NODE_INT:
    printf("NODE_INT %s base %d\n", (char*)tree->car, (int)(intptr_t)tree->cdr->car);
    break;

  case NODE_FLOAT:
    printf("NODE_FLOAT %s\n", (char*)tree);
    break;

  case NODE_NEGATE:
    printf("NODE_NEGATE\n");
    mrb_parser_dump(mrb, tree, offset+1);
    break;

  case NODE_STR:
    printf("NODE_STR \"%s\" len %d\n", (char*)tree->car, (int)(intptr_t)tree->cdr);
    break;

  case NODE_DSTR:
    printf("NODE_DSTR\n");
    dump_recur(mrb, tree, offset+1);
    break;

  case NODE_XSTR:
    printf("NODE_XSTR \"%s\" len %d\n", (char*)tree->car, (int)(intptr_t)tree->cdr);
    break;

  case NODE_DXSTR:
    printf("NODE_DXSTR\n");
    dump_recur(mrb, tree, offset+1);
    break;

  case NODE_REGX:
    printf("NODE_REGX /%s/%s\n", (char*)tree->car, (char*)tree->cdr);
    break;

  case NODE_DREGX:
    printf("NODE_DREGX\n");
    dump_recur(mrb, tree->car, offset+1);
    dump_prefix(tree, offset);
    printf("tail: %s\n", (char*)tree->cdr->cdr->car);
    if (tree->cdr->cdr->cdr->car) {
      dump_prefix(tree, offset);
      printf("opt: %s\n", (char*)tree->cdr->cdr->cdr->car);
    }
    if (tree->cdr->cdr->cdr->cdr) {
      dump_prefix(tree, offset);
      printf("enc: %s\n", (char*)tree->cdr->cdr->cdr->cdr);
    }
    break;

  case NODE_SYM:
    printf("NODE_SYM :%s (%d)\n", mrb_sym2name(mrb, sym(tree)),
           (int)(intptr_t)tree);
    break;

  case NODE_SELF:
    printf("NODE_SELF\n");
    break;

  case NODE_NIL:
    printf("NODE_NIL\n");
    break;

  case NODE_TRUE:
    printf("NODE_TRUE\n");
    break;

  case NODE_FALSE:
    printf("NODE_FALSE\n");
    break;

  case NODE_ALIAS:
    printf("NODE_ALIAS %s %s:\n",
        mrb_sym2name(mrb, sym(tree->car)),
        mrb_sym2name(mrb, sym(tree->cdr)));
    break;

  case NODE_UNDEF:
    printf("NODE_UNDEF");
    {
      node *t = tree;
      while (t) {
        printf(" %s", mrb_sym2name(mrb, sym(t->car)));
        t = t->cdr;
      }
    }
    printf(":\n");
    break;

  case NODE_CLASS:
    printf("NODE_CLASS:\n");
    if (tree->car->car == (node*)0) {
      dump_prefix(tree, offset+1);
      printf(":%s\n", mrb_sym2name(mrb, sym(tree->car->cdr)));
    }
    else if (tree->car->car == (node*)1) {
      dump_prefix(tree, offset+1);
      printf("::%s\n", mrb_sym2name(mrb, sym(tree->car->cdr)));
    }
    else {
      mrb_parser_dump(mrb, tree->car->car, offset+1);
      dump_prefix(tree, offset+1);
      printf("::%s\n", mrb_sym2name(mrb, sym(tree->car->cdr)));
    }
    if (tree->cdr->car) {
      dump_prefix(tree, offset+1);
      printf("super:\n");
      mrb_parser_dump(mrb, tree->cdr->car, offset+2);
    }
    dump_prefix(tree, offset+1);
    printf("body:\n");
    mrb_parser_dump(mrb, tree->cdr->cdr->car->cdr, offset+2);
    break;

  case NODE_MODULE:
    printf("NODE_MODULE:\n");
    if (tree->car->car == (node*)0) {
      dump_prefix(tree, offset+1);
      printf(":%s\n", mrb_sym2name(mrb, sym(tree->car->cdr)));
    }
    else if (tree->car->car == (node*)1) {
      dump_prefix(tree, offset+1);
      printf("::%s\n", mrb_sym2name(mrb, sym(tree->car->cdr)));
    }
    else {
      mrb_parser_dump(mrb, tree->car->car, offset+1);
      dump_prefix(tree, offset+1);
      printf("::%s\n", mrb_sym2name(mrb, sym(tree->car->cdr)));
    }
    dump_prefix(tree, offset+1);
    printf("body:\n");
    mrb_parser_dump(mrb, tree->cdr->car->cdr, offset+2);
    break;

  case NODE_SCLASS:
    printf("NODE_SCLASS:\n");
    mrb_parser_dump(mrb, tree->car, offset+1);
    dump_prefix(tree, offset+1);
    printf("body:\n");
    mrb_parser_dump(mrb, tree->cdr->car->cdr, offset+2);
    break;

  case NODE_DEF:
    printf("NODE_DEF:\n");
    dump_prefix(tree, offset+1);
    printf("%s\n", mrb_sym2name(mrb, sym(tree->car)));
    tree = tree->cdr;
    {
      node *n2 = tree->car;
      mrb_bool first_lval = TRUE;

      if (n2 && (n2->car || n2->cdr)) {
        dump_prefix(n2, offset+1);
        printf("local variables:\n");
        dump_prefix(n2, offset+2);
        while (n2) {
          if (n2->car) {
            if (!first_lval) printf(", ");
            printf("%s", mrb_sym2name(mrb, sym(n2->car)));
            first_lval = FALSE;
          }
          n2 = n2->cdr;
        }
        printf("\n");
      }
    }
    tree = tree->cdr;
    if (tree->car) {
      node *n = tree->car;

      if (n->car) {
        dump_prefix(n, offset+1);
        printf("mandatory args:\n");
        dump_recur(mrb, n->car, offset+2);
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("optional args:\n");
        {
          node *n2 = n->car;

          while (n2) {
            dump_prefix(n2, offset+2);
            printf("%s=", mrb_sym2name(mrb, sym(n2->car->car)));
            mrb_parser_dump(mrb, n2->car->cdr, 0);
            n2 = n2->cdr;
          }
        }
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("rest=*%s\n", mrb_sym2name(mrb, sym(n->car)));
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("post mandatory args:\n");
        dump_recur(mrb, n->car, offset+2);
      }
      if (n->cdr) {
        dump_prefix(n, offset+1);
        printf("blk=&%s\n", mrb_sym2name(mrb, sym(n->cdr)));
      }
    }
    mrb_parser_dump(mrb, tree->cdr->car, offset+1);
    break;

  case NODE_SDEF:
    printf("NODE_SDEF:\n");
    mrb_parser_dump(mrb, tree->car, offset+1);
    tree = tree->cdr;
    dump_prefix(tree, offset+1);
    printf(":%s\n", mrb_sym2name(mrb, sym(tree->car)));
    tree = tree->cdr->cdr;
    if (tree->car) {
      node *n = tree->car;

      if (n->car) {
        dump_prefix(n, offset+1);
        printf("mandatory args:\n");
        dump_recur(mrb, n->car, offset+2);
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("optional args:\n");
        {
          node *n2 = n->car;

          while (n2) {
            dump_prefix(n2, offset+2);
            printf("%s=", mrb_sym2name(mrb, sym(n2->car->car)));
            mrb_parser_dump(mrb, n2->car->cdr, 0);
            n2 = n2->cdr;
          }
        }
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("rest=*%s\n", mrb_sym2name(mrb, sym(n->car)));
      }
      n = n->cdr;
      if (n->car) {
        dump_prefix(n, offset+1);
        printf("post mandatory args:\n");
        dump_recur(mrb, n->car, offset+2);
      }
      n = n->cdr;
      if (n) {
        dump_prefix(n, offset+1);
        printf("blk=&%s\n", mrb_sym2name(mrb, sym(n)));
      }
    }
    tree = tree->cdr;
    mrb_parser_dump(mrb, tree->car, offset+1);
    break;

  case NODE_POSTEXE:
    printf("NODE_POSTEXE:\n");
    mrb_parser_dump(mrb, tree, offset+1);
    break;

  case NODE_HEREDOC:
    printf("NODE_HEREDOC (<<%s):\n", ((parser_heredoc_info*)tree)->term);
    dump_recur(mrb, ((parser_heredoc_info*)tree)->doc, offset+1);
    break;

  default:
    printf("node type: %d (0x%x)\n", nodetype, (unsigned)nodetype);
    break;
  }
#endif
}

