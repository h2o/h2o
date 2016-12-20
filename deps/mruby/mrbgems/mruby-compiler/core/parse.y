/*
** parse.y - mruby parser
**
** See Copyright Notice in mruby.h
*/

%{
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
  return list4((node*)NODE_IF, a, b, c);
}

/* (:unless cond then else) */
static node*
new_unless(parser_state *p, node *a, node *b, node *c)
{
  return list4((node*)NODE_IF, a, c, b);
}

/* (:while cond body) */
static node*
new_while(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_WHILE, cons(a, b));
}

/* (:until cond body) */
static node*
new_until(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_UNTIL, cons(a, b));
}

/* (:for var obj body) */
static node*
new_for(parser_state *p, node *v, node *o, node *b)
{
  return list4((node*)NODE_FOR, v, o, b);
}

/* (:case a ((when ...) body) ((when...) body)) */
static node*
new_case(parser_state *p, node *a, node *b)
{
  node *n = list2((node*)NODE_CASE, a);
  node *n2 = n;

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
  return list4((node*)NODE_CLASS, c, s, cons(locals_node(p), b));
}

/* (:sclass obj body) */
static node*
new_sclass(parser_state *p, node *o, node *b)
{
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
  return cons((node*)NODE_ASGN, cons(a, b));
}

/* (:masgn mlhs=(pre rest post)  mrhs) */
static node*
new_masgn(parser_state *p, node *a, node *b)
{
  return cons((node*)NODE_MASGN, cons(a, b));
}

/* (:asgn lhs rhs) */
static node*
new_op_asgn(parser_state *p, node *a, mrb_sym op, node *b)
{
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

/* (:str . (a . a)) */
static node*
new_regx(parser_state *p, const char *p1, const char* p2, const char* p3)
{
  return cons((node*)NODE_REGX, cons((node*)p1, cons((node*)p2, (node*)p3)));
}

/* (:dregx . a) */
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

%}

%pure-parser
%parse-param {parser_state *p}
%lex-param {parser_state *p}

%union {
    node *nd;
    mrb_sym id;
    int num;
    stack_type stack;
    const struct vtable *vars;
}

%token <num>
        keyword_class
        keyword_module
        keyword_def
        keyword_begin
        keyword_if
        keyword_unless
        keyword_while
        keyword_until
        keyword_for

%token
        keyword_undef
        keyword_rescue
        keyword_ensure
        keyword_end
        keyword_then
        keyword_elsif
        keyword_else
        keyword_case
        keyword_when
        keyword_break
        keyword_next
        keyword_redo
        keyword_retry
        keyword_in
        keyword_do
        keyword_do_cond
        keyword_do_block
        keyword_do_LAMBDA
        keyword_return
        keyword_yield
        keyword_super
        keyword_self
        keyword_nil
        keyword_true
        keyword_false
        keyword_and
        keyword_or
        keyword_not
        modifier_if
        modifier_unless
        modifier_while
        modifier_until
        modifier_rescue
        keyword_alias
        keyword_BEGIN
        keyword_END
        keyword__LINE__
        keyword__FILE__
        keyword__ENCODING__

%token <id>  tIDENTIFIER tFID tGVAR tIVAR tCONSTANT tCVAR tLABEL
%token <nd>  tINTEGER tFLOAT tCHAR tXSTRING tREGEXP
%token <nd>  tSTRING tSTRING_PART tSTRING_MID tLABEL_END
%token <nd>  tNTH_REF tBACK_REF
%token <num> tREGEXP_END

%type <nd> singleton string string_rep string_interp xstring regexp
%type <nd> literal numeric cpath symbol
%type <nd> top_compstmt top_stmts top_stmt
%type <nd> bodystmt compstmt stmts stmt expr arg primary command command_call method_call
%type <nd> expr_value arg_rhs primary_value
%type <nd> if_tail opt_else case_body cases opt_rescue exc_list exc_var opt_ensure
%type <nd> args call_args opt_call_args
%type <nd> paren_args opt_paren_args variable
%type <nd> command_args aref_args opt_block_arg block_arg var_ref var_lhs
%type <nd> command_asgn command_rhs mrhs superclass block_call block_command
%type <nd> f_block_optarg f_block_opt
%type <nd> f_arglist f_args f_arg f_arg_item f_optarg f_marg f_marg_list f_margs
%type <nd> assoc_list assocs assoc undef_list backref for_var
%type <nd> block_param opt_block_param block_param_def f_opt
%type <nd> bv_decls opt_bv_decl bvar f_larglist lambda_body
%type <nd> brace_block cmd_brace_block do_block lhs none f_bad_arg
%type <nd> mlhs mlhs_list mlhs_post mlhs_basic mlhs_item mlhs_node mlhs_inner
%type <id> fsym sym basic_symbol operation operation2 operation3
%type <id> cname fname op f_rest_arg f_block_arg opt_f_block_arg f_norm_arg f_opt_asgn
%type <nd> heredoc words symbols
%type <num> call_op call_op2     /* 0:'&.', 1:'.', 2:'::' */

%token tUPLUS             /* unary+ */
%token tUMINUS            /* unary- */
%token tPOW               /* ** */
%token tCMP               /* <=> */
%token tEQ                /* == */
%token tEQQ               /* === */
%token tNEQ               /* != */
%token tGEQ               /* >= */
%token tLEQ               /* <= */
%token tANDOP tOROP       /* && and || */
%token tMATCH tNMATCH     /* =~ and !~ */
%token tDOT2 tDOT3        /* .. and ... */
%token tAREF tASET        /* [] and []= */
%token tLSHFT tRSHFT      /* << and >> */
%token tCOLON2            /* :: */
%token tCOLON3            /* :: at EXPR_BEG */
%token <id> tOP_ASGN      /* +=, -=  etc. */
%token tASSOC             /* => */
%token tLPAREN            /* ( */
%token tLPAREN_ARG        /* ( */
%token tRPAREN            /* ) */
%token tLBRACK            /* [ */
%token tLBRACE            /* { */
%token tLBRACE_ARG        /* { */
%token tSTAR              /* * */
%token tAMPER             /* & */
%token tLAMBDA            /* -> */
%token tANDDOT            /* &. */
%token tSYMBEG tREGEXP_BEG tWORDS_BEG tSYMBOLS_BEG
%token tSTRING_BEG tXSTRING_BEG tSTRING_DVAR tLAMBEG
%token <nd> tHEREDOC_BEG  /* <<, <<- */
%token tHEREDOC_END tLITERAL_DELIM tHD_LITERAL_DELIM
%token <nd> tHD_STRING_PART tHD_STRING_MID

/*
 * precedence table
 */

%nonassoc tLOWEST
%nonassoc tLBRACE_ARG

%nonassoc  modifier_if modifier_unless modifier_while modifier_until
%left  keyword_or keyword_and
%right keyword_not
%right '=' tOP_ASGN
%left modifier_rescue
%right '?' ':'
%nonassoc tDOT2 tDOT3
%left  tOROP
%left  tANDOP
%nonassoc  tCMP tEQ tEQQ tNEQ tMATCH tNMATCH
%left  '>' tGEQ '<' tLEQ
%left  '|' '^'
%left  '&'
%left  tLSHFT tRSHFT
%left  '+' '-'
%left  '*' '/' '%'
%right tUMINUS_NUM tUMINUS
%right tPOW
%right '!' '~' tUPLUS

%token tLAST_TOKEN

%%
program         :   {
                      p->lstate = EXPR_BEG;
                      if (!p->locals) p->locals = cons(0,0);
                    }
                  top_compstmt
                    {
                      p->tree = new_scope(p, $2);
                      NODE_LINENO(p->tree, $2);
                    }
                ;

top_compstmt    : top_stmts opt_terms
                    {
                      $$ = $1;
                    }
                ;

top_stmts       : none
                    {
                      $$ = new_begin(p, 0);
                    }
                | top_stmt
                    {
                      $$ = new_begin(p, $1);
                      NODE_LINENO($$, $1);
                    }
                | top_stmts terms top_stmt
                    {
                      $$ = push($1, newline_node($3));
                    }
                | error top_stmt
                    {
                      $$ = new_begin(p, 0);
                    }
                ;

top_stmt        : stmt
                | keyword_BEGIN
                    {
                      $<nd>$ = local_switch(p);
                    }
                  '{' top_compstmt '}'
                    {
                      yyerror(p, "BEGIN not supported");
                      local_resume(p, $<nd>2);
                      $$ = 0;
                    }
                ;

bodystmt        : compstmt
                  opt_rescue
                  opt_else
                  opt_ensure
                    {
                      if ($2) {
                        $$ = new_rescue(p, $1, $2, $3);
                        NODE_LINENO($$, $1);
                      }
                      else if ($3) {
                        yywarn(p, "else without rescue is useless");
                        $$ = push($1, $3);
                      }
                      else {
                        $$ = $1;
                      }
                      if ($4) {
                        if ($$) {
                          $$ = new_ensure(p, $$, $4);
                        }
                        else {
                          $$ = push($4, new_nil(p));
                        }
                      }
                    }
                ;

compstmt        : stmts opt_terms
                    {
                      $$ = $1;
                    }
                ;

stmts           : none
                    {
                      $$ = new_begin(p, 0);
                    }
                | stmt
                    {
                      $$ = new_begin(p, $1);
                      NODE_LINENO($$, $1);
                    }
                | stmts terms stmt
                    {
                      $$ = push($1, newline_node($3));
                    }
                | error stmt
                    {
                      $$ = new_begin(p, $2);
                    }
                ;

stmt            : keyword_alias fsym {p->lstate = EXPR_FNAME;} fsym
                    {
                      $$ = new_alias(p, $2, $4);
                    }
                | keyword_undef undef_list
                    {
                      $$ = $2;
                    }
                | stmt modifier_if expr_value
                    {
                      $$ = new_if(p, cond($3), $1, 0);
                    }
                | stmt modifier_unless expr_value
                    {
                      $$ = new_unless(p, cond($3), $1, 0);
                    }
                | stmt modifier_while expr_value
                    {
                      $$ = new_while(p, cond($3), $1);
                    }
                | stmt modifier_until expr_value
                    {
                      $$ = new_until(p, cond($3), $1);
                    }
                | stmt modifier_rescue stmt
                    {
                      $$ = new_mod_rescue(p, $1, $3);
                    }
                | keyword_END '{' compstmt '}'
                    {
                      yyerror(p, "END not supported");
                      $$ = new_postexe(p, $3);
                    }
                | command_asgn
                | mlhs '=' command_call
                    {
                      $$ = new_masgn(p, $1, $3);
                    }
                | lhs '=' mrhs
                    {
                      $$ = new_asgn(p, $1, new_array(p, $3));
                    }
                | mlhs '=' arg
                    {
                      $$ = new_masgn(p, $1, $3);
                    }
                | mlhs '=' mrhs
                    {
                      $$ = new_masgn(p, $1, new_array(p, $3));
                    }
                | expr
                ;

command_asgn    : lhs '=' command_rhs
                    {
                      $$ = new_asgn(p, $1, $3);
                    }
                | var_lhs tOP_ASGN command_rhs
                    {
                      $$ = new_op_asgn(p, $1, $2, $3);
                    }
                | primary_value '[' opt_call_args rbracket tOP_ASGN command_rhs
                    {
                      $$ = new_op_asgn(p, new_call(p, $1, intern("[]",2), $3, '.'), $5, $6);
                    }
                | primary_value call_op tIDENTIFIER tOP_ASGN command_rhs
                    {
                      $$ = new_op_asgn(p, new_call(p, $1, $3, 0, $2), $4, $5);
                    }
                | primary_value call_op tCONSTANT tOP_ASGN command_rhs
                    {
                      $$ = new_op_asgn(p, new_call(p, $1, $3, 0, $2), $4, $5);
                    }
                | primary_value tCOLON2 tCONSTANT tOP_ASGN command_call
                    {
                      yyerror(p, "constant re-assignment");
                      $$ = 0;
                    }
                | primary_value tCOLON2 tIDENTIFIER tOP_ASGN command_rhs
                    {
                      $$ = new_op_asgn(p, new_call(p, $1, $3, 0, tCOLON2), $4, $5);
                    }
                | backref tOP_ASGN command_rhs
                    {
                      backref_error(p, $1);
                      $$ = new_begin(p, 0);
                    }
		;

command_rhs     : command_call   %prec tOP_ASGN
                | command_call modifier_rescue stmt
                    {
                      $$ = new_mod_rescue(p, $1, $3);
                    }
                | command_asgn
                ;


expr            : command_call
                | expr keyword_and expr
                    {
                      $$ = new_and(p, $1, $3);
                    }
                | expr keyword_or expr
                    {
                      $$ = new_or(p, $1, $3);
                    }
                | keyword_not opt_nl expr
                    {
                      $$ = call_uni_op(p, cond($3), "!");
                    }
                | '!' command_call
                    {
                      $$ = call_uni_op(p, cond($2), "!");
                    }
                | arg
                ;

expr_value      : expr
                    {
                      if (!$1) $$ = new_nil(p);
                      else {
                        void_expr_error(p, $1);
                        $$ = $1;
                      }
                    }
                ;

command_call    : command
                | block_command
                ;

block_command   : block_call
                | block_call call_op2 operation2 command_args
                ;

cmd_brace_block : tLBRACE_ARG
                    {
                      local_nest(p);
                    }
                  opt_block_param
                  compstmt
                  '}'
                    {
                      $$ = new_block(p, $3, $4);
                      local_unnest(p);
                    }
                ;

command         : operation command_args       %prec tLOWEST
                    {
                      $$ = new_fcall(p, $1, $2);
                    }
                | operation command_args cmd_brace_block
                    {
                      args_with_block(p, $2, $3);
                      $$ = new_fcall(p, $1, $2);
                    }
                | primary_value call_op operation2 command_args     %prec tLOWEST
                    {
                      $$ = new_call(p, $1, $3, $4, $2);
                    }
                | primary_value call_op operation2 command_args cmd_brace_block
                    {
                      args_with_block(p, $4, $5);
                      $$ = new_call(p, $1, $3, $4, $2);
                   }
                | primary_value tCOLON2 operation2 command_args %prec tLOWEST
                    {
                      $$ = new_call(p, $1, $3, $4, tCOLON2);
                    }
                | primary_value tCOLON2 operation2 command_args cmd_brace_block
                    {
                      args_with_block(p, $4, $5);
                      $$ = new_call(p, $1, $3, $4, tCOLON2);
                    }
                | keyword_super command_args
                    {
                      $$ = new_super(p, $2);
                    }
                | keyword_yield command_args
                    {
                      $$ = new_yield(p, $2);
                    }
                | keyword_return call_args
                    {
                      $$ = new_return(p, ret_args(p, $2));
                    }
                | keyword_break call_args
                    {
                      $$ = new_break(p, ret_args(p, $2));
                    }
                | keyword_next call_args
                    {
                      $$ = new_next(p, ret_args(p, $2));
                    }
                ;

mlhs            : mlhs_basic
                    {
                      $$ = $1;
                    }
                | tLPAREN mlhs_inner rparen
                    {
                      $$ = $2;
                    }
                ;

mlhs_inner      : mlhs_basic
                | tLPAREN mlhs_inner rparen
                    {
                      $$ = $2;
                    }
                ;

mlhs_basic      : mlhs_list
                    {
                      $$ = list1($1);
                    }
                | mlhs_list mlhs_item
                    {
                      $$ = list1(push($1,$2));
                    }
                | mlhs_list tSTAR mlhs_node
                    {
                      $$ = list2($1, $3);
                    }
                | mlhs_list tSTAR mlhs_node ',' mlhs_post
                    {
                      $$ = list3($1, $3, $5);
                    }
                | mlhs_list tSTAR
                    {
                      $$ = list2($1, new_nil(p));
                    }
                | mlhs_list tSTAR ',' mlhs_post
                    {
                      $$ = list3($1, new_nil(p), $4);
                    }
                | tSTAR mlhs_node
                    {
                      $$ = list2(0, $2);
                    }
                | tSTAR mlhs_node ',' mlhs_post
                    {
                      $$ = list3(0, $2, $4);
                    }
                | tSTAR
                    {
                      $$ = list2(0, new_nil(p));
                    }
                | tSTAR ',' mlhs_post
                    {
                      $$ = list3(0, new_nil(p), $3);
                    }
                ;

mlhs_item       : mlhs_node
                | tLPAREN mlhs_inner rparen
                    {
                      $$ = new_masgn(p, $2, NULL);
                    }
                ;

mlhs_list       : mlhs_item ','
                    {
                      $$ = list1($1);
                    }
                | mlhs_list mlhs_item ','
                    {
                      $$ = push($1, $2);
                    }
                ;

mlhs_post       : mlhs_item
                    {
                      $$ = list1($1);
                    }
                | mlhs_list mlhs_item
                    {
                      $$ = push($1, $2);
                    }
                ;

mlhs_node       : variable
                    {
                      assignable(p, $1);
                    }
                | primary_value '[' opt_call_args rbracket
                    {
                      $$ = new_call(p, $1, intern("[]",2), $3, '.');
                    }
                | primary_value call_op tIDENTIFIER
                    {
                      $$ = new_call(p, $1, $3, 0, $2);
                    }
                | primary_value tCOLON2 tIDENTIFIER
                    {
                      $$ = new_call(p, $1, $3, 0, tCOLON2);
                    }
                | primary_value call_op tCONSTANT
                    {
                      $$ = new_call(p, $1, $3, 0, $2);
                    }
                | primary_value tCOLON2 tCONSTANT
                    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "dynamic constant assignment");
                      $$ = new_colon2(p, $1, $3);
                    }
                | tCOLON3 tCONSTANT
                    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "dynamic constant assignment");
                      $$ = new_colon3(p, $2);
                    }
                | backref
                    {
                      backref_error(p, $1);
                      $$ = 0;
                    }
                ;

lhs             : variable
                    {
                      assignable(p, $1);
                    }
                | primary_value '[' opt_call_args rbracket
                    {
                      $$ = new_call(p, $1, intern("[]",2), $3, '.');
                    }
                | primary_value call_op tIDENTIFIER
                    {
                      $$ = new_call(p, $1, $3, 0, $2);
                    }
                | primary_value tCOLON2 tIDENTIFIER
                    {
                      $$ = new_call(p, $1, $3, 0, tCOLON2);
                    }
                | primary_value call_op tCONSTANT
                    {
                      $$ = new_call(p, $1, $3, 0, $2);
                    }
                | primary_value tCOLON2 tCONSTANT
                    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "dynamic constant assignment");
                      $$ = new_colon2(p, $1, $3);
                    }
                | tCOLON3 tCONSTANT
                    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "dynamic constant assignment");
                      $$ = new_colon3(p, $2);
                    }
                | backref
                    {
                      backref_error(p, $1);
                      $$ = 0;
                    }
                ;

cname           : tIDENTIFIER
                    {
                      yyerror(p, "class/module name must be CONSTANT");
                    }
                | tCONSTANT
                ;

cpath           : tCOLON3 cname
                    {
                      $$ = cons((node*)1, nsym($2));
                    }
                | cname
                    {
                      $$ = cons((node*)0, nsym($1));
                    }
                | primary_value tCOLON2 cname
                    {
                      $$ = cons($1, nsym($3));
                    }
                ;

fname           : tIDENTIFIER
                | tCONSTANT
                | tFID
                | op
                    {
                      p->lstate = EXPR_ENDFN;
                      $$ = $1;
                    }
                | reswords
                    {
                      p->lstate = EXPR_ENDFN;
                      $$ = $<id>1;
                    }
                ;

fsym            : fname
                | basic_symbol
                ;

undef_list      : fsym
                    {
                      $$ = new_undef(p, $1);
                    }
                | undef_list ',' {p->lstate = EXPR_FNAME;} fsym
                    {
                      $$ = push($1, nsym($4));
                    }
                ;

op              : '|'           { $$ = intern_c('|');   }
                | '^'           { $$ = intern_c('^');   }
                | '&'           { $$ = intern_c('&');   }
                | tCMP          { $$ = intern("<=>",3); }
                | tEQ           { $$ = intern("==",2);  }
                | tEQQ          { $$ = intern("===",3); }
                | tMATCH        { $$ = intern("=~",2);  }
                | tNMATCH       { $$ = intern("!~",2);  }
                | '>'           { $$ = intern_c('>');   }
                | tGEQ          { $$ = intern(">=",2);  }
                | '<'           { $$ = intern_c('<');   }
                | tLEQ          { $$ = intern("<=",2);  }
                | tNEQ          { $$ = intern("!=",2);  }
                | tLSHFT        { $$ = intern("<<",2);  }
                | tRSHFT        { $$ = intern(">>",2);  }
                | '+'           { $$ = intern_c('+');   }
                | '-'           { $$ = intern_c('-');   }
                | '*'           { $$ = intern_c('*');   }
                | tSTAR         { $$ = intern_c('*');   }
                | '/'           { $$ = intern_c('/');   }
                | '%'           { $$ = intern_c('%');   }
                | tPOW          { $$ = intern("**",2);  }
                | '!'           { $$ = intern_c('!');   }
                | '~'           { $$ = intern_c('~');   }
                | tUPLUS        { $$ = intern("+@",2);  }
                | tUMINUS       { $$ = intern("-@",2);  }
                | tAREF         { $$ = intern("[]",2);  }
                | tASET         { $$ = intern("[]=",3); }
                | '`'           { $$ = intern_c('`');   }
                ;

reswords        : keyword__LINE__ | keyword__FILE__ | keyword__ENCODING__
                | keyword_BEGIN | keyword_END
                | keyword_alias | keyword_and | keyword_begin
                | keyword_break | keyword_case | keyword_class | keyword_def
                | keyword_do | keyword_else | keyword_elsif
                | keyword_end | keyword_ensure | keyword_false
                | keyword_for | keyword_in | keyword_module | keyword_next
                | keyword_nil | keyword_not | keyword_or | keyword_redo
                | keyword_rescue | keyword_retry | keyword_return | keyword_self
                | keyword_super | keyword_then | keyword_true | keyword_undef
                | keyword_when | keyword_yield | keyword_if | keyword_unless
                | keyword_while | keyword_until
                ;

arg             : lhs '=' arg_rhs
                    {
                      $$ = new_asgn(p, $1, $3);
                    }
                | var_lhs tOP_ASGN arg_rhs
                    {
                      $$ = new_op_asgn(p, $1, $2, $3);
                    }
                | primary_value '[' opt_call_args rbracket tOP_ASGN arg_rhs
                    {
                      $$ = new_op_asgn(p, new_call(p, $1, intern("[]",2), $3, '.'), $5, $6);
                    }
                | primary_value call_op tIDENTIFIER tOP_ASGN arg_rhs
                    {
                      $$ = new_op_asgn(p, new_call(p, $1, $3, 0, $2), $4, $5);
                    }
                | primary_value call_op tCONSTANT tOP_ASGN arg_rhs
                    {
                      $$ = new_op_asgn(p, new_call(p, $1, $3, 0, $2), $4, $5);
                    }
                | primary_value tCOLON2 tIDENTIFIER tOP_ASGN arg_rhs
                    {
                      $$ = new_op_asgn(p, new_call(p, $1, $3, 0, tCOLON2), $4, $5);
                    }
                | primary_value tCOLON2 tCONSTANT tOP_ASGN arg_rhs
                    {
                      yyerror(p, "constant re-assignment");
                      $$ = new_begin(p, 0);
                    }
                | tCOLON3 tCONSTANT tOP_ASGN arg_rhs
                    {
                      yyerror(p, "constant re-assignment");
                      $$ = new_begin(p, 0);
                    }
                | backref tOP_ASGN arg_rhs
                    {
                      backref_error(p, $1);
                      $$ = new_begin(p, 0);
                    }
                | arg tDOT2 arg
                    {
                      $$ = new_dot2(p, $1, $3);
                    }
                | arg tDOT3 arg
                    {
                      $$ = new_dot3(p, $1, $3);
                    }
                | arg '+' arg
                    {
                      $$ = call_bin_op(p, $1, "+", $3);
                    }
                | arg '-' arg
                    {
                      $$ = call_bin_op(p, $1, "-", $3);
                    }
                | arg '*' arg
                    {
                      $$ = call_bin_op(p, $1, "*", $3);
                    }
                | arg '/' arg
                    {
                      $$ = call_bin_op(p, $1, "/", $3);
                    }
                | arg '%' arg
                    {
                      $$ = call_bin_op(p, $1, "%", $3);
                    }
                | arg tPOW arg
                    {
                      $$ = call_bin_op(p, $1, "**", $3);
                    }
                | tUMINUS_NUM tINTEGER tPOW arg
                    {
                      $$ = call_uni_op(p, call_bin_op(p, $2, "**", $4), "-@");
                    }
                | tUMINUS_NUM tFLOAT tPOW arg
                    {
                      $$ = call_uni_op(p, call_bin_op(p, $2, "**", $4), "-@");
                    }
                | tUPLUS arg
                    {
                      $$ = call_uni_op(p, $2, "+@");
                    }
                | tUMINUS arg
                    {
                      $$ = call_uni_op(p, $2, "-@");
                    }
                | arg '|' arg
                    {
                      $$ = call_bin_op(p, $1, "|", $3);
                    }
                | arg '^' arg
                    {
                      $$ = call_bin_op(p, $1, "^", $3);
                    }
                | arg '&' arg
                    {
                      $$ = call_bin_op(p, $1, "&", $3);
                    }
                | arg tCMP arg
                    {
                      $$ = call_bin_op(p, $1, "<=>", $3);
                    }
                | arg '>' arg
                    {
                      $$ = call_bin_op(p, $1, ">", $3);
                    }
                | arg tGEQ arg
                    {
                      $$ = call_bin_op(p, $1, ">=", $3);
                    }
                | arg '<' arg
                    {
                      $$ = call_bin_op(p, $1, "<", $3);
                    }
                | arg tLEQ arg
                    {
                      $$ = call_bin_op(p, $1, "<=", $3);
                    }
                | arg tEQ arg
                    {
                      $$ = call_bin_op(p, $1, "==", $3);
                    }
                | arg tEQQ arg
                    {
                      $$ = call_bin_op(p, $1, "===", $3);
                    }
                | arg tNEQ arg
                    {
                      $$ = call_bin_op(p, $1, "!=", $3);
                    }
                | arg tMATCH arg
                    {
                      $$ = call_bin_op(p, $1, "=~", $3);
                    }
                | arg tNMATCH arg
                    {
                      $$ = call_bin_op(p, $1, "!~", $3);
                    }
                | '!' arg
                    {
                      $$ = call_uni_op(p, cond($2), "!");
                    }
                | '~' arg
                    {
                      $$ = call_uni_op(p, cond($2), "~");
                    }
                | arg tLSHFT arg
                    {
                      $$ = call_bin_op(p, $1, "<<", $3);
                    }
                | arg tRSHFT arg
                    {
                      $$ = call_bin_op(p, $1, ">>", $3);
                    }
                | arg tANDOP arg
                    {
                      $$ = new_and(p, $1, $3);
                    }
                | arg tOROP arg
                    {
                      $$ = new_or(p, $1, $3);
                    }
                | arg '?' arg opt_nl ':' arg
                    {
                      $$ = new_if(p, cond($1), $3, $6);
                    }
                | primary
                    {
                      $$ = $1;
                    }
                ;

aref_args       : none
                | args trailer
                    {
                      $$ = $1;
                      NODE_LINENO($$, $1);
                    }
                | args comma assocs trailer
                    {
                      $$ = push($1, new_hash(p, $3));
                    }
                | assocs trailer
                    {
                      $$ = cons(new_hash(p, $1), 0);
                      NODE_LINENO($$, $1);
                    }
                ;

arg_rhs         : arg %prec tOP_ASGN
                    {
                      void_expr_error(p, $1);
                      $$ = $1;
                    }
                | arg modifier_rescue arg
                    {
                      void_expr_error(p, $1);
                      $$ = new_mod_rescue(p, $1, $3);
                    }
                ;

paren_args      : '(' opt_call_args rparen
                    {
                      $$ = $2;
                    }
                ;

opt_paren_args  : none
                | paren_args
                ;

opt_call_args   : none
                | call_args
                | args ','
                    {
                      $$ = cons($1,0);
                      NODE_LINENO($$, $1);
                    }
                | args comma assocs ','
                    {
                      $$ = cons(push($1, new_hash(p, $3)), 0);
                      NODE_LINENO($$, $1);
                    }
                | assocs ','
                    {
                      $$ = cons(list1(new_hash(p, $1)), 0);
                      NODE_LINENO($$, $1);
                    }
                ;

call_args       : command
                    {
                      $$ = cons(list1($1), 0);
                      NODE_LINENO($$, $1);
                    }
                | args opt_block_arg
                    {
                      $$ = cons($1, $2);
                      NODE_LINENO($$, $1);
                    }
                | assocs opt_block_arg
                    {
                      $$ = cons(list1(new_hash(p, $1)), $2);
                      NODE_LINENO($$, $1);
                    }
                | args comma assocs opt_block_arg
                    {
                      $$ = cons(push($1, new_hash(p, $3)), $4);
                      NODE_LINENO($$, $1);
                    }
                | block_arg
                    {
                      $$ = cons(0, $1);
                      NODE_LINENO($$, $1);
                    }
                ;

command_args    :  {
                      $<stack>$ = p->cmdarg_stack;
                      CMDARG_PUSH(1);
                    }
                  call_args
                    {
                      p->cmdarg_stack = $<stack>1;
                      $$ = $2;
                    }
                ;

block_arg       : tAMPER arg
                    {
                      $$ = new_block_arg(p, $2);
                    }
                ;

opt_block_arg   : comma block_arg
                    {
                      $$ = $2;
                    }
                | none
                    {
                      $$ = 0;
                    }
                ;

comma           : ','
                | ','  heredoc_bodies
                ;

args            : arg
                    {
                      void_expr_error(p, $1);
                      $$ = cons($1, 0);
                      NODE_LINENO($$, $1);
                    }
                | tSTAR arg
                    {
                      void_expr_error(p, $2);
                      $$ = cons(new_splat(p, $2), 0);
                      NODE_LINENO($$, $2);
                    }
                | args comma arg
                    {
                      void_expr_error(p, $3);
                      $$ = push($1, $3);
                    }
                | args comma tSTAR arg
                    {
                      void_expr_error(p, $4);
                      $$ = push($1, new_splat(p, $4));
                    }
                ;

mrhs            : args comma arg
                    {
                      void_expr_error(p, $3);
                      $$ = push($1, $3);
                    }
                | args comma tSTAR arg
                    {
                      void_expr_error(p, $4);
                      $$ = push($1, new_splat(p, $4));
                    }
                | tSTAR arg
                    {
                      void_expr_error(p, $2);
                      $$ = list1(new_splat(p, $2));
                    }
                ;

primary         : literal
                | string
                | xstring
                | regexp
                | heredoc
                | var_ref
                | backref
                | tFID
                    {
                      $$ = new_fcall(p, $1, 0);
                    }
                | keyword_begin
                    {
                      $<stack>$ = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    }
                  bodystmt
                  keyword_end
                    {
                      p->cmdarg_stack = $<stack>2;
                      $$ = $3;
                    }
                | tLPAREN_ARG
                    {
                      $<stack>$ = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    }
                  stmt {p->lstate = EXPR_ENDARG;} rparen
                    {
                      p->cmdarg_stack = $<stack>2;
                      $$ = $3;
                    }
                | tLPAREN_ARG {p->lstate = EXPR_ENDARG;} rparen
                    {
                      $$ = new_nil(p);
                    }
                | tLPAREN compstmt ')'
                    {
                      $$ = $2;
                    }
                | primary_value tCOLON2 tCONSTANT
                    {
                      $$ = new_colon2(p, $1, $3);
                    }
                | tCOLON3 tCONSTANT
                    {
                      $$ = new_colon3(p, $2);
                    }
                | tLBRACK aref_args ']'
                    {
                      $$ = new_array(p, $2);
                      NODE_LINENO($$, $2);
                    }
                | tLBRACE assoc_list '}'
                    {
                      $$ = new_hash(p, $2);
                      NODE_LINENO($$, $2);
                    }
                | keyword_return
                    {
                      $$ = new_return(p, 0);
                    }
                | keyword_yield opt_paren_args
                    {
                      $$ = new_yield(p, $2);
                    }
                | keyword_not '(' expr rparen
                    {
                      $$ = call_uni_op(p, cond($3), "!");
                    }
                | keyword_not '(' rparen
                    {
                      $$ = call_uni_op(p, new_nil(p), "!");
                    }
                | operation brace_block
                    {
                      $$ = new_fcall(p, $1, cons(0, $2));
                    }
                | method_call
                | method_call brace_block
                    {
                      call_with_block(p, $1, $2);
                      $$ = $1;
                    }
                | tLAMBDA
                    {
                      local_nest(p);
                      $<num>$ = p->lpar_beg;
                      p->lpar_beg = ++p->paren_nest;
                    }
                  f_larglist
                    {
                      $<stack>$ = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    }
                  lambda_body
                    {
                      p->lpar_beg = $<num>2;
                      $$ = new_lambda(p, $3, $5);
                      local_unnest(p);
                      p->cmdarg_stack = $<stack>4;
                      CMDARG_LEXPOP();
                    }
                | keyword_if expr_value then
                  compstmt
                  if_tail
                  keyword_end
                    {
                      $$ = new_if(p, cond($2), $4, $5);
                      SET_LINENO($$, $1);
                    }
                | keyword_unless expr_value then
                  compstmt
                  opt_else
                  keyword_end
                    {
                      $$ = new_unless(p, cond($2), $4, $5);
                      SET_LINENO($$, $1);
                    }
                | keyword_while {COND_PUSH(1);} expr_value do {COND_POP();}
                  compstmt
                  keyword_end
                    {
                      $$ = new_while(p, cond($3), $6);
                      SET_LINENO($$, $1);
                    }
                | keyword_until {COND_PUSH(1);} expr_value do {COND_POP();}
                  compstmt
                  keyword_end
                    {
                      $$ = new_until(p, cond($3), $6);
                      SET_LINENO($$, $1);
                    }
                | keyword_case expr_value opt_terms
                  case_body
                  keyword_end
                    {
                      $$ = new_case(p, $2, $4);
                    }
                | keyword_case opt_terms case_body keyword_end
                    {
                      $$ = new_case(p, 0, $3);
                    }
                | keyword_for for_var keyword_in
                  {COND_PUSH(1);}
                  expr_value do
                  {COND_POP();}
                  compstmt
                  keyword_end
                    {
                      $$ = new_for(p, $2, $5, $8);
                      SET_LINENO($$, $1);
                    }
                | keyword_class
                  cpath superclass
                    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "class definition in method body");
                      $<nd>$ = local_switch(p);
                    }
                  bodystmt
                  keyword_end
                    {
                      $$ = new_class(p, $2, $3, $5);
                      SET_LINENO($$, $1);
                      local_resume(p, $<nd>4);
                    }
                | keyword_class
                  tLSHFT expr
                    {
                      $<num>$ = p->in_def;
                      p->in_def = 0;
                    }
                  term
                    {
                      $<nd>$ = cons(local_switch(p), nint(p->in_single));
                      p->in_single = 0;
                    }
                  bodystmt
                  keyword_end
                    {
                      $$ = new_sclass(p, $3, $7);
                      SET_LINENO($$, $1);
                      local_resume(p, $<nd>6->car);
                      p->in_def = $<num>4;
                      p->in_single = intn($<nd>6->cdr);
                    }
                | keyword_module
                  cpath
                    {
                      if (p->in_def || p->in_single)
                        yyerror(p, "module definition in method body");
                      $<nd>$ = local_switch(p);
                    }
                  bodystmt
                  keyword_end
                    {
                      $$ = new_module(p, $2, $4);
                      SET_LINENO($$, $1);
                      local_resume(p, $<nd>3);
                    }
                | keyword_def fname
                    {
                      $<stack>$ = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    }
                    {
                      p->in_def++;
                      $<nd>$ = local_switch(p);
                    }
                  f_arglist
                  bodystmt
                  keyword_end
                    {
                      $$ = new_def(p, $2, $5, $6);
                      SET_LINENO($$, $1);
                      local_resume(p, $<nd>4);
                      p->in_def--;
                      p->cmdarg_stack = $<stack>3;
                    }
                | keyword_def singleton dot_or_colon
                    {
                      p->lstate = EXPR_FNAME;
                      $<stack>$ = p->cmdarg_stack;
                      p->cmdarg_stack = 0;
                    }
                    fname
                    {
                      p->in_single++;
                      p->lstate = EXPR_ENDFN; /* force for args */
                      $<nd>$ = local_switch(p);
                    }
                  f_arglist
                  bodystmt
                  keyword_end
                    {
                      $$ = new_sdef(p, $2, $5, $7, $8);
                      SET_LINENO($$, $1);
                      local_resume(p, $<nd>6);
                      p->in_single--;
                      p->cmdarg_stack = $<stack>4;
                    }
                | keyword_break
                    {
                      $$ = new_break(p, 0);
                    }
                | keyword_next
                    {
                      $$ = new_next(p, 0);
                    }
                | keyword_redo
                    {
                      $$ = new_redo(p);
                    }
                | keyword_retry
                    {
                      $$ = new_retry(p);
                    }
                ;

primary_value   : primary
                    {
                      $$ = $1;
                      if (!$$) $$ = new_nil(p);
                    }
                ;

then            : term
                | keyword_then
                | term keyword_then
                ;

do              : term
                | keyword_do_cond
                ;

if_tail         : opt_else
                | keyword_elsif expr_value then
                  compstmt
                  if_tail
                    {
                      $$ = new_if(p, cond($2), $4, $5);
                    }
                ;

opt_else        : none
                | keyword_else compstmt
                    {
                      $$ = $2;
                    }
                ;

for_var         : lhs
                    {
                      $$ = list1(list1($1));
                    }
                | mlhs
                ;

f_marg          : f_norm_arg
                    {
                      $$ = new_arg(p, $1);
                    }
                | tLPAREN f_margs rparen
                    {
                      $$ = new_masgn(p, $2, 0);
                    }
                ;

f_marg_list     : f_marg
                    {
                      $$ = list1($1);
                    }
                | f_marg_list ',' f_marg
                    {
                      $$ = push($1, $3);
                    }
                ;

f_margs         : f_marg_list
                    {
                      $$ = list3($1,0,0);
                    }
                | f_marg_list ',' tSTAR f_norm_arg
                    {
                      $$ = list3($1, new_arg(p, $4), 0);
                    }
                | f_marg_list ',' tSTAR f_norm_arg ',' f_marg_list
                    {
                      $$ = list3($1, new_arg(p, $4), $6);
                    }
                | f_marg_list ',' tSTAR
                    {
                      $$ = list3($1, (node*)-1, 0);
                    }
                | f_marg_list ',' tSTAR ',' f_marg_list
                    {
                      $$ = list3($1, (node*)-1, $5);
                    }
                | tSTAR f_norm_arg
                    {
                      $$ = list3(0, new_arg(p, $2), 0);
                    }
                | tSTAR f_norm_arg ',' f_marg_list
                    {
                      $$ = list3(0, new_arg(p, $2), $4);
                    }
                | tSTAR
                    {
                      $$ = list3(0, (node*)-1, 0);
                    }
                | tSTAR ',' f_marg_list
                    {
                      $$ = list3(0, (node*)-1, $3);
                    }
                ;

block_param     : f_arg ',' f_block_optarg ',' f_rest_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, $3, $5, 0, $6);
                    }
                | f_arg ',' f_block_optarg ',' f_rest_arg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, $3, $5, $7, $8);
                    }
                | f_arg ',' f_block_optarg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, $3, 0, 0, $4);
                    }
                | f_arg ',' f_block_optarg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, $3, 0, $5, $6);
                    }
                | f_arg ',' f_rest_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, 0, $3, 0, $4);
                    }
                | f_arg ','
                    {
                      $$ = new_args(p, $1, 0, 1, 0, 0);
                    }
                | f_arg ',' f_rest_arg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, 0, $3, $5, $6);
                    }
                | f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, 0, 0, 0, $2);
                    }
                | f_block_optarg ',' f_rest_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, $1, $3, 0, $4);
                    }
                | f_block_optarg ',' f_rest_arg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, $1, $3, $5, $6);
                    }
                | f_block_optarg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, $1, 0, 0, $2);
                    }
                | f_block_optarg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, $1, 0, $3, $4);
                    }
                | f_rest_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, 0, $1, 0, $2);
                    }
                | f_rest_arg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, 0, $1, $3, $4);
                    }
                | f_block_arg
                    {
                      $$ = new_args(p, 0, 0, 0, 0, $1);
                    }
                ;

opt_block_param : none
                | block_param_def
                    {
                      p->cmd_start = TRUE;
                      $$ = $1;
                    }
                ;

block_param_def : '|' opt_bv_decl '|'
                    {
                      $$ = 0;
                    }
                | tOROP
                    {
                      $$ = 0;
                    }
                | '|' block_param opt_bv_decl '|'
                    {
                      $$ = $2;
                    }
                ;


opt_bv_decl     : opt_nl
                    {
                      $$ = 0;
                    }
                | opt_nl ';' bv_decls opt_nl
                    {
                      $$ = 0;
                    }
                ;

bv_decls        : bvar
                | bv_decls ',' bvar
                ;

bvar            : tIDENTIFIER
                    {
                      local_add_f(p, $1);
                      new_bv(p, $1);
                    }
                | f_bad_arg
                ;

f_larglist      : '(' f_args opt_bv_decl ')'
                    {
                      $$ = $2;
                    }
                | f_args
                    {
                      $$ = $1;
                    }
                ;

lambda_body     : tLAMBEG compstmt '}'
                    {
                      $$ = $2;
                    }
                | keyword_do_LAMBDA compstmt keyword_end
                    {
                      $$ = $2;
                    }
                ;

do_block        : keyword_do_block
                    {
                      local_nest(p);
                    }
                  opt_block_param
                  compstmt
                  keyword_end
                    {
                      $$ = new_block(p,$3,$4);
                      local_unnest(p);
                    }
                ;

block_call      : command do_block
                    {
                      if ($1->car == (node*)NODE_YIELD) {
                        yyerror(p, "block given to yield");
                      }
                      else {
                        call_with_block(p, $1, $2);
                      }
                      $$ = $1;
                    }
                | block_call call_op2 operation2 opt_paren_args
                    {
                      $$ = new_call(p, $1, $3, $4, $2);
                    }
                | block_call call_op2 operation2 opt_paren_args brace_block
                    {
                      $$ = new_call(p, $1, $3, $4, $2);
                      call_with_block(p, $$, $5);
                    }
                | block_call call_op2 operation2 command_args do_block
                    {
                      $$ = new_call(p, $1, $3, $4, $2);
                      call_with_block(p, $$, $5);
                    }
                ;

method_call     : operation paren_args
                    {
                      $$ = new_fcall(p, $1, $2);
                    }
                | primary_value call_op operation2 opt_paren_args
                    {
                      $$ = new_call(p, $1, $3, $4, $2);
                    }
                | primary_value tCOLON2 operation2 paren_args
                    {
                      $$ = new_call(p, $1, $3, $4, tCOLON2);
                    }
                | primary_value tCOLON2 operation3
                    {
                      $$ = new_call(p, $1, $3, 0, tCOLON2);
                    }
                | primary_value call_op paren_args
                    {
                      $$ = new_call(p, $1, intern("call",4), $3, $2);
                    }
                | primary_value tCOLON2 paren_args
                    {
                      $$ = new_call(p, $1, intern("call",4), $3, tCOLON2);
                    }
                | keyword_super paren_args
                    {
                      $$ = new_super(p, $2);
                    }
                | keyword_super
                    {
                      $$ = new_zsuper(p);
                    }
                | primary_value '[' opt_call_args rbracket
                    {
                      $$ = new_call(p, $1, intern("[]",2), $3, '.');
                    }
                ;

brace_block     : '{'
                    {
                      local_nest(p);
                      $<num>$ = p->lineno;
                    }
                  opt_block_param
                  compstmt '}'
                    {
                      $$ = new_block(p,$3,$4);
                      SET_LINENO($$, $<num>2);
                      local_unnest(p);
                    }
                | keyword_do
                    {
                      local_nest(p);
                      $<num>$ = p->lineno;
                    }
                  opt_block_param
                  compstmt keyword_end
                    {
                      $$ = new_block(p,$3,$4);
                      SET_LINENO($$, $<num>2);
                      local_unnest(p);
                    }
                ;

case_body       : keyword_when args then
                  compstmt
                  cases
                    {
                      $$ = cons(cons($2, $4), $5);
                    }
                ;

cases           : opt_else
                    {
                      if ($1) {
                        $$ = cons(cons(0, $1), 0);
                      }
                      else {
                        $$ = 0;
                      }
                    }
                | case_body
                ;

opt_rescue      : keyword_rescue exc_list exc_var then
                  compstmt
                  opt_rescue
                    {
                      $$ = list1(list3($2, $3, $5));
                      if ($6) $$ = append($$, $6);
                    }
                | none
                ;

exc_list        : arg
                    {
                        $$ = list1($1);
                    }
                | mrhs
                | none
                ;

exc_var         : tASSOC lhs
                    {
                      $$ = $2;
                    }
                | none
                ;

opt_ensure      : keyword_ensure compstmt
                    {
                      $$ = $2;
                    }
                | none
                ;

literal         : numeric
                | symbol
                | words
                | symbols
                ;

string          : tCHAR
                | tSTRING
                | tSTRING_BEG tSTRING
                    {
                      $$ = $2;
                    }
                | tSTRING_BEG string_rep tSTRING
                    {
                      $$ = new_dstr(p, push($2, $3));
                    }
                ;

string_rep      : string_interp
                | string_rep string_interp
                    {
                      $$ = append($1, $2);
                    }
                ;

string_interp   : tSTRING_MID
                    {
                      $$ = list1($1);
                    }
                | tSTRING_PART
                    {
                      $<nd>$ = p->lex_strterm;
                      p->lex_strterm = NULL;
                    }
                  compstmt
                  '}'
                    {
                      p->lex_strterm = $<nd>2;
                      $$ = list2($1, $3);
                    }
                | tLITERAL_DELIM
                    {
                      $$ = list1(new_literal_delim(p));
                    }
                | tHD_LITERAL_DELIM heredoc_bodies
                    {
                      $$ = list1(new_literal_delim(p));
                    }
                ;

xstring         : tXSTRING_BEG tXSTRING
                    {
                        $$ = $2;
                    }
                | tXSTRING_BEG string_rep tXSTRING
                    {
                      $$ = new_dxstr(p, push($2, $3));
                    }
                ;

regexp          : tREGEXP_BEG tREGEXP
                    {
                        $$ = $2;
                    }
                | tREGEXP_BEG string_rep tREGEXP
                    {
                      $$ = new_dregx(p, $2, $3);
                    }
                ;

heredoc         : tHEREDOC_BEG
                ;

heredoc_bodies  : heredoc_body
                | heredoc_bodies heredoc_body
                ;

heredoc_body    : tHEREDOC_END
                    {
                      parser_heredoc_info * inf = parsing_heredoc_inf(p);
                      inf->doc = push(inf->doc, new_str(p, "", 0));
                      heredoc_end(p);
                    }
                | heredoc_string_rep tHEREDOC_END
                    {
                      heredoc_end(p);
                    }
                ;

heredoc_string_rep : heredoc_string_interp
                   | heredoc_string_rep heredoc_string_interp
                   ;

heredoc_string_interp : tHD_STRING_MID
                    {
                      parser_heredoc_info * inf = parsing_heredoc_inf(p);
                      inf->doc = push(inf->doc, $1);
                      heredoc_treat_nextline(p);
                    }
                | tHD_STRING_PART
                    {
                      $<nd>$ = p->lex_strterm;
                      p->lex_strterm = NULL;
                    }
                  compstmt
                  '}'
                    {
                      parser_heredoc_info * inf = parsing_heredoc_inf(p);
                      p->lex_strterm = $<nd>2;
                      inf->doc = push(push(inf->doc, $1), $3);
                    }
                ;

words           : tWORDS_BEG tSTRING
                    {
                      $$ = new_words(p, list1($2));
                    }
                | tWORDS_BEG string_rep tSTRING
                    {
                      $$ = new_words(p, push($2, $3));
                    }
                ;


symbol          : basic_symbol
                    {
                      $$ = new_sym(p, $1);
                    }
                | tSYMBEG tSTRING_BEG string_rep tSTRING
                    {
                      p->lstate = EXPR_END;
                      $$ = new_dsym(p, push($3, $4));
                    }
                ;

basic_symbol    : tSYMBEG sym
                    {
                      p->lstate = EXPR_END;
                      $$ = $2;
                    }
                ;

sym             : fname
                | tIVAR
                | tGVAR
                | tCVAR
                | tSTRING
                    {
                      $$ = new_strsym(p, $1);
                    }
                | tSTRING_BEG tSTRING
                    {
                      $$ = new_strsym(p, $2);
                    }
                ;

symbols         : tSYMBOLS_BEG tSTRING
                    {
                      $$ = new_symbols(p, list1($2));
                    }
                | tSYMBOLS_BEG string_rep tSTRING
                    {
                      $$ = new_symbols(p, push($2, $3));
                    }
                ;

numeric         : tINTEGER
                | tFLOAT
                | tUMINUS_NUM tINTEGER          %prec tLOWEST
                    {
                      $$ = negate_lit(p, $2);
                    }
                | tUMINUS_NUM tFLOAT            %prec tLOWEST
                    {
                      $$ = negate_lit(p, $2);
                    }
                ;

variable        : tIDENTIFIER
                    {
                      $$ = new_lvar(p, $1);
                    }
                | tIVAR
                    {
                      $$ = new_ivar(p, $1);
                    }
                | tGVAR
                    {
                      $$ = new_gvar(p, $1);
                    }
                | tCVAR
                    {
                      $$ = new_cvar(p, $1);
                    }
                | tCONSTANT
                    {
                      $$ = new_const(p, $1);
                    }
                ;

var_lhs         : variable
                    {
                      assignable(p, $1);
                    }
                ;

var_ref         : variable
                    {
                      $$ = var_reference(p, $1);
                    }
                | keyword_nil
                    {
                      $$ = new_nil(p);
                    }
                | keyword_self
                    {
                      $$ = new_self(p);
                    }
                | keyword_true
                    {
                      $$ = new_true(p);
                    }
                | keyword_false
                    {
                      $$ = new_false(p);
                    }
                | keyword__FILE__
                    {
                      if (!p->filename) {
                        p->filename = "(null)";
                      }
                      $$ = new_str(p, p->filename, strlen(p->filename));
                    }
                | keyword__LINE__
                    {
                      char buf[16];

                      snprintf(buf, sizeof(buf), "%d", p->lineno);
                      $$ = new_int(p, buf, 10);
                    }
                ;

backref         : tNTH_REF
                | tBACK_REF
                ;

superclass      : /* term */
                    {
                      $$ = 0;
                    }
                | '<'
                    {
                      p->lstate = EXPR_BEG;
                      p->cmd_start = TRUE;
                    }
                  expr_value term
                    {
                      $$ = $3;
                    } /*
                | error term
                    {
                      yyerrok;
                      $$ = 0;
                    } */
                ;

f_arglist       : '(' f_args rparen
                    {
                      $$ = $2;
                      p->lstate = EXPR_BEG;
                      p->cmd_start = TRUE;
                    }
                | f_args term
                    {
                      $$ = $1;
                    }
                ;

f_args          : f_arg ',' f_optarg ',' f_rest_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, $3, $5, 0, $6);
                    }
                | f_arg ',' f_optarg ',' f_rest_arg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, $3, $5, $7, $8);
                    }
                | f_arg ',' f_optarg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, $3, 0, 0, $4);
                    }
                | f_arg ',' f_optarg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, $3, 0, $5, $6);
                    }
                | f_arg ',' f_rest_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, 0, $3, 0, $4);
                    }
                | f_arg ',' f_rest_arg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, 0, $3, $5, $6);
                    }
                | f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, $1, 0, 0, 0, $2);
                    }
                | f_optarg ',' f_rest_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, $1, $3, 0, $4);
                    }
                | f_optarg ',' f_rest_arg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, $1, $3, $5, $6);
                    }
                | f_optarg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, $1, 0, 0, $2);
                    }
                | f_optarg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, $1, 0, $3, $4);
                    }
                | f_rest_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, 0, $1, 0, $2);
                    }
                | f_rest_arg ',' f_arg opt_f_block_arg
                    {
                      $$ = new_args(p, 0, 0, $1, $3, $4);
                    }
                | f_block_arg
                    {
                      $$ = new_args(p, 0, 0, 0, 0, $1);
                    }
                | /* none */
                    {
                      local_add_f(p, 0);
                      $$ = new_args(p, 0, 0, 0, 0, 0);
                    }
                ;

f_bad_arg       : tCONSTANT
                    {
                      yyerror(p, "formal argument cannot be a constant");
                      $$ = 0;
                    }
                | tIVAR
                    {
                      yyerror(p, "formal argument cannot be an instance variable");
                      $$ = 0;
                    }
                | tGVAR
                    {
                      yyerror(p, "formal argument cannot be a global variable");
                      $$ = 0;
                    }
                | tCVAR
                    {
                      yyerror(p, "formal argument cannot be a class variable");
                      $$ = 0;
                    }
                ;

f_norm_arg      : f_bad_arg
                    {
                      $$ = 0;
                    }
                | tIDENTIFIER
                    {
                      local_add_f(p, $1);
                      $$ = $1;
                    }
                ;

f_arg_item      : f_norm_arg
                    {
                      $$ = new_arg(p, $1);
                    }
                | tLPAREN f_margs rparen
                    {
                      $$ = new_masgn(p, $2, 0);
                    }
                ;

f_arg           : f_arg_item
                    {
                      $$ = list1($1);
                    }
                | f_arg ',' f_arg_item
                    {
                      $$ = push($1, $3);
                    }
                ;

f_opt_asgn      : tIDENTIFIER '='
                    {
                      local_add_f(p, $1);
                      $$ = $1;
                    }
                ;

f_opt           : f_opt_asgn arg
                    {
                      $$ = cons(nsym($1), $2);
                    }
                ;

f_block_opt     : f_opt_asgn primary_value
                    {
                      $$ = cons(nsym($1), $2);
                    }
                ;

f_block_optarg  : f_block_opt
                    {
                      $$ = list1($1);
                    }
                | f_block_optarg ',' f_block_opt
                    {
                      $$ = push($1, $3);
                    }
                ;

f_optarg        : f_opt
                    {
                      $$ = list1($1);
                    }
                | f_optarg ',' f_opt
                    {
                      $$ = push($1, $3);
                    }
                ;

restarg_mark    : '*'
                | tSTAR
                ;

f_rest_arg      : restarg_mark tIDENTIFIER
                    {
                      local_add_f(p, $2);
                      $$ = $2;
                    }
                | restarg_mark
                    {
                      local_add_f(p, 0);
                      $$ = -1;
                    }
                ;

blkarg_mark     : '&'
                | tAMPER
                ;

f_block_arg     : blkarg_mark tIDENTIFIER
                    {
                      local_add_f(p, $2);
                      $$ = $2;
                    }
                ;

opt_f_block_arg : ',' f_block_arg
                    {
                      $$ = $2;
                    }
                | none
                    {
                      local_add_f(p, 0);
                      $$ = 0;
                    }
                ;

singleton       : var_ref
                    {
                      $$ = $1;
                      if (!$$) $$ = new_nil(p);
                    }
                | '(' {p->lstate = EXPR_BEG;} expr rparen
                    {
                      if ($3 == 0) {
                        yyerror(p, "can't define singleton method for ().");
                      }
                      else {
                        switch ((enum node_type)intn($3->car)) {
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
                      $$ = $3;
                    }
                ;

assoc_list      : none
                | assocs trailer
                    {
                      $$ = $1;
                    }
                ;

assocs          : assoc
                    {
                      $$ = list1($1);
                      NODE_LINENO($$, $1);
                    }
                | assocs ',' assoc
                    {
                      $$ = push($1, $3);
                    }
                ;

assoc           : arg tASSOC arg
                    {
                      $$ = cons($1, $3);
                    }
                | tLABEL arg
                    {
                      $$ = cons(new_sym(p, $1), $2);
                    }
                | tLABEL_END arg
                    {
                      $$ = cons(new_sym(p, new_strsym(p, $1)), $2);
                    }
                | tSTRING_BEG tLABEL_END arg
                    {
                      $$ = cons(new_sym(p, new_strsym(p, $2)), $3);
                    }
                | tSTRING_BEG string_rep tLABEL_END arg
                    {
                      $$ = cons(new_dsym(p, push($2, $3)), $4);
                    }
                ;

operation       : tIDENTIFIER
                | tCONSTANT
                | tFID
                ;

operation2      : tIDENTIFIER
                | tCONSTANT
                | tFID
                | op
                ;

operation3      : tIDENTIFIER
                | tFID
                | op
                ;

dot_or_colon    : '.'
                | tCOLON2
                ;

call_op         : '.'
                    {
                      $$ = '.';
                    }
                | tANDDOT
                    {
                      $$ = 0;
                    }
                ;

call_op2        : call_op
                | tCOLON2
                    {
                      $$ = tCOLON2;
                    }
                ;

opt_terms       : /* none */
                | terms
                ;

opt_nl          : /* none */
                | nl
                ;

rparen          : opt_nl ')'
                ;

rbracket        : opt_nl ']'
                ;

trailer         : /* none */
                | nl
                | comma
                ;

term            : ';' {yyerrok;}
                | nl
                | heredoc_body
                ;

nl              : '\n'
                    {
                      p->lineno++;
                      p->column = 0;
                    }
                ;

terms           : term
                | terms term
                ;

none            : /* none */
                    {
                      $$ = 0;
                    }
                ;
%%
#define yylval  (*((YYSTYPE*)(p->ylval)))

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
    yyerror_i(p, "can't set variable $%d", (int)(intptr_t)n->cdr);
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
      if (c < 0) return c;
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
      yylval.nd = new_str(p, tok(p), toklen(p));
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
        yylval.nd = new_str(p, tok(p), toklen(p));
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
        yylval.nd = new_str(p, tok(p), toklen(p));
        return tSTRING_MID;
      }
    }
    tokadd(p, c);
  }

  tokfix(p);
  p->lstate = EXPR_END;
  end_strterm(p);

  if (type & STR_FUNC_XQUOTE) {
    yylval.nd = new_xstr(p, tok(p), toklen(p));
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
    } else {
      dup = NULL;
    }
    if (enc) {
      encp = strndup(&enc, 1);
    } else {
      encp = NULL;
    }
    yylval.nd = new_regx(p, s, dup, encp);

    return tREGEXP;
  }
  yylval.nd = new_str(p, tok(p), toklen(p));
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

  yylval.nd = newnode;
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
        yylval.id = intern("**",2);
        p->lstate = EXPR_BEG;
        return tOP_ASGN;
      }
      pushback(p, c);
      c = tPOW;
    }
    else {
      if (c == '=') {
        yylval.id = intern_c('*');
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
        yylval.id = intern("<<",2);
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
        yylval.id = intern(">>",2);
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
    yylval.nd = new_str(p, tok(p), toklen(p));
    p->lstate = EXPR_END;
    return tCHAR;

  case '&':
    if ((c = nextc(p)) == '&') {
      p->lstate = EXPR_BEG;
      if ((c = nextc(p)) == '=') {
        yylval.id = intern("&&",2);
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
      yylval.id = intern_c('&');
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
        yylval.id = intern("||",2);
        p->lstate = EXPR_BEG;
        return tOP_ASGN;
      }
      pushback(p, c);
      return tOROP;
    }
    if (c == '=') {
      yylval.id = intern_c('|');
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
      yylval.id = intern_c('+');
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
      yylval.id = intern_c('-');
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
        yylval.nd = new_int(p, tok(p), 16);
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
        yylval.nd = new_int(p, tok(p), 2);
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
        yylval.nd = new_int(p, tok(p), 10);
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
          yylval.nd = new_int(p, tok(p), 8);
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
        yylval.nd = new_int(p, "0", 10);
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
      yylval.nd = new_float(p, tok(p));
      return tFLOAT;
    }
    yylval.nd = new_int(p, tok(p), 10);
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
      yylval.id = intern_c('/');
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
      yylval.id = intern_c('^');
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
      yylval.id = intern_c('%');
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
      yylval.id = intern_cstr(tok(p));
      return tGVAR;

    case '-':
      tokadd(p, '$');
      tokadd(p, c);
      c = nextc(p);
      pushback(p, c);
      gvar:
      tokfix(p);
      yylval.id = intern_cstr(tok(p));
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
      yylval.nd = new_back_ref(p, c);
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
        yylval.nd = new_nth_ref(p, (int)n);
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
          yylval.id = intern_cstr(tok(p));
          return tLABEL;
        }
      }
      if (p->lstate != EXPR_DOT) {
        const struct kwtable *kw;

        /* See if it is a reserved word.  */
        kw = mrb_reserved_word(tok(p), toklen(p));
        if (kw) {
          enum mrb_lex_state_enum state = p->lstate;
          yylval.num = p->lineno;
          p->lstate = kw->state;
          if (state == EXPR_FNAME) {
            yylval.id = intern_cstr(kw->name);
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

      yylval.id = ident;
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
  struct mrb_jmpbuf buf;
  p->jmp = &buf;

  MRB_TRY(p->jmp) {

    p->cmd_start = TRUE;
    p->in_def = p->in_single = 0;
    p->nerr = p->nwarn = 0;
    p->lex_strterm = NULL;

    parser_init_cxt(p, c);
    if (yyparse(p) != 0 || p->nerr > 0) {
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
      mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_SYNTAX_ERROR, "syntax error"));
      mrb_parser_free(p);
      return mrb_undef_value();
    }
  }
  proc = mrb_generate_code(mrb, p);
  mrb_parser_free(p);
  if (proc == NULL) {
    mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_SCRIPT_ERROR, "codegen error"));
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
    printf("NODE_NTH_REF: $%d\n", (int)(intptr_t)tree);
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
    dump_prefix(tree, offset);
    printf("opt: %s\n", (char*)tree->cdr->cdr->cdr);
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
