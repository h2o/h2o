#include <mruby.h>
#include <stdio.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/class.h>
#include <mruby/variable.h>
#include <mruby/value.h>

/* PostgreSQL headers */
#include "libpq-fe.h"
#include "libpq/libpq-fs.h"
#include "pg_config_manual.h"

#define mrb_mPG(mrb) (mrb_module_get(mrb, "PG"))
#define mrb_cPGconn(mrb) (mrb_class_get_under(mrb, mrb_mPG(mrb), "Connection"))
#define mrb_ePGerror(mrb) (mrb_class_get_under(mrb, mrb_mPG(mrb), "Error"))
#define mrb_cPGresult(mrb) (mrb_class_get_under(mrb, mrb_mPG(mrb), "Result"))


/****************************************************************
 * Global functions
 ****************************************************************/

/*
 * Object validity checker. Returns the data pointer.
 */
static PGconn *
pgconn_check(mrb_state *mrb, mrb_value self) {
  if (!mrb_obj_is_kind_of(mrb, self, mrb_cPGconn(mrb))) {
    mrb_raisef(mrb, E_TYPE_ERROR,
               "wrong argument type %s (expected PG::Connection)",
               mrb_obj_classname(mrb, self));
  }

  return DATA_PTR(self);
}

PGconn *
pg_get_pgconn(mrb_state *mrb, mrb_value self)
{
  PGconn *conn = pgconn_check(mrb, self);

  if (!conn) {
    mrb_raise(mrb, mrb_ePGerror(mrb), "connection is closed");
  }

  return conn;
}


/****************************************************************
 * PG::Result
 ****************************************************************/

/*
 * GC Free function
 */
static void
pgresult_gc_free(mrb_state *mrb, void *result)
{
  if(result != NULL) {
    PQclear((PGresult *)result);
  }
}

const struct mrb_data_type mrb_pgresult_type = {
  "pgresult", pgresult_gc_free,
};

/*
 * Fetch the data pointer for the result object
 */
static PGresult*
pgresult_get(mrb_state *mrb, mrb_value self)
{
  PGresult *result;

  Data_Get_Struct(mrb, self, &mrb_pgresult_type, result);
  if (result == NULL) {
    mrb_raise(mrb, mrb_ePGerror(mrb), "result has been cleared");
  }
  return result;
}


/*
 * Result constructor
 */
mrb_value
pg_new_result(mrb_state *mrb, PGresult *result, mrb_value mrb_pgconn)
{
  mrb_value val;
  
  val = mrb_obj_value(Data_Wrap_Struct(mrb, mrb_cPGresult(mrb), &mrb_pgresult_type, result));
  mrb_iv_set(mrb, val, mrb_intern_lit(mrb, "@connection"), mrb_pgconn);

  return val;
}

static mrb_value
pgresult_value(mrb_state *mrb, mrb_value self, PGresult *result, int tuple_num, int field_num)
{
  mrb_value val;
  if (PQgetisnull(result, tuple_num, field_num)) {
    return mrb_nil_value();
  }
  else {
    val = mrb_str_new(mrb,
                      PQgetvalue(result, tuple_num, field_num),
                      PQgetlength(result, tuple_num, field_num));

    return val;
  }
}

/*
 * call-seq:
 *    res[ n ] -> Hash
 *
 * Returns tuple _n_ as a hash.
 */
static mrb_value
pgresult_aref(mrb_state *mrb, mrb_value self)
{
  PGresult *result = pgresult_get(mrb, self);
  int field_num;
  mrb_value fname;
  mrb_value tuple;
  mrb_value index;
  int tuple_num;

  mrb_get_args(mrb, "i", &index);
  tuple_num = mrb_fixnum(index);

  if (tuple_num < 0 || tuple_num >= PQntuples(result)) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "Index %d is out of range", tuple_num);
  }

  tuple = mrb_hash_new(mrb);
  for (field_num = 0; field_num < PQnfields(result); field_num++) {
    fname = mrb_str_new_cstr(mrb, PQfname(result,field_num));
    mrb_hash_set(mrb, tuple, fname, pgresult_value(mrb, self, result, tuple_num, field_num));
  }
  return tuple;
}

/*
 * call-seq:
 *    res.size  -> Integer
 *
 * Record size.
 */
static mrb_value
pgresult_size(mrb_state *mrb, mrb_value self)
{
  PGresult *result = pgresult_get(mrb, self);
  return mrb_fixnum_value(PQntuples(result));
}

/*
 * call-seq:
 *    res.check -> nil
 *
 * Raises appropriate exception if PG::Result is in a bad state.
 */
mrb_value
pgresult_check(mrb_state *mrb, mrb_value self)
{
  mrb_value error;
  PGresult *result;
  mrb_value mrb_pgconn = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@connection"));
  PGconn *conn = pg_get_pgconn(mrb, mrb_pgconn);

  Data_Get_Struct(mrb, self, &mrb_pgresult_type, result);

  if (result == NULL)
  {
    error = mrb_str_new_cstr(mrb, PQerrorMessage(conn));
  }
  else
  {
    switch (PQresultStatus(result))
    {
    case PGRES_TUPLES_OK:
    case PGRES_COPY_OUT:
    case PGRES_COPY_IN:
#ifdef HAVE_CONST_PGRES_COPY_BOTH
    case PGRES_COPY_BOTH:
#endif
#ifdef HAVE_CONST_PGRES_SINGLE_TUPLE
    case PGRES_SINGLE_TUPLE:
#endif
    case PGRES_EMPTY_QUERY:
    case PGRES_COMMAND_OK:
      return self;
    case PGRES_BAD_RESPONSE:
    case PGRES_FATAL_ERROR:
    case PGRES_NONFATAL_ERROR:
      error = mrb_str_new_cstr(mrb, PQresultErrorMessage(result));
      break;
    default:
      error = mrb_str_new_cstr(mrb, "internal error : unknown result status.");
    }
  }

  mrb_raise(mrb, mrb_ePGerror(mrb), RSTRING_PTR(error));

  /* Not reached */
  return self;
}

/*
 * call-seq:
 *    res.clear() -> nil
 *
 * Clears the PG::Result object as the result of the query.
 */
static mrb_value
pgresult_clear(mrb_state *mrb, mrb_value self)
{
  PQclear(pgresult_get(mrb, self));
  DATA_PTR(self) = NULL;
  return mrb_nil_value();
}


/****************************************************************
 * PG::Connection
 ****************************************************************/

static void
pgconn_free(mrb_state *mrb, void *conn)
{
  if (conn != NULL) {
    PQfinish((PGconn *)conn);
  }
}

const struct mrb_data_type mrb_pgconn_type = {
  "pgconn", pgconn_free,
};

static mrb_value
pgconn_init(mrb_state *mrb, mrb_value self)
{
  PGconn *conn = NULL;
  mrb_value *argv;
  int argc;
  mrb_value conninfo;

  argc = mrb_get_args(mrb, "*", &argv, &argc);
  conninfo = mrb_funcall_argv(mrb,
                              mrb_obj_value(mrb_cPGconn(mrb)),
                              mrb_intern_lit(mrb, "parse_connect_args"),
                              argc, argv);
  conn = PQconnectdb(mrb_string_value_ptr(mrb, conninfo));

  if (conn == NULL) {
    mrb_raise(mrb, mrb_ePGerror(mrb),
              "PQconnectdb() unable to allocate structure");
  }

  DATA_PTR(self) = conn;
  DATA_TYPE(self) = &mrb_pgconn_type;

  if (PQstatus(conn) == CONNECTION_BAD) {
    mrb_raise(mrb, mrb_ePGerror(mrb), PQerrorMessage(conn));
  }

  return self;
}

/*
 * call-seq:
 *    conn.get_result() -> PG::Result
 *
 * Blocks waiting for the next result from a call to
 * #send_query (or another asynchronous command), and returns
 * it. Returns +nil+ if no more results are available.
 *
 * Note: call this function repeatedly until it returns +nil+, or else
 * you will not be able to issue further commands.
 */
static mrb_value
pgconn_get_result(mrb_state *mrb, mrb_value self)
{
  PGconn *conn = pg_get_pgconn(mrb, self);
  PGresult *result;
  mrb_value mrb_pgresult;

  result = PQgetResult(conn);
  if(result == NULL) {
    return mrb_nil_value();
  }
  mrb_pgresult = pg_new_result(mrb, result, self);
  return mrb_pgresult;
}

/*
 * call-seq:
 *    conn.exec_params(sql, params[, result_format ] ) -> PG::Result
 *    conn.exec_params(sql, params[, result_format ] ) {|pg_result| block }
 *
 * Sends SQL query request specified by +sql+ to PostgreSQL using placeholders
 * for parameters.
 *
 * Returns a PG::Result instance on success. On failure, it raises a PG::Error.
 *
 * +params+ is an array of the bind parameters for the SQL query.
 * Each element of the +params+ array may be either:
 *   a hash of the form:
 *     {:value  => String (value of bind parameter)
 *      :type   => Fixnum (oid of type of bind parameter)
 *      :format => Fixnum (0 for text, 1 for binary)
 *     }
 *   or, it may be a String. If it is a string, that is equivalent to the hash:
 *     { :value => <string value>, :type => 0, :format => 0 }
 *
 * PostgreSQL bind parameters are represented as $1, $1, $2, etc.,
 * inside the SQL query. The 0th element of the +params+ array is bound
 * to $1, the 1st element is bound to $2, etc. +nil+ is treated as +NULL+.
 *
 * If the types are not specified, they will be inferred by PostgreSQL.
 * Instead of specifying type oids, it's recommended to simply add
 * explicit casts in the query to ensure that the right type is used.
 *
 * For example: "SELECT $1::int"
 *
 * The optional +result_format+ should be 0 for text results, 1
 * for binary.
 *
 * If the optional code block is given, it will be passed <i>result</i> as an argument,
 * and the PG::Result object will  automatically be cleared when the block terminates.
 * In this instance, <code>conn.exec</code> returns the value of the block.
 */
static mrb_value
pgconn_exec_params(mrb_state *mrb, mrb_value self)
{
  PGconn *conn = pg_get_pgconn(mrb, self);
  PGresult *result = NULL;
  mrb_value mrb_pgresult;
  mrb_value command, params, in_res_fmt, block;
  mrb_value param, param_type, param_value, param_format;
  mrb_value param_value_tmp;
  mrb_sym sym_type, sym_value, sym_format;
  mrb_value gc_array;
  int i=0;
  int nParams, argc;
  Oid *paramTypes;
  char ** paramValues;
  int *paramLengths;
  int *paramFormats;
  int resultFormat;

  argc = mrb_get_args(mrb, "SA|i&", &command, &params, &in_res_fmt, &block);

  /*
   * Handle the edge-case where the caller is coming from #exec, but passed an explict +nil+
   * for the second parameter.
   */
  mrb_check_type(mrb, params, MRB_TT_ARRAY);

  if (argc < 3) {
    resultFormat = 0;
  }
  else {
    resultFormat = mrb_fixnum(in_res_fmt);
  }

  gc_array = mrb_ary_new(mrb);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@__tmp_gc_array"), gc_array);

  sym_type = mrb_intern_cstr(mrb, "type");
  sym_value = mrb_intern_cstr(mrb, "value");
  sym_format = mrb_intern_cstr(mrb, "format");
  nParams = (int)RARRAY_LEN(params);
  paramTypes =  mrb_malloc(mrb, (sizeof(Oid) * nParams));
  paramValues = mrb_malloc(mrb, (sizeof(char *) * nParams));
  paramLengths = mrb_malloc(mrb, (sizeof(int) * nParams));
  paramFormats = mrb_malloc(mrb, (sizeof(int) * nParams));

  for ( i = 0; i < nParams; i++ ) {
    param = mrb_ary_entry(params, i);
    if (mrb_hash_p(param)) {
      param_type = mrb_hash_get(mrb, param, mrb_symbol_value(sym_type));
      param_value_tmp = mrb_hash_get(mrb, param, mrb_symbol_value(sym_value));
      if (mrb_nil_p(param_value_tmp)) {
        param_value = param_value_tmp;
      }
      else {
        param_value = mrb_obj_as_string(mrb, param_value_tmp);
      }
      param_format = mrb_hash_get(mrb, param, mrb_symbol_value(sym_format));
    }
    else {
      param_type = mrb_nil_value();
      if (mrb_nil_p(param)) {
        param_value = param;
      }
      else {
        param_value = mrb_obj_as_string(mrb, param);
      }
      param_format = mrb_nil_value();
    }

    if (mrb_nil_p(param_type)) {
      paramTypes[i] = 0;
    }
    else {
      paramTypes[i] = mrb_fixnum(param_type);
    }

    if(mrb_nil_p(param_value)) {
      paramValues[i] = NULL;
      paramLengths[i] = 0;
    }
    else {
      mrb_check_type(mrb, param_value, MRB_TT_STRING);
      /* make sure param_value doesn't get freed by the GC */
      mrb_ary_push(mrb, gc_array, param_value);
      paramValues[i] = RSTRING_PTR(param_value);
      paramLengths[i] = (int)RSTRING_LEN(param_value);
    }

    if (mrb_nil_p(param_format)) {
      paramFormats[i] = 0;
    }
    else {
      paramFormats[i] = mrb_fixnum(param_format);
    }
  }

  result = PQexecParams(conn, RSTRING_PTR(command), nParams, paramTypes,
    (const char * const *)paramValues, paramLengths, paramFormats, resultFormat);

  mrb_free(mrb, paramTypes);
  mrb_free(mrb, paramValues);
  mrb_free(mrb, paramLengths);
  mrb_free(mrb, paramFormats);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@__tmp_gc_array"), mrb_nil_value());

  mrb_pgresult = pg_new_result(mrb, result, self);
  pgresult_check(mrb, mrb_pgresult);

  if(!mrb_nil_p(block))
    return mrb_funcall_with_block(mrb,mrb_pgresult,mrb_intern_lit(mrb, "each"),0,NULL,block);

  return mrb_pgresult;
}

/*
 * call-seq:
 *    conn.exec(sql) -> PG::Result
 *    conn.exec(sql) {|pg_result| block }
 *
 * Sends SQL query request specified by _sql_ to PostgreSQL.
 * Returns a PG::Result instance on success.
 * On failure, it raises a PG::Error.
 *
 * If the optional code block is given, it will be passed <i>result</i> as an argument,
 * and the PG::Result object will  automatically be cleared when the block terminates.
 * In this instance, <code>conn.exec</code> returns the value of the block.
 */
static mrb_value
pgconn_exec(mrb_state *mrb, mrb_value self)
{
  PGconn *conn = pg_get_pgconn(mrb, self);
  PGresult *result = NULL;
  mrb_value *argv,b;
  mrb_value mrb_pgresult;
  int argc;

  mrb_get_args(mrb, "*&", &argv, &argc, &b);

  if(argc>1)
  {
    if(mrb_nil_p(b))
      return mrb_funcall_argv(mrb,self,mrb_intern_lit(mrb, "exec_params"),argc,argv);
    return mrb_funcall_with_block(mrb,self,mrb_intern_lit(mrb, "exec_params"),argc,argv,b);       
  }

  result = PQexec(conn, RSTRING_PTR(argv[0]));
  mrb_pgresult = pg_new_result(mrb, result, self);
  pgresult_check(mrb, mrb_pgresult);

  if(!mrb_nil_p(b))
    return mrb_funcall_with_block(mrb,mrb_pgresult,mrb_intern_lit(mrb, "each"),0,NULL,b);
  
  return mrb_pgresult;
}

/****************************************************************
 * mrb init/final
 ****************************************************************/

void
mrb_mruby_pg_gem_init(mrb_state* mrb) {
  struct RClass *_mPG, *_cPGconn, *_cPGresult;

  _mPG = mrb_define_module(mrb, "PG");

  _cPGconn = mrb_define_class_under(mrb, _mPG, "Connection", mrb->object_class);
  MRB_SET_INSTANCE_TT(_cPGconn, MRB_TT_DATA);
  mrb_define_method(mrb, _cPGconn, "initialize", pgconn_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _cPGconn, "connect", pgconn_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _cPGconn, "open", pgconn_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _cPGconn, "setdb", pgconn_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _cPGconn, "setdblogin", pgconn_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, _cPGconn, "exec", pgconn_exec, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _cPGconn, "exec_params", pgconn_exec_params, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, _cPGconn, "get_result", pgconn_get_result, MRB_ARGS_NONE());
  

  mrb_define_class_under(mrb, _mPG, "Error", mrb->eStandardError_class);

  _cPGresult = mrb_define_class_under(mrb, _mPG, "Result", mrb->object_class);
  MRB_SET_INSTANCE_TT(_cPGresult, MRB_TT_DATA);
  mrb_include_module(mrb, _cPGresult, mrb_module_get(mrb, "Enumerable"));

  /******     PG::Result INSTANCE METHODS: other     ******/
  mrb_define_method(mrb, _cPGresult, "[]", pgresult_aref, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, _cPGresult, "size", pgresult_size, MRB_ARGS_NONE());
  mrb_define_method(mrb, _cPGresult, "length", pgresult_size, MRB_ARGS_NONE());
  mrb_define_method(mrb, _cPGresult, "check", pgresult_check, MRB_ARGS_NONE());
  mrb_define_method(mrb, _cPGresult, "clear", pgresult_clear, MRB_ARGS_NONE());
}

void
mrb_mruby_pg_gem_final(mrb_state* mrb) {
  /* finalizer */
}
