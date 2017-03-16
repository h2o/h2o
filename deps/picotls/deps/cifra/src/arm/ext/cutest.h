/* cutest, for embedded targets. */

#ifndef CUTEST_H
#define CUTEST_H

/* Main interface. */
#define TEST_LIST const struct test__ test_list__[]
#define TEST_CHECK(cond) test_check__((cond), __FILE__, __LINE__, #cond)
/* no TEST_CHECK_ -- we don't have a good enough printf */

/* Implementation */
#include "../semihost.h"

struct test__
{
  const char *name;
  void (*func)(void);
};

extern const struct test__ test_list__[];

static void test_check__(int cond, const char *file, int line, const char *expr)
{
  if (cond)
    return; /* pass */

  emit("Failed!\n");
  emit("File: "); emit(file); emit("\n");
  emit("Line: "); emit_uint32(line); emit("\n");
  emit("Expr: "); emit(expr); emit("\n");
  quit_failure();
}

static void run_test__(const struct test__ *t)
{
  emit("  "); emit(t->name); emit(": ");
  t->func();
  emit("OK\n");
}

int main(void)
{
  emit("Running tests:\n");

  for (const struct test__ *t = test_list__;
       t->name;
       t++)
  {
    run_test__(t);
  }
  emit("Success\n");
  quit_success();
}

#endif
