/**
** @file mruby/version.h - mruby version definition
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_VERSION_H
#define MRUBY_VERSION_H

#include "common.h"

/**
 * mruby version definition macros
 */
MRB_BEGIN_DECL

/*
 * A passed in expression.
 */
#define MRB_STRINGIZE0(expr) #expr

/*
 * Passes in an expression to MRB_STRINGIZE0.
 */
#define MRB_STRINGIZE(expr) MRB_STRINGIZE0(expr)

/*
 * The version of Ruby used by mruby.
 */
#define MRUBY_RUBY_VERSION "3.1"

/*
 * Ruby engine.
 */
#define MRUBY_RUBY_ENGINE  "mruby"

/*
 * Major release version number.
 */
#define MRUBY_RELEASE_MAJOR 3

/*
 * Minor release version number.
 */
#define MRUBY_RELEASE_MINOR 1

/*
 * Tiny release version number.
 */
#define MRUBY_RELEASE_TEENY 0

/*
 * Patch level.
 */
#define MRUBY_PATCHLEVEL -1

/*
 * Patch level string. (optional)
 */
#define MRUBY_PATCHLEVEL_STR ""

#ifndef MRUBY_PATCHLEVEL_STR
# if MRUBY_PATCHLEVEL < 0
#   define MRUBY_PATCHLEVEL_STR "dev"
# else
#   define MRUBY_PATCHLEVEL_STR "p"MRB_STRINGIZE(MRUBY_PATCHLEVEL)
# endif
#endif

/*
 * The mruby version.
 */
#define MRUBY_VERSION MRB_STRINGIZE(MRUBY_RELEASE_MAJOR) "." MRB_STRINGIZE(MRUBY_RELEASE_MINOR) "." MRB_STRINGIZE(MRUBY_RELEASE_TEENY)

/*
 * Release number.
 */
#define MRUBY_RELEASE_NO (MRUBY_RELEASE_MAJOR * 100 * 100 + MRUBY_RELEASE_MINOR * 100 + MRUBY_RELEASE_TEENY)

/*
 * Release year.
 */
#define MRUBY_RELEASE_YEAR 2022

/*
 * Release month.
 */
#define MRUBY_RELEASE_MONTH 5

/*
 * Release day.
 */
#define MRUBY_RELEASE_DAY 12

/*
 * Release date as a string.
 */
#define MRUBY_RELEASE_DATE    \
  MRUBY_RELEASE_YEAR_STR "-"  \
  MRUBY_RELEASE_MONTH_STR "-" \
  MRUBY_RELEASE_DAY_STR
#define MRUBY_RELEASE_YEAR_STR MRB_STRINGIZE(MRUBY_RELEASE_YEAR)
#if MRUBY_RELEASE_MONTH < 10
#define MRUBY_RELEASE_MONTH_STR "0" MRB_STRINGIZE(MRUBY_RELEASE_MONTH)
#else
#define MRUBY_RELEASE_MONTH_STR MRB_STRINGIZE(MRUBY_RELEASE_MONTH)
#endif
#if MRUBY_RELEASE_DAY < 10
#define MRUBY_RELEASE_DAY_STR "0" MRB_STRINGIZE(MRUBY_RELEASE_DAY)
#else
#define MRUBY_RELEASE_DAY_STR MRB_STRINGIZE(MRUBY_RELEASE_DAY)
#endif

/*
 * The year mruby was first created.
 */
#define MRUBY_BIRTH_YEAR 2010

/*
 * MRuby's authors.
 */
#define MRUBY_AUTHOR "mruby developers"

/*
 * mruby's version, and release date.
 */
#define MRUBY_DESCRIPTION     \
  "mruby " MRUBY_VERSION      \
  MRUBY_PATCHLEVEL_STR        \
  " (" MRUBY_RELEASE_DATE ")" \

/*
 * mruby's copyright information.
 */
#define MRUBY_COPYRIGHT                \
  "mruby - Copyright (c) "             \
  MRB_STRINGIZE(MRUBY_BIRTH_YEAR)"-"   \
  MRB_STRINGIZE(MRUBY_RELEASE_YEAR)" " \
  MRUBY_AUTHOR                         \

MRB_END_DECL

#endif  /* MRUBY_VERSION_H */
