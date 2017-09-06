/*
** mruby/version.h - mruby version definition
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
#define MRUBY_RUBY_VERSION "1.9"

/*
 * Ruby engine.
 */
#define MRUBY_RUBY_ENGINE  "mruby"

/*
 * Major release version number.
 */
#define MRUBY_RELEASE_MAJOR 1

/*
 * Minor release version number.
 */
#define MRUBY_RELEASE_MINOR 3

/*
 * Tiny release version number.
 */
#define MRUBY_RELEASE_TEENY 0

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
#define MRUBY_RELEASE_YEAR 2017

/*
 * Release month.
 */
#define MRUBY_RELEASE_MONTH 7

/*
 * Release day.
 */
#define MRUBY_RELEASE_DAY 4

/*
 * Release date as a string.
 */
#define MRUBY_RELEASE_DATE MRB_STRINGIZE(MRUBY_RELEASE_YEAR) "-" MRB_STRINGIZE(MRUBY_RELEASE_MONTH) "-" MRB_STRINGIZE(MRUBY_RELEASE_DAY)

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
#define MRUBY_DESCRIPTION      \
  "mruby " MRUBY_VERSION       \
  " (" MRUBY_RELEASE_DATE ") " \

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
