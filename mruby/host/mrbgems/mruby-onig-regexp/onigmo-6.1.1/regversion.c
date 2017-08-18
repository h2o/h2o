/**********************************************************************
  regversion.c -  Onigmo (Oniguruma-mod) (regular expression library)
**********************************************************************/
/*-
 * Copyright (c) 2002-2016  K.Kosako  <sndgk393 AT ybb DOT ne DOT jp>
 * Copyright (c) 2011-2017  K.Takata  <kentkt AT csc DOT jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "onigmo.h"

#define TOSTR_(a)	#a
#define ONIG_VERSION_TOSTR_(a,b,c)	\
	TOSTR_(a) "." TOSTR_(b) "." TOSTR_(c)
#define ONIG_VERSION_STRING	\
	ONIG_VERSION_TOSTR_(ONIGMO_VERSION_MAJOR, ONIGMO_VERSION_MINOR, ONIGMO_VERSION_TEENY)

extern const char*
onig_version(void)
{
  const char *s = ONIG_VERSION_STRING;

  return s;
}

extern const char*
onig_copyright(void)
{
  const char *s =
    "Onigmo " ONIG_VERSION_STRING " : Copyright (C) 2002-2016 K.Kosako, "
    "2011-2017 K.Takata";

  return s;
}
