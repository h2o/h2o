/*
** mrb_sleep - sleep methods for mruby
**
** Copyright (c) mod_mruby developers 2012-
** Copyright (c) mruby developers 2018
**
** Permission is hereby granted, free of charge, to any person obtaining
** a copy of this software and associated documentation files (the
** "Software"), to deal in the Software without restriction, including
** without limitation the rights to use, copy, modify, merge, publish,
** distribute, sublicense, and/or sell copies of the Software, and to
** permit persons to whom the Software is furnished to do so, subject to
** the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
** SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
** [ MIT license: https://www.opensource.org/licenses/mit-license.php ]
*/

#include <time.h>
#ifdef _WIN32
    #include <windows.h>
    #define sleep(x) Sleep(x * 1000)
    #define usleep(x) Sleep((DWORD)(((x)<1000) ? 1 : ((x)/1000)))
#else
    #include <unistd.h>
    #include <sys/time.h>
#endif

#include "mruby.h"

/* not implemented forever sleep (called without an argument)*/
static mrb_value
mrb_f_sleep(mrb_state *mrb, mrb_value self)
{
    time_t beg = time(0);
    time_t end;
#ifndef MRB_NO_FLOAT
    mrb_float sec;

    mrb_get_args(mrb, "f", &sec);
    if (sec >= 0) {
        usleep(sec * 1000000);
    }
    else {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "time interval must not be negative");
    }
#else
    mrb_int sec;

    mrb_get_args(mrb, "i", &sec);
    if (sec >= 0) {
        sleep(sec);
    } else {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "time interval must not be negative");
    }
#endif
    end = time(0) - beg;

    return mrb_fixnum_value((mrb_int)end);
}

/* mruby special; needed for mruby without float numbers */
static mrb_value
mrb_f_usleep(mrb_state *mrb, mrb_value self)
{
    mrb_int usec;
#ifdef _WIN32
    FILETIME st_ft,ed_ft;
    unsigned __int64 st_time = 0;
    unsigned __int64 ed_time = 0;
#else
    struct timeval st_tm,ed_tm;
#endif
    time_t slp_tm;

#ifdef _WIN32
    GetSystemTimeAsFileTime(&st_ft);
#else
    gettimeofday(&st_tm, NULL);
#endif

    /* not implemented forever sleep (called without an argument)*/
    mrb_get_args(mrb, "i", &usec);

    if (usec >= 0) {
        usleep(usec);
    } else {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "time interval must not be negative integer");
    }

#ifdef _WIN32
    GetSystemTimeAsFileTime(&ed_ft);

    st_time |= st_ft.dwHighDateTime;
    st_time <<=32;
    st_time |= st_ft.dwLowDateTime;
    ed_time |= ed_ft.dwHighDateTime;
    ed_time <<=32;
    ed_time |= ed_ft.dwLowDateTime;

    slp_tm = (ed_time - st_time) / 10;
#else
    gettimeofday(&ed_tm, NULL);

    if (st_tm.tv_usec > ed_tm.tv_usec) {
        slp_tm = 1000000 + ed_tm.tv_usec - st_tm.tv_usec;
    }
    else {
        slp_tm = ed_tm.tv_usec - st_tm.tv_usec;
    }
#endif

    return mrb_fixnum_value((mrb_int)slp_tm);
}

void
mrb_mruby_sleep_gem_init(mrb_state *mrb)
{
    mrb_define_method(mrb, mrb->kernel_module, "sleep",   mrb_f_sleep,   MRB_ARGS_REQ(1));
    mrb_define_method(mrb, mrb->kernel_module, "usleep",  mrb_f_usleep,  MRB_ARGS_REQ(1));
}

void
mrb_mruby_sleep_gem_final(mrb_state *mrb)
{
}
