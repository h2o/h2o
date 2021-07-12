/*
** time.c - Time class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRB_WITHOUT_FLOAT
#include <math.h>
#endif

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/numeric.h>
#include <mruby/time.h>
#include <mruby/string.h>

#ifdef MRB_DISABLE_STDIO
#include <string.h>
#endif

#include <stdlib.h>

#define NDIV(x,y) (-(-((x)+1)/(y))-1)
#define TO_S_FMT "%Y-%m-%d %H:%M:%S "

#if defined(_MSC_VER) && _MSC_VER < 1800
double round(double x) {
  return floor(x + 0.5);
}
#endif

#ifndef MRB_WITHOUT_FLOAT
# if !defined(__MINGW64__) && defined(_WIN32)
#  define llround(x) round(x)
# endif
#endif

#if defined(__MINGW64__) || defined(__MINGW32__)
# include <sys/time.h>
#endif

/** Time class configuration */

/* gettimeofday(2) */
/* C99 does not have gettimeofday that is required to retrieve microseconds */
/* uncomment following macro on platforms without gettimeofday(2) */
/* #define NO_GETTIMEOFDAY */

/* gmtime(3) */
/* C99 does not have reentrant gmtime_r() so it might cause troubles under */
/* multi-threading environment.  undef following macro on platforms that */
/* does not have gmtime_r() and localtime_r(). */
/* #define NO_GMTIME_R */

#ifdef _WIN32
#ifdef _MSC_VER
/* Win32 platform do not provide gmtime_r/localtime_r; emulate them using gmtime_s/localtime_s */
#define gmtime_r(tp, tm)    ((gmtime_s((tm), (tp)) == 0) ? (tm) : NULL)
#define localtime_r(tp, tm)    ((localtime_s((tm), (tp)) == 0) ? (tm) : NULL)
#else
#define NO_GMTIME_R
#endif
#endif

/* asctime(3) */
/* mruby usually use its own implementation of struct tm to string conversion */
/* except when DISABLE_STDIO is set. In that case, it uses asctime() or asctime_r(). */
/* By default mruby tries to use asctime_r() which is reentrant. */
/* Undef following macro on platforms that does not have asctime_r(). */
/* #define NO_ASCTIME_R */

/* timegm(3) */
/* mktime() creates tm structure for localtime; timegm() is for UTC time */
/* define following macro to use probably faster timegm() on the platform */
/* #define USE_SYSTEM_TIMEGM */

/** end of Time class configuration */

#ifndef NO_GETTIMEOFDAY
# ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN  /* don't include winsock.h */
#  include <windows.h>
#  define gettimeofday my_gettimeofday

#  ifdef _MSC_VER
#    define UI64(x) x##ui64
#  else
#    define UI64(x) x##ull
#  endif

typedef long suseconds_t;

# if (!defined __MINGW64__) && (!defined __MINGW32__)
struct timeval {
  time_t tv_sec;
  suseconds_t tv_usec;
};
# endif

static int
gettimeofday(struct timeval *tv, void *tz)
{
  if (tz) {
    mrb_assert(0);  /* timezone is not supported */
  }
  if (tv) {
    union {
      FILETIME ft;
      unsigned __int64 u64;
    } t;
    GetSystemTimeAsFileTime(&t.ft);   /* 100 ns intervals since Windows epoch */
    t.u64 -= UI64(116444736000000000);  /* Unix epoch bias */
    t.u64 /= 10;                      /* to microseconds */
    tv->tv_sec = (time_t)(t.u64 / (1000 * 1000));
    tv->tv_usec = t.u64 % (1000 * 1000);
  }
  return 0;
}
# else
#  include <sys/time.h>
# endif
#endif
#ifdef NO_GMTIME_R
#define gmtime_r(t,r) gmtime(t)
#define localtime_r(t,r) localtime(t)
#endif

#ifndef USE_SYSTEM_TIMEGM
#define timegm my_timgm

static unsigned int
is_leapyear(unsigned int y)
{
  return (y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0);
}

static time_t
timegm(struct tm *tm)
{
  static const unsigned int ndays[2][12] = {
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
    {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
  };
  time_t r = 0;
  int i;
  unsigned int *nday = (unsigned int*) ndays[is_leapyear(tm->tm_year+1900)];

  static const int epoch_year = 70;
  if(tm->tm_year >= epoch_year) {
    for (i = epoch_year; i < tm->tm_year; ++i)
      r += is_leapyear(i+1900) ? 366*24*60*60 : 365*24*60*60;
  } else {
    for (i = tm->tm_year; i < epoch_year; ++i)
      r -= is_leapyear(i+1900) ? 366*24*60*60 : 365*24*60*60;
  }
  for (i = 0; i < tm->tm_mon; ++i)
    r += nday[i] * 24 * 60 * 60;
  r += (tm->tm_mday - 1) * 24 * 60 * 60;
  r += tm->tm_hour * 60 * 60;
  r += tm->tm_min * 60;
  r += tm->tm_sec;
  return r;
}
#endif

/* Since we are limited to using ISO C99, this implementation is based
* on time_t. That means the resolution of time is only precise to the
* second level. Also, there are only 2 timezones, namely UTC and LOCAL.
*/

typedef struct mrb_timezone_name {
  const char name[8];
  size_t len;
} mrb_timezone_name;

static const mrb_timezone_name timezone_names[] = {
  { "none", sizeof("none") - 1 },
  { "UTC", sizeof("UTC") - 1 },
  { "LOCAL", sizeof("LOCAL") - 1 },
};

#ifndef MRB_DISABLE_STDIO
static const char mon_names[12][4] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

static const char wday_names[7][4] = {
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
};
#endif

struct mrb_time {
  time_t              sec;
  time_t              usec;
  enum mrb_timezone   timezone;
  struct tm           datetime;
};

static const struct mrb_data_type mrb_time_type = { "Time", mrb_free };

#ifndef MRB_WITHOUT_FLOAT
void mrb_check_num_exact(mrb_state *mrb, mrb_float num);
typedef mrb_float mrb_sec;
#define mrb_sec_value(mrb, sec) mrb_float_value(mrb, sec)
#else
typedef mrb_int mrb_sec;
#define mrb_sec_value(mrb, sec) mrb_fixnum_value(sec)
#endif

#define MRB_TIME_T_UINT (~(time_t)0 > 0)
#define MRB_TIME_MIN (                                                      \
  MRB_TIME_T_UINT ? 0 :                                                     \
                    (sizeof(time_t) <= 4 ? INT32_MIN : INT64_MIN)           \
)
#define MRB_TIME_MAX (                                                      \
  MRB_TIME_T_UINT ? (sizeof(time_t) <= 4 ? UINT32_MAX : UINT64_MAX) :       \
                    (sizeof(time_t) <= 4 ? INT32_MAX : INT64_MAX)           \
)

static mrb_bool
fixable_time_t_p(time_t v)
{
  if (MRB_INT_MIN <= MRB_TIME_MIN && MRB_TIME_MAX <= MRB_INT_MAX) return TRUE;
  return FIXABLE(v);
}

static time_t
mrb_to_time_t(mrb_state *mrb, mrb_value obj, time_t *usec)
{
  time_t t;

  switch (mrb_type(obj)) {
#ifndef MRB_WITHOUT_FLOAT
    case MRB_TT_FLOAT:
      {
        mrb_float f = mrb_float(obj);

        mrb_check_num_exact(mrb, f);
        if (f >= ((mrb_float)MRB_TIME_MAX-1.0) || f < ((mrb_float)MRB_TIME_MIN+1.0)) {
          goto out_of_range;
        }

        if (usec) {
          t = (time_t)f;
          *usec = (time_t)llround((f - t) * 1.0e+6);
        }
        else {
          t = (time_t)llround(f);
        }
      }
      break;
#endif /* MRB_WITHOUT_FLOAT */
    default:
    case MRB_TT_FIXNUM:
      {
        mrb_int i = mrb_int(mrb, obj);

        if ((MRB_INT_MAX > MRB_TIME_MAX && i > 0 && i > (mrb_int)MRB_TIME_MAX) ||
            (MRB_TIME_MIN > MRB_INT_MIN && MRB_TIME_MIN > i)) {
          goto out_of_range;
        }

        t = (time_t)i;
        if (usec) { *usec = 0; }
      }
      break;
  }

  return t;

out_of_range:
  mrb_raisef(mrb, E_ARGUMENT_ERROR, "%v out of Time range", obj);

  /* not reached */
  if (usec) { *usec = 0; }
  return 0;
}

/** Updates the datetime of a mrb_time based on it's timezone and
    seconds setting. Returns self on success, NULL of failure.
    if `dealloc` is set `true`, it frees `self` on error. */
static struct mrb_time*
time_update_datetime(mrb_state *mrb, struct mrb_time *self, int dealloc)
{
  struct tm *aid;
  time_t t = self->sec;

  if (self->timezone == MRB_TIMEZONE_UTC) {
    aid = gmtime_r(&t, &self->datetime);
  }
  else {
    aid = localtime_r(&t, &self->datetime);
  }
  if (!aid) {
    mrb_sec sec = (mrb_sec)t;

    if (dealloc) mrb_free(mrb, self);
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "%v out of Time range", mrb_sec_value(mrb, sec));
    /* not reached */
    return NULL;
  }
#ifdef NO_GMTIME_R
  self->datetime = *aid; /* copy data */
#endif

  return self;
}

static mrb_value
mrb_time_wrap(mrb_state *mrb, struct RClass *tc, struct mrb_time *tm)
{
  return mrb_obj_value(Data_Wrap_Struct(mrb, tc, &mrb_time_type, tm));
}

/* Allocates a mrb_time object and initializes it. */
static struct mrb_time*
time_alloc_time(mrb_state *mrb, time_t sec, time_t usec, enum mrb_timezone timezone)
{
  struct mrb_time *tm;

  tm = (struct mrb_time *)mrb_malloc(mrb, sizeof(struct mrb_time));
  tm->sec  = sec;
  tm->usec = usec;
  if (tm->usec < 0) {
    long sec2 = (long)NDIV(tm->usec,1000000); /* negative div */
    tm->usec -= sec2 * 1000000;
    tm->sec += sec2;
  }
  else if (tm->usec >= 1000000) {
    long sec2 = (long)(tm->usec / 1000000);
    tm->usec -= sec2 * 1000000;
    tm->sec += sec2;
  }
  tm->timezone = timezone;
  time_update_datetime(mrb, tm, TRUE);

  return tm;
}

static struct mrb_time*
time_alloc(mrb_state *mrb, mrb_value sec, mrb_value usec, enum mrb_timezone timezone)
{
  time_t tsec, tusec;

  tsec = mrb_to_time_t(mrb, sec, &tusec);
  tusec += mrb_to_time_t(mrb, usec, NULL);

  return time_alloc_time(mrb, tsec, tusec, timezone);
}

static mrb_value
mrb_time_make_time(mrb_state *mrb, struct RClass *c, time_t sec, time_t usec, enum mrb_timezone timezone)
{
  return mrb_time_wrap(mrb, c, time_alloc_time(mrb, sec, usec, timezone));
}

static mrb_value
mrb_time_make(mrb_state *mrb, struct RClass *c, mrb_value sec, mrb_value usec, enum mrb_timezone timezone)
{
  return mrb_time_wrap(mrb, c, time_alloc(mrb, sec, usec, timezone));
}

static struct mrb_time*
current_mrb_time(mrb_state *mrb)
{
  struct mrb_time tmzero = {0};
  struct mrb_time *tm;
  time_t sec, usec;

#if defined(TIME_UTC) && !defined(__ANDROID__)
  {
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) == 0) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "timespec_get() failed for unknown reasons");
    }
    sec = ts.tv_sec;
    usec = ts.tv_nsec / 1000;
  }
#elif defined(NO_GETTIMEOFDAY)
  {
    static time_t last_sec = 0, last_usec = 0;

    sec = time(NULL);
    if (sec != last_sec) {
      last_sec = sec;
      last_usec = 0;
    }
    else {
      /* add 1 usec to differentiate two times */
      last_usec += 1;
    }
    usec = last_usec;
  }
#else
  {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    sec = tv.tv_sec;
    usec = tv.tv_usec;
  }
#endif
  tm = (struct mrb_time *)mrb_malloc(mrb, sizeof(*tm));
  *tm = tmzero;
  tm->sec = sec; tm->usec = usec;
  tm->timezone = MRB_TIMEZONE_LOCAL;
  time_update_datetime(mrb, tm, TRUE);

  return tm;
}

/* Allocates a new Time object with given millis value. */
static mrb_value
mrb_time_now(mrb_state *mrb, mrb_value self)
{
  return mrb_time_wrap(mrb, mrb_class_ptr(self), current_mrb_time(mrb));
}

MRB_API mrb_value
mrb_time_at(mrb_state *mrb, time_t sec, time_t usec, enum mrb_timezone zone)
{
  return mrb_time_make_time(mrb, mrb_class_get(mrb, "Time"), sec, usec, zone);
}

/* 15.2.19.6.1 */
/* Creates an instance of time at the given time in seconds, etc. */
static mrb_value
mrb_time_at_m(mrb_state *mrb, mrb_value self)
{
  mrb_value sec;
  mrb_value usec = mrb_fixnum_value(0);

  mrb_get_args(mrb, "o|o", &sec, &usec);

  return mrb_time_make(mrb, mrb_class_ptr(self), sec, usec, MRB_TIMEZONE_LOCAL);
}

static struct mrb_time*
time_mktime(mrb_state *mrb, mrb_int ayear, mrb_int amonth, mrb_int aday,
  mrb_int ahour, mrb_int amin, mrb_int asec, mrb_int ausec,
  enum mrb_timezone timezone)
{
  time_t nowsecs;
  struct tm nowtime = { 0 };

  nowtime.tm_year  = (int)ayear  - 1900;
  nowtime.tm_mon   = (int)amonth - 1;
  nowtime.tm_mday  = (int)aday;
  nowtime.tm_hour  = (int)ahour;
  nowtime.tm_min   = (int)amin;
  nowtime.tm_sec   = (int)asec;
  nowtime.tm_isdst = -1;

  if (nowtime.tm_mon  < 0 || nowtime.tm_mon  > 11
      || nowtime.tm_mday < 1 || nowtime.tm_mday > 31
      || nowtime.tm_hour < 0 || nowtime.tm_hour > 24
      || (nowtime.tm_hour == 24 && (nowtime.tm_min > 0 || nowtime.tm_sec > 0))
      || nowtime.tm_min  < 0 || nowtime.tm_min  > 59
      || nowtime.tm_sec  < 0 || nowtime.tm_sec  > 60)
    mrb_raise(mrb, E_RUNTIME_ERROR, "argument out of range");

  if (timezone == MRB_TIMEZONE_UTC) {
    nowsecs = timegm(&nowtime);
  }
  else {
    nowsecs = mktime(&nowtime);
  }
  if (nowsecs == (time_t)-1) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Not a valid time.");
  }

  return time_alloc_time(mrb, nowsecs, ausec, timezone);
}

/* 15.2.19.6.2 */
/* Creates an instance of time at the given time in UTC. */
static mrb_value
mrb_time_gm(mrb_state *mrb, mrb_value self)
{
  mrb_int ayear = 0, amonth = 1, aday = 1, ahour = 0, amin = 0, asec = 0, ausec = 0;

  mrb_get_args(mrb, "i|iiiiii",
                &ayear, &amonth, &aday, &ahour, &amin, &asec, &ausec);
  return mrb_time_wrap(mrb, mrb_class_ptr(self),
          time_mktime(mrb, ayear, amonth, aday, ahour, amin, asec, ausec, MRB_TIMEZONE_UTC));
}


/* 15.2.19.6.3 */
/* Creates an instance of time at the given time in local time zone. */
static mrb_value
mrb_time_local(mrb_state *mrb, mrb_value self)
{
  mrb_int ayear = 0, amonth = 1, aday = 1, ahour = 0, amin = 0, asec = 0, ausec = 0;

  mrb_get_args(mrb, "i|iiiiii",
                &ayear, &amonth, &aday, &ahour, &amin, &asec, &ausec);
  return mrb_time_wrap(mrb, mrb_class_ptr(self),
          time_mktime(mrb, ayear, amonth, aday, ahour, amin, asec, ausec, MRB_TIMEZONE_LOCAL));
}

static struct mrb_time*
time_get_ptr(mrb_state *mrb, mrb_value time)
{
  struct mrb_time *tm;

  tm = DATA_GET_PTR(mrb, time, &mrb_time_type, struct mrb_time);
  if (!tm) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "uninitialized time");
  }
  return tm;
}

static mrb_value
mrb_time_eq(mrb_state *mrb, mrb_value self)
{
  mrb_value other = mrb_get_arg1(mrb);
  struct mrb_time *tm1, *tm2;
  mrb_bool eq_p;

  tm1 = DATA_GET_PTR(mrb, self, &mrb_time_type, struct mrb_time);
  tm2 = DATA_CHECK_GET_PTR(mrb, other, &mrb_time_type, struct mrb_time);
  eq_p = tm1 && tm2 && tm1->sec == tm2->sec && tm1->usec == tm2->usec;

  return mrb_bool_value(eq_p);
}

static mrb_value
mrb_time_cmp(mrb_state *mrb, mrb_value self)
{
  mrb_value other = mrb_get_arg1(mrb);
  struct mrb_time *tm1, *tm2;

  tm1 = DATA_GET_PTR(mrb, self, &mrb_time_type, struct mrb_time);
  tm2 = DATA_CHECK_GET_PTR(mrb, other, &mrb_time_type, struct mrb_time);
  if (!tm1 || !tm2) return mrb_nil_value();
  if (tm1->sec > tm2->sec) {
    return mrb_fixnum_value(1);
  }
  else if (tm1->sec < tm2->sec) {
    return mrb_fixnum_value(-1);
  }
  /* tm1->sec == tm2->sec */
  if (tm1->usec > tm2->usec) {
    return mrb_fixnum_value(1);
  }
  else if (tm1->usec < tm2->usec) {
    return mrb_fixnum_value(-1);
  }
  return mrb_fixnum_value(0);
}

static mrb_value
mrb_time_plus(mrb_state *mrb, mrb_value self)
{
  mrb_value o = mrb_get_arg1(mrb);
  struct mrb_time *tm;
  time_t sec, usec;

  tm = time_get_ptr(mrb, self);
  sec = mrb_to_time_t(mrb, o, &usec);
  return mrb_time_make_time(mrb, mrb_obj_class(mrb, self), tm->sec+sec, tm->usec+usec, tm->timezone);
}

static mrb_value
mrb_time_minus(mrb_state *mrb, mrb_value self)
{
  mrb_value other = mrb_get_arg1(mrb);
  struct mrb_time *tm, *tm2;

  tm = time_get_ptr(mrb, self);
  tm2 = DATA_CHECK_GET_PTR(mrb, other, &mrb_time_type, struct mrb_time);
  if (tm2) {
#ifndef MRB_WITHOUT_FLOAT
    mrb_float f;
    f = (mrb_sec)(tm->sec - tm2->sec)
      + (mrb_sec)(tm->usec - tm2->usec) / 1.0e6;
    return mrb_float_value(mrb, f);
#else
    mrb_int f;
    f = tm->sec - tm2->sec;
    if (tm->usec < tm2->usec) f--;
    return mrb_fixnum_value(f);
#endif
  }
  else {
    time_t sec, usec;
    sec = mrb_to_time_t(mrb, other, &usec);
    return mrb_time_make_time(mrb, mrb_obj_class(mrb, self), tm->sec-sec, tm->usec-usec, tm->timezone);
  }
}

/* 15.2.19.7.30 */
/* Returns week day number of time. */
static mrb_value
mrb_time_wday(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_wday);
}

/* 15.2.19.7.31 */
/* Returns year day number of time. */
static mrb_value
mrb_time_yday(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_yday + 1);
}

/* 15.2.19.7.32 */
/* Returns year of time. */
static mrb_value
mrb_time_year(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_year + 1900);
}

/* 15.2.19.7.33 */
/* Returns name of time's timezone. */
static mrb_value
mrb_time_zone(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  if (tm->timezone <= MRB_TIMEZONE_NONE) return mrb_nil_value();
  if (tm->timezone >= MRB_TIMEZONE_LAST) return mrb_nil_value();
  return mrb_str_new_static(mrb,
                            timezone_names[tm->timezone].name,
                            timezone_names[tm->timezone].len);
}

/* 15.2.19.7.4 */
/* Returns a string that describes the time. */
static mrb_value
mrb_time_asctime(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm = time_get_ptr(mrb, self);
  struct tm *d = &tm->datetime;
  int len;

#if defined(MRB_DISABLE_STDIO)
  char *s;
# ifdef NO_ASCTIME_R
  s = asctime(d);
# else
  char buf[32];
  s = asctime_r(d, buf);
# endif
  len = strlen(s)-1;            /* truncate the last newline */
#else
  char buf[256];

  len = snprintf(buf, sizeof(buf), "%s %s %2d %02d:%02d:%02d %.4d",
    wday_names[d->tm_wday], mon_names[d->tm_mon], d->tm_mday,
    d->tm_hour, d->tm_min, d->tm_sec,
    d->tm_year + 1900);
#endif
  return mrb_str_new(mrb, buf, len);
}

/* 15.2.19.7.6 */
/* Returns the day in the month of the time. */
static mrb_value
mrb_time_day(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_mday);
}


/* 15.2.19.7.7 */
/* Returns true if daylight saving was applied for this time. */
static mrb_value
mrb_time_dst_p(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_bool_value(tm->datetime.tm_isdst);
}

/* 15.2.19.7.8 */
/* 15.2.19.7.10 */
/* Returns the Time object of the UTC(GMT) timezone. */
static mrb_value
mrb_time_getutc(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm, *tm2;

  tm = time_get_ptr(mrb, self);
  tm2 = (struct mrb_time *)mrb_malloc(mrb, sizeof(*tm));
  *tm2 = *tm;
  tm2->timezone = MRB_TIMEZONE_UTC;
  time_update_datetime(mrb, tm2, TRUE);
  return mrb_time_wrap(mrb, mrb_obj_class(mrb, self), tm2);
}

/* 15.2.19.7.9 */
/* Returns the Time object of the LOCAL timezone. */
static mrb_value
mrb_time_getlocal(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm, *tm2;

  tm = time_get_ptr(mrb, self);
  tm2 = (struct mrb_time *)mrb_malloc(mrb, sizeof(*tm));
  *tm2 = *tm;
  tm2->timezone = MRB_TIMEZONE_LOCAL;
  time_update_datetime(mrb, tm2, TRUE);
  return mrb_time_wrap(mrb, mrb_obj_class(mrb, self), tm2);
}

/* 15.2.19.7.15 */
/* Returns hour of time. */
static mrb_value
mrb_time_hour(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_hour);
}

/* 15.2.19.7.16 */
/* Initializes a time by setting the amount of milliseconds since the epoch.*/
static mrb_value
mrb_time_initialize(mrb_state *mrb, mrb_value self)
{
  mrb_int ayear = 0, amonth = 1, aday = 1, ahour = 0,
  amin = 0, asec = 0, ausec = 0;
  mrb_int n;
  struct mrb_time *tm;

  n = mrb_get_args(mrb, "|iiiiiii",
       &ayear, &amonth, &aday, &ahour, &amin, &asec, &ausec);
  tm = (struct mrb_time*)DATA_PTR(self);
  if (tm) {
    mrb_free(mrb, tm);
  }
  mrb_data_init(self, NULL, &mrb_time_type);

  if (n == 0) {
    tm = current_mrb_time(mrb);
  }
  else {
    tm = time_mktime(mrb, ayear, amonth, aday, ahour, amin, asec, ausec, MRB_TIMEZONE_LOCAL);
  }
  mrb_data_init(self, tm, &mrb_time_type);
  return self;
}

/* 15.2.19.7.17(x) */
/* Initializes a copy of this time object. */
static mrb_value
mrb_time_initialize_copy(mrb_state *mrb, mrb_value copy)
{
  mrb_value src = mrb_get_arg1(mrb);
  struct mrb_time *t1, *t2;

  if (mrb_obj_equal(mrb, copy, src)) return copy;
  if (!mrb_obj_is_instance_of(mrb, src, mrb_obj_class(mrb, copy))) {
    mrb_raise(mrb, E_TYPE_ERROR, "wrong argument class");
  }
  t1 = (struct mrb_time *)DATA_PTR(copy);
  t2 = (struct mrb_time *)DATA_PTR(src);
  if (!t2) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "uninitialized time");
  }
  if (!t1) {
    t1 = (struct mrb_time *)mrb_malloc(mrb, sizeof(struct mrb_time));
    mrb_data_init(copy, t1, &mrb_time_type);
  }
  *t1 = *t2;
  return copy;
}

/* 15.2.19.7.18 */
/* Sets the timezone attribute of the Time object to LOCAL. */
static mrb_value
mrb_time_localtime(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  tm->timezone = MRB_TIMEZONE_LOCAL;
  time_update_datetime(mrb, tm, FALSE);
  return self;
}

/* 15.2.19.7.19 */
/* Returns day of month of time. */
static mrb_value
mrb_time_mday(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_mday);
}

/* 15.2.19.7.20 */
/* Returns minutes of time. */
static mrb_value
mrb_time_min(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_min);
}

/* 15.2.19.7.21 and 15.2.19.7.22 */
/* Returns month of time. */
static mrb_value
mrb_time_mon(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_mon + 1);
}

/* 15.2.19.7.23 */
/* Returns seconds in minute of time. */
static mrb_value
mrb_time_sec(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_fixnum_value(tm->datetime.tm_sec);
}

#ifndef MRB_WITHOUT_FLOAT
/* 15.2.19.7.24 */
/* Returns a Float with the time since the epoch in seconds. */
static mrb_value
mrb_time_to_f(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_float_value(mrb, (mrb_float)tm->sec + (mrb_float)tm->usec/1.0e6);
}
#endif

/* 15.2.19.7.25 */
/* Returns an Integer with the time since the epoch in seconds. */
static mrb_value
mrb_time_to_i(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
#ifndef MRB_WITHOUT_FLOAT
  if (!fixable_time_t_p(tm->sec)) {
    return mrb_float_value(mrb, (mrb_float)tm->sec);
  }
#endif
  return mrb_fixnum_value((mrb_int)tm->sec);
}

/* 15.2.19.7.26 */
/* Returns an Integer with the time since the epoch in microseconds. */
static mrb_value
mrb_time_usec(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
#ifndef MRB_WITHOUT_FLOAT
  if (!fixable_time_t_p(tm->usec)) {
    return mrb_float_value(mrb, (mrb_float)tm->usec);
  }
#endif
  return mrb_fixnum_value((mrb_int)tm->usec);
}

/* 15.2.19.7.27 */
/* Sets the timezone attribute of the Time object to UTC. */
static mrb_value
mrb_time_utc(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  tm->timezone = MRB_TIMEZONE_UTC;
  time_update_datetime(mrb, tm, FALSE);
  return self;
}

/* 15.2.19.7.28 */
/* Returns true if this time is in the UTC timezone false if not. */
static mrb_value
mrb_time_utc_p(mrb_state *mrb, mrb_value self)
{
  struct mrb_time *tm;

  tm = time_get_ptr(mrb, self);
  return mrb_bool_value(tm->timezone == MRB_TIMEZONE_UTC);
}

static size_t
time_to_s_utc(mrb_state *mrb, struct mrb_time *tm, char *buf, size_t buf_len)
{
  return strftime(buf, buf_len, TO_S_FMT "UTC", &tm->datetime);
}

static size_t
time_to_s_local(mrb_state *mrb, struct mrb_time *tm, char *buf, size_t buf_len)
{
#if defined(_MSC_VER) && _MSC_VER < 1900 || defined(__MINGW64__) || defined(__MINGW32__)
  struct tm datetime = {0};
  time_t utc_sec = timegm(&tm->datetime);
  size_t len;
  int offset;

  if (utc_sec == (time_t)-1) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Not a valid time.");
  }
  offset = abs((int)(utc_sec - tm->sec) / 60);
  datetime.tm_year = 100;
  datetime.tm_hour = offset / 60;
  datetime.tm_min = offset % 60;
  len = strftime(buf, buf_len, TO_S_FMT, &tm->datetime);
  buf[len++] = utc_sec < tm->sec ? '-' : '+';

  return len + strftime(buf + len, buf_len - len, "%H%M", &datetime);
#else
  return strftime(buf, buf_len, TO_S_FMT "%z", &tm->datetime);
#endif
}

static mrb_value
mrb_time_to_s(mrb_state *mrb, mrb_value self)
{
  char buf[64];
  struct mrb_time *tm = time_get_ptr(mrb, self);
  mrb_bool utc = tm->timezone == MRB_TIMEZONE_UTC;
  size_t len = (utc ? time_to_s_utc : time_to_s_local)(mrb, tm, buf, sizeof(buf));
  mrb_value str = mrb_str_new(mrb, buf, len);
  RSTR_SET_ASCII_FLAG(mrb_str_ptr(str));
  return str;
}

void
mrb_mruby_time_gem_init(mrb_state* mrb)
{
  struct RClass *tc;
  /* ISO 15.2.19.2 */
  tc = mrb_define_class(mrb, "Time", mrb->object_class);
  MRB_SET_INSTANCE_TT(tc, MRB_TT_DATA);
  mrb_include_module(mrb, tc, mrb_module_get(mrb, "Comparable"));
  mrb_define_class_method(mrb, tc, "at", mrb_time_at_m, MRB_ARGS_ARG(1, 1));      /* 15.2.19.6.1 */
  mrb_define_class_method(mrb, tc, "gm", mrb_time_gm, MRB_ARGS_ARG(1,6));       /* 15.2.19.6.2 */
  mrb_define_class_method(mrb, tc, "local", mrb_time_local, MRB_ARGS_ARG(1,6)); /* 15.2.19.6.3 */
  mrb_define_class_method(mrb, tc, "mktime", mrb_time_local, MRB_ARGS_ARG(1,6));/* 15.2.19.6.4 */
  mrb_define_class_method(mrb, tc, "now", mrb_time_now, MRB_ARGS_NONE());       /* 15.2.19.6.5 */
  mrb_define_class_method(mrb, tc, "utc", mrb_time_gm, MRB_ARGS_ARG(1,6));      /* 15.2.19.6.6 */

  mrb_define_method(mrb, tc, "=="     , mrb_time_eq     , MRB_ARGS_REQ(1));
  mrb_define_method(mrb, tc, "<=>"    , mrb_time_cmp    , MRB_ARGS_REQ(1)); /* 15.2.19.7.1 */
  mrb_define_method(mrb, tc, "+"      , mrb_time_plus   , MRB_ARGS_REQ(1)); /* 15.2.19.7.2 */
  mrb_define_method(mrb, tc, "-"      , mrb_time_minus  , MRB_ARGS_REQ(1)); /* 15.2.19.7.3 */
  mrb_define_method(mrb, tc, "to_s"   , mrb_time_to_s   , MRB_ARGS_NONE());
  mrb_define_method(mrb, tc, "inspect", mrb_time_to_s   , MRB_ARGS_NONE());
  mrb_define_method(mrb, tc, "asctime", mrb_time_asctime, MRB_ARGS_NONE()); /* 15.2.19.7.4 */
  mrb_define_method(mrb, tc, "ctime"  , mrb_time_asctime, MRB_ARGS_NONE()); /* 15.2.19.7.5 */
  mrb_define_method(mrb, tc, "day"    , mrb_time_day    , MRB_ARGS_NONE()); /* 15.2.19.7.6 */
  mrb_define_method(mrb, tc, "dst?"   , mrb_time_dst_p  , MRB_ARGS_NONE()); /* 15.2.19.7.7 */
  mrb_define_method(mrb, tc, "getgm"  , mrb_time_getutc , MRB_ARGS_NONE()); /* 15.2.19.7.8 */
  mrb_define_method(mrb, tc, "getlocal",mrb_time_getlocal,MRB_ARGS_NONE()); /* 15.2.19.7.9 */
  mrb_define_method(mrb, tc, "getutc" , mrb_time_getutc , MRB_ARGS_NONE()); /* 15.2.19.7.10 */
  mrb_define_method(mrb, tc, "gmt?"   , mrb_time_utc_p  , MRB_ARGS_NONE()); /* 15.2.19.7.11 */
  mrb_define_method(mrb, tc, "gmtime" , mrb_time_utc    , MRB_ARGS_NONE()); /* 15.2.19.7.13 */
  mrb_define_method(mrb, tc, "hour"   , mrb_time_hour, MRB_ARGS_NONE());    /* 15.2.19.7.15 */
  mrb_define_method(mrb, tc, "localtime", mrb_time_localtime, MRB_ARGS_NONE()); /* 15.2.19.7.18 */
  mrb_define_method(mrb, tc, "mday"   , mrb_time_mday, MRB_ARGS_NONE());    /* 15.2.19.7.19 */
  mrb_define_method(mrb, tc, "min"    , mrb_time_min, MRB_ARGS_NONE());     /* 15.2.19.7.20 */

  mrb_define_method(mrb, tc, "mon"  , mrb_time_mon, MRB_ARGS_NONE());       /* 15.2.19.7.21 */
  mrb_define_method(mrb, tc, "month", mrb_time_mon, MRB_ARGS_NONE());       /* 15.2.19.7.22 */

  mrb_define_method(mrb, tc, "sec" , mrb_time_sec, MRB_ARGS_NONE());        /* 15.2.19.7.23 */
  mrb_define_method(mrb, tc, "to_i", mrb_time_to_i, MRB_ARGS_NONE());       /* 15.2.19.7.25 */
#ifndef MRB_WITHOUT_FLOAT
  mrb_define_method(mrb, tc, "to_f", mrb_time_to_f, MRB_ARGS_NONE());       /* 15.2.19.7.24 */
#endif
  mrb_define_method(mrb, tc, "usec", mrb_time_usec, MRB_ARGS_NONE());       /* 15.2.19.7.26 */
  mrb_define_method(mrb, tc, "utc" , mrb_time_utc, MRB_ARGS_NONE());        /* 15.2.19.7.27 */
  mrb_define_method(mrb, tc, "utc?", mrb_time_utc_p,MRB_ARGS_NONE());       /* 15.2.19.7.28 */
  mrb_define_method(mrb, tc, "wday", mrb_time_wday, MRB_ARGS_NONE());       /* 15.2.19.7.30 */
  mrb_define_method(mrb, tc, "yday", mrb_time_yday, MRB_ARGS_NONE());       /* 15.2.19.7.31 */
  mrb_define_method(mrb, tc, "year", mrb_time_year, MRB_ARGS_NONE());       /* 15.2.19.7.32 */
  mrb_define_method(mrb, tc, "zone", mrb_time_zone, MRB_ARGS_NONE());       /* 15.2.19.7.33 */

  mrb_define_method(mrb, tc, "initialize", mrb_time_initialize, MRB_ARGS_REQ(1)); /* 15.2.19.7.16 */
  mrb_define_method(mrb, tc, "initialize_copy", mrb_time_initialize_copy, MRB_ARGS_REQ(1)); /* 15.2.19.7.17 */

  /*
    methods not available:
      gmt_offset(15.2.19.7.12)
      gmtoff(15.2.19.7.14)
      utc_offset(15.2.19.7.29)
  */
}

void
mrb_mruby_time_gem_final(mrb_state* mrb)
{
}
