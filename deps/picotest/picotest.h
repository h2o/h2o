#ifndef picotest_h
#define picotest_h

typedef void picotest_cb_t();

extern picotest_cb_t PICOTEST_FUNCS;

void note(const char *fmt, ...)  __attribute__((format (printf, 1, 2)));
#define ok(cond) _ok(cond, __FILE__, __LINE__)
void _ok(int cond, const char *file, int line);

#endif
