#include <mruby.h>
#include <mruby/numeric.h>
#include <errno.h>

/* mrb_int_read(): read mrb_int from a string (base 10 only) */
/* const char *p - string to read                            */
/* const char *e - end of string                             */
/* char **endp   - end of parsed integer                     */

/* if integer overflows, errno will be set to ERANGE         */
/* also endp will be set to NULL on overflow                 */
MRB_API mrb_int
mrb_int_read(const char *p, const char *e, char **endp)
{
  mrb_int n = 0;
  int ch;

  while ((e == NULL || p < e) && ISDIGIT(*p)) {
    ch = *p - '0';
    if (mrb_int_mul_overflow(n, 10, &n) ||
        mrb_int_add_overflow(n, ch, &n)) {
      if (endp) *endp = NULL;
      errno = ERANGE;
      return MRB_INT_MAX;
    }
    p++;
  }
  if (endp) *endp = (char*)p;
  return n;
}
