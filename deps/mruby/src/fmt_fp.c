#include <mruby.h>
#include <string.h>

#ifndef MRB_NO_FLOAT
/***********************************************************************

  Routine for converting a single-precision
  floating point number into a string.

  The code in this function was inspired from Fred Bayer's pdouble.c.
  Since pdouble.c was released as Public Domain, I'm releasing this
  code as public domain as well.

  Dave Hylands

  The original code can be found in https://github.com/dhylands/format-float
***********************************************************************/

/***********************************************************************

  I modified the routine for mruby:

  * support `double`
  * support `#` (alt_form) modifier

  My modifications in this file are also placed in the public domain.

  Matz (Yukihiro Matsumoto)

***********************************************************************/

#include <math.h>

#ifdef MRB_USE_FLOAT32

// 1 sign bit, 8 exponent bits, and 23 mantissa bits.
// exponent values 0 and 255 are reserved, exponent can be 1 to 254.
// exponent is stored with a bias of 127.
// The min and max floats are on the order of 1x10^37 and 1x10^-37

#define FLT_DECEXP      32
#define FLT_ROUND_TO_ONE 0.9999995F
#define FLT_MIN_BUF_SIZE 6 // -9e+99

#else

// 1 sign bit, 11 exponent bits, and 52 mantissa bits.

#define FLT_DECEXP      256
#define FLT_ROUND_TO_ONE 0.999999999995
#define FLT_MIN_BUF_SIZE  7 // -9e+199

#endif  /* MRB_USE_FLOAT32 */

static const mrb_float g_pos_pow[] = {
#ifndef MRB_USE_FLOAT32
    1e256, 1e128, 1e64,
#endif
    1e32, 1e16, 1e8, 1e4, 1e2, 1e1
};
static const mrb_float g_neg_pow[] = {
#ifndef MRB_USE_FLOAT32
    1e-256, 1e-128, 1e-64,
#endif
    1e-32, 1e-16, 1e-8, 1e-4, 1e-2, 1e-1
};

/*
 * mrb_format_float(mrb_float f, char *buf, size_t buf_size, char fmt, int prec, char sign)
 *
 * fmt: should be one of 'e', 'E', 'f', 'F', 'g', or 'G'. (|0x80 for '#')
 * prec: is the precision (as specified in printf)
 * sign: should be '\0', '+', or ' '  ('\0' is the normal one - only print
 *       a sign if ```f``` is negative. Anything else is printed as the
 *       sign character for positive numbers.
 */

int
mrb_format_float(mrb_float f, char *buf, size_t buf_size, char fmt, int prec, char sign) {
  char *s = buf;
  int buf_remaining = buf_size - 1;
  int alt_form = 0;

  if ((uint8_t)fmt & 0x80) {
    fmt &= 0x7f;  /* turn off alt_form flag */
    alt_form = 1;
  }
  if (buf_size <= FLT_MIN_BUF_SIZE) {
    // Smallest exp notion is -9e+99 (-9e+199) which is 6 (7) chars plus terminating
    // null.

    if (buf_size >= 2) {
      *s++ = '?';
    }
    if (buf_size >= 1) {
      *s++ = '\0';
    }
    return buf_size >= 2;
  }
  if (signbit(f)) {
    *s++ = '-';
    f = -f;
  } else if (sign) {
    *s++ = sign;
  }
  buf_remaining -= (s - buf); // Adjust for sign

  {
    char uc = fmt & 0x20;
    if (isinf(f)) {
      *s++ = 'I' ^ uc;
      *s++ = 'N' ^ uc;
      *s++ = 'F' ^ uc;
      goto ret;
    } else if (isnan(f)) {
      *s++ = 'N' ^ uc;
      *s++ = 'A' ^ uc;
      *s++ = 'N' ^ uc;
    ret:
      *s = '\0';
      return s - buf;
    }
  }

  if (prec < 0) {
    prec = 6;
  }
  char e_char = 'E' | (fmt & 0x20);   // e_char will match case of fmt
  fmt |= 0x20; // Force fmt to be lowercase
  char org_fmt = fmt;
  if (fmt == 'g' && prec == 0) {
    prec = 1;
  }
  int e, e1;
  int dec = 0;
  char e_sign = '\0';
  int num_digits = 0;
  const mrb_float *pos_pow = g_pos_pow;
  const mrb_float *neg_pow = g_neg_pow;

  if (f == 0.0) {
    e = 0;
    if (fmt == 'e') {
      e_sign = '+';
    } else if (fmt == 'f') {
      num_digits = prec + 1;
    }
  } else if (f < 1.0) { // f < 1.0
    char first_dig = '0';
    if (f >= FLT_ROUND_TO_ONE) {
      first_dig = '1';
    }

    // Build negative exponent
    for (e = 0, e1 = FLT_DECEXP; e1; e1 >>= 1, pos_pow++, neg_pow++) {
      if (*neg_pow > f) {
        e += e1;
        f *= *pos_pow;
      }
    }
    char e_sign_char = '-';
    if (f < 1.0) {
      if (f >= FLT_ROUND_TO_ONE) {
        f = 1.0;
        if (e == 0) {
          e_sign_char = '+';
        }
      } else {
        e++;
        f *= 10.0;
      }
    }

    // If the user specified 'g' format, and e is <= 4, then we'll switch
    // to the fixed format ('f')

    if (fmt == 'f' || (fmt == 'g' && e <= 4)) {
      fmt = 'f';
      dec = -1;
      *s++ = first_dig;

      if (org_fmt == 'g') {
        prec += (e - 1);
      }
      // truncate precision to prevent buffer overflow
      if (prec + 2 > buf_remaining) {
        prec = buf_remaining - 2;
      }
      num_digits = prec;
      if (num_digits || alt_form) {
        *s++ = '.';
        while (--e && num_digits) {
          *s++ = '0';
          num_digits--;
        }
      }
    } else {
      // For e & g formats, we'll be printing the exponent, so set the
      // sign.
      e_sign = e_sign_char;
      dec = 0;

      if (prec > (buf_remaining - FLT_MIN_BUF_SIZE)) {
        prec = buf_remaining - FLT_MIN_BUF_SIZE;
        if (fmt == 'g') {
          prec++;
        }
      }
    }
  } else {
    // Build positive exponent
    for (e = 0, e1 = FLT_DECEXP; e1; e1 >>= 1, pos_pow++, neg_pow++) {
      if (*pos_pow <= f) {
        e += e1;
        f *= *neg_pow;
      }
    }

    // If the user specified fixed format (fmt == 'f') and e makes the
    // number too big to fit into the available buffer, then we'll
    // switch to the 'e' format.

    if (fmt == 'f') {
      if (e >= buf_remaining) {
        fmt = 'e';
      } else if ((e + prec + 2) > buf_remaining) {
        prec = buf_remaining - e - 2;
        if (prec < 0) {
          // This means no decimal point, so we can add one back
          // for the decimal.
          prec++;
        }
      }
    }
    if (fmt == 'e' && prec > (buf_remaining - 6)) {
      prec = buf_remaining - 6;
    }
    // If the user specified 'g' format, and e is < prec, then we'll switch
    // to the fixed format.

    if (fmt == 'g' && e < prec) {
      fmt = 'f';
      prec -= (e + 1);
    }
    if (fmt == 'f') {
      dec = e;
      num_digits = prec + e + 1;
    } else {
      e_sign = '+';
    }
  }
  if (prec < 0) {
    // This can happen when the prec is trimmed to prevent buffer overflow
    prec = 0;
  }

  // We now have f as a floating point number between >= 1 and < 10
  // (or equal to zero), and e contains the absolute value of the power of
  // 10 exponent. and (dec + 1) == the number of dgits before the decimal.

  // For e, prec is # digits after the decimal
  // For f, prec is # digits after the decimal
  // For g, prec is the max number of significant digits
  //
  // For e & g there will be a single digit before the decimal
  // for f there will be e digits before the decimal

  if (fmt == 'e') {
    num_digits = prec + 1;
  } else if (fmt == 'g') {
    if (prec == 0) {
      prec = 1;
    }
    num_digits = prec;
  }

  // Print the digits of the mantissa
  for (int i = 0; i < num_digits; ++i, --dec) {
    int8_t d = (int8_t)((int)f)%10;
    *s++ = '0' + d;
    if (dec == 0 && (prec > 0 || alt_form)) {
      *s++ = '.';
    }
    f -= (mrb_float)d;
    f *= 10.0;
  }

  // Round
  if (f >= 5.0) {
    char *rs = s;
    rs--;
    while (1) {
      if (*rs == '.') {
        rs--;
        continue;
      }
      if (*rs < '0' || *rs > '9') {
        // + or -
        rs++; // So we sit on the digit to the right of the sign
        break;
      }
      if (*rs < '9') {
        (*rs)++;
        break;
      }
      *rs = '0';
      if (rs == buf) {
        break;
      }
      rs--;
    }
    if (*rs == '0') {
      // We need to insert a 1
      if (rs[1] == '.' && fmt != 'f') {
        // We're going to round 9.99 to 10.00
        // Move the decimal point
        rs[0] = '.';
        rs[1] = '0';
        if (e_sign == '-') {
          e--;
        } else {
          e++;
        }
      }
      s++;
      char *ss = s;
      while (ss > rs) {
        *ss = ss[-1];
        ss--;
      }
      *rs = '1';
      if (f < 1.0 && fmt == 'f') {
        // We rounded up to 1.0
        prec--;
      }
    }
  }

  if (org_fmt == 'g' && prec > 0 && !alt_form) {
    // Remove trailing zeros and a trailing decimal point
    while (s[-1] == '0') {
      s--;
    }
    if (s[-1] == '.') {
      s--;
    }
  }
  // Append the exponent
  if (e_sign) {
    *s++ = e_char;
    *s++ = e_sign;
    if (e >= 100) {
      *s++ = '0' + (e / 100);
      e %= 100;
    }
    *s++ = '0' + (e / 10);
    *s++ = '0' + (e % 10);
  }
  *s = '\0';

  return s - buf;
}
#endif
