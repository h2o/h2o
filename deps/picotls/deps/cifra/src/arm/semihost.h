#ifndef SEMIHOST_H
#define SEMIHOST_H

#include <stdint.h>
#include <stdlib.h>

/* Exits emulator with success (or merely hangs). */
__attribute__((noreturn))
void quit_success(void);

/* Exits emulator with failure (or merely hangs). */
__attribute__((noreturn))
void quit_failure(void);

/* Writes zero terminated string to debug output */
void emit(const char *buf);

/* Writes a formatting string to debug output.
 *
 * Supported:
 * %u - uint32_t argument, same as emit_uint32
 * %s - const char * argument, same as emit
 */
void emitf(const char *fmt, ...);

/* Writes hex dump of len bytes at ptr to debug output. */
void emit_hex(const void *ptr, size_t len);

/* Writes value v in hex to debug output, in format:
 * 0xHHHHHHHH (equivalent to printf 0x%08x). */
void emit_uint32(uint32_t v);

/* Reset cycle counter to 0.  Returns the current value
 * (just after resetting it). */
uint32_t reset_cycles(void);

/* Return the value of the cycle counter. */
uint32_t get_cycles(void);

#endif
