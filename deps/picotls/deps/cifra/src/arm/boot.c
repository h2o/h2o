#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int main(void);

/* --- Defined by link script --- */
extern uint32_t __etext; /* End of text/start of data. */
extern uint32_t __data_start__, __data_end__; /* Data addresses in RAM */
extern uint32_t __bss_start__, __bss_end__; /* BSS addresses in RAM */
extern uint32_t __StackTop; /* End of stack in RAM */

#define ATTR_SECTION(sec) __attribute__ ((section (sec)))

/* --- Interrupt vector table. --- */
void Reset_Handler(void);
void SysTick_Handler(void);
void infinite_loop(void);
void do_nothing(void);

typedef void (*vector_fn)(void);

typedef struct {
  uint32_t *stack_top;
  vector_fn reset, nmi, hard_fault, mmu_fault, bus_fault, usage_fault;
  vector_fn reserved0[4];
  vector_fn svc, debug_monitor;
  vector_fn reserved1;
  vector_fn pendsv, systick;
  vector_fn irq[128];
} vectors_t;

#define COPY2(v) v, v
#define COPY4(v) COPY2(v), COPY2(v)
#define COPY8(v) COPY4(v), COPY4(v)
#define COPY16(v) COPY8(v), COPY8(v)
#define COPY32(v) COPY16(v), COPY16(v)
#define COPY64(v) COPY32(v), COPY32(v)
#define COPY128(v) COPY64(v), COPY64(v)

vectors_t vectors ATTR_SECTION(".isr_vector") = {
  .stack_top = &__StackTop,
  .reset = Reset_Handler,
  .nmi = do_nothing,
  .hard_fault = infinite_loop,
  .mmu_fault = infinite_loop,
  .bus_fault = infinite_loop,
  .usage_fault = infinite_loop,
  .svc = do_nothing,
  .debug_monitor = do_nothing,
  .pendsv = do_nothing,
  .systick = SysTick_Handler,
  .irq = { COPY128(do_nothing) }
};

/* --- ISRs --- */
void Reset_Handler(void)
{
  /* Copy data segment contents from flash to RAM. */
  uint32_t data_bytes = (&__data_end__ - &__data_start__) * 4;
  memcpy(&__etext, &__data_start__, data_bytes);

  /* Zero BSS. */
  uint32_t bss_bytes = (&__bss_end__ - &__bss_start__) * 4;
  memset(&__bss_start__, 0, bss_bytes);

  main();
  while (1)
    ;
}

void __assert_func(const char *file, int line, const char *func, const char *expr)
{
  while (1)
    ;
}

void infinite_loop(void)
{
  while (1)
    ;
}

void do_nothing(void)
{
}

uint32_t ticks = 0;

void SysTick_Handler(void)
{
  ticks++;
}

uint32_t get_ticks(void)
{
  return ticks;
}

void reset_ticks(void)
{
  ticks = 0;
}

void *memmove(void *vtarg, const void *vsrc, size_t len)
{
  if (vsrc > vtarg)
    return memcpy(vtarg, vsrc, len);
  else if (vsrc == vtarg)
    return vtarg;

  uint8_t *targ = vtarg;
  const uint8_t *src = vsrc;

  for (size_t i = len; i != 0; i++)
    targ[i - 1] = src[i - 1];
  return vtarg;
}

int memcmp(const void *va, const void *vb, size_t len)
{
  const uint8_t *a = va, *b = vb;

  for (size_t i = 0; i < len; i++)
  {
    if (a[i] != b[i])
      return a[i] < b[i] ? -1 : 1;
  }

  return 0;
}

size_t strlen(const char *c)
{
  size_t r = 0;
  while (*c++) r++;
  return r;
}

void abort(void)
{
  while (1)
    ;
}
