/*
** mrdbconf.h - mruby debugger configuration
**
*/

#ifndef MRDBCONF_H
#define MRDBCONF_H

#ifndef MRB_USE_DEBUG_HOOK
# error mruby-bin-debugger need 'MRB_USE_DEBUG_HOOK' in your build configuration
#endif

#ifdef MRB_NO_STDIO
# error mruby-bin-debugger conflicts 'MRB_NO_STDIO' in your build configuration
#endif

/* configuration options: */
/* maximum size for command buffer */
#define MAX_COMMAND_LINE 1024

/* maximum number of setable breakpoint */
#define MAX_BREAKPOINT 5

#endif
