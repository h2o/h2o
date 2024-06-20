#pragma once

#ifdef LIBCAP_FOUND
#include <sys/capability.h>
#include <sys/prctl.h>
#endif
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#ifdef LIBC_HAS_BACKTRACE
#include <execinfo.h>
#endif
