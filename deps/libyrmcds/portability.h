/** @file portability.h
 *
 * Private header file for OS portability.
 *
 * Some code are copied from a public domain source at:
 * https://gist.github.com/yinyin/2027912
 *
 * This is public domain, too.
 */

#pragma once

#ifndef YRMCDS_PORTABILITY_H_INCLUDED
#define YRMCDS_PORTABILITY_H_INCLUDED

#if defined(__APPLE__)
#  include <libkern/OSByteOrder.h>
#  define htobe16(x) OSSwapHostToBigInt16(x)
#  define htole16(x) OSSwapHostToLittleInt16(x)
#  define be16toh(x) OSSwapBigToHostInt16(x)
#  define le16toh(x) OSSwapLittleToHostInt16(x)
#  define htobe32(x) OSSwapHostToBigInt32(x)
#  define htole32(x) OSSwapHostToLittleInt32(x)
#  define be32toh(x) OSSwapBigToHostInt32(x)
#  define le32toh(x) OSSwapLittleToHostInt32(x)
#  define htobe64(x) OSSwapHostToBigInt64(x)
#  define htole64(x) OSSwapHostToLittleInt64(x)
#  define be64toh(x) OSSwapBigToHostInt64(x)
#  define le64toh(x) OSSwapLittleToHostInt64(x)
#elif defined(__linux__)
#  include <endian.h>
#else // *BSD
#  include <sys/endian.h>
#endif

#endif // YRMCDS_PORTABILITY_H_INCLUDED
