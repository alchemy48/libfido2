/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _COMPAT_H
#define _COMPAT_H

#if defined(HAVE_ENDIAN_H)
#include <endian.h>
#endif

#if defined(__APPLE__) && !defined(HAVE_ENDIAN_H)
#include <libkern/OSByteOrder.h>
#define be16toh(x) OSSwapBigToHostInt16((x))
#define be32toh(x) OSSwapBigToHostInt32((x))
#endif /* __APPLE__ && !HAVE_ENDIAN_H */

#if defined(_WIN32) && !defined(HAVE_ENDIAN_H)
#include <winsock2.h>
#include <sys/param.h>
#define be16toh(x) ntohs((x))
#define be32toh(x) ntohl((x))
#endif /* _WIN32 && !HAVE_ENDIAN_H */

#include <stdlib.h>

#if !defined(HAVE_RECALLOCARRAY)
void *recallocarray(void *, size_t, size_t, size_t);
#endif

#if !defined(HAVE_EXPLICIT_BZERO)
void explicit_bzero(void *, size_t);
#endif

#if !defined(HAVE_GETPAGESIZE)
int getpagesize(void);
#endif

#endif /* !_COMPAT_H */
