/*
*******************************************************************************
\file u64.c
\brief 64-bit unsigned words
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.10.28
\version 2015.11.17
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u64.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Преобразования
*******************************************************************************
*/

void u64Rev2(u64 buf[], size_t count)
{
	ASSERT(memIsValid(buf, count * 8));
	while (count--)
		buf[count] = u64Rev(buf[count]);
}

void u64From(u64 dest[], const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, ((count + 7) / 8) * 8));
	memMove(dest, src, count);
	if (count % 8)
		memSetZero((octet*)dest + count, 8 - count % 8);
#if (OCTET_ORDER == BIG_ENDIAN)
	for (count = (count + 7) / 8; count--;)
		dest[count] = u64Rev(dest[count]);
#endif // OCTET_ORDER
}

void u64To(void* dest, size_t count, const u64 src[])
{
	ASSERT(memIsValid(src, (count + 7) / 8 * 8));
	ASSERT(memIsValid(dest, count));
	memMove(dest, src, count);
#if (OCTET_ORDER == BIG_ENDIAN)
	if (count % 8)
	{
		size_t t = count / 8;
		register u64 u = src[t];
		for (t *= 8; t < count; ++t, u >>= 8)
			((octet*)dest)[t] = (octet)u;
	}
	for (count /= 8; count--;)
		((u64*)dest)[count] = u64Rev(((u64*)dest)[count]);
#endif // OCTET_ORDER
}
