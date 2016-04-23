/*
*******************************************************************************
\file u32.c
\brief 32-bit unsigned words
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.10.28
\version 2015.11.17
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Преобразования
*******************************************************************************
*/

void u32Rev2(u32 buf[], size_t count)
{
	ASSERT(memIsValid(buf, count * 4));
	while (count--)
		buf[count] = u32Rev(buf[count]);
}

void u32From(u32 dest[], const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, ((count + 3) / 4) * 4));
	memMove(dest, src, count);
	if (count % 4)
		memSetZero((octet*)dest + count, 4 - count % 4);
#if (OCTET_ORDER == BIG_ENDIAN)
	for (count = (count + 3) / 4; count--;)
		dest[count] = u32Rev(dest[count]);
#endif // OCTET_ORDER
}

void u32To(void* dest, size_t count, const u32 src[])
{
	ASSERT(memIsValid(src, (count + 3) / 4 * 4));
	ASSERT(memIsValid(dest, count));
	memMove(dest, src, count);
#if (OCTET_ORDER == BIG_ENDIAN)
	if (count % 4)
	{
		size_t t = count / 4;
		register u32 u = src[t];
		for (t *= 4; t < count; ++t, u >>= 8)
			((octet*)dest)[t] = (octet)u;
	}
	for (count /= 4; count--;)
		((u32*)dest)[count] = u32Rev(((u32*)dest)[count]);
#endif // OCTET_ORDER
}
