/*
*******************************************************************************
\file u16.c
\brief 16-bit unsigned words
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.10.28
\version 2015.11.17
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u16.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Преобразования
*******************************************************************************
*/

void u16Rev2(u16 buf[], size_t count)
{
	ASSERT(memIsValid(buf, count * 2));
	while (count--)
		buf[count] = u16Rev(buf[count]);
}

void u16From(u16 dest[], const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, count + count % 2));
	memMove(dest, src, count);
	if (count % 2)
		((octet*)dest)[count] = 0;
#if (OCTET_ORDER == BIG_ENDIAN)
	for (count = (count + 1) / 2; count--;)
		dest[count] = u16Rev(dest[count]);
#endif // OCTET_ORDER
}

void u16To(void* dest, size_t count, const u16 src[])
{
	ASSERT(memIsValid(src, count + count % 2));
	ASSERT(memIsValid(dest, count));
	memMove(dest, src, count);
#if (OCTET_ORDER == BIG_ENDIAN)
	if (count % 2)
	{
		register u16 u = src[--count / 2];
		((octet*)dest)[count] = (octet)u;
		u = 0;
	}
	for (count /= 2; count--;)
		((u16*)dest)[count] = u16Rev(((u16*)dest)[count]);
#endif // OCTET_ORDER
}
