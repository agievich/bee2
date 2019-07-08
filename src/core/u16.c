/*
*******************************************************************************
\file u16.c
\brief 16-bit unsigned words
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.10.28
\version 2019.07.08
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u16.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Операции

Реализованные алгоритмы прокомментированы в u32.c.
*******************************************************************************
*/

u16 u16Rev(u16 w)
{
	return w << 8 | w >> 8;
}

void u16Rev2(u16 buf[], size_t count)
{
	ASSERT(memIsValid(buf, count * 2));
	while (count--)
		buf[count] = u16Rev(buf[count]);
}

size_t u16Weight(register u16 w)
{
	w -= ((w >> 1) & 0x5555);
	w = (w & 0x3333) + ((w >> 2) & 0x3333);
	w = (w + (w >> 4)) & 0x0F0F;
	w += w >> 8;
	return (size_t)(w & 0x001F);
}

bool_t u16Parity(register u16 w)
{
	w ^= w >> 1;
	w ^= w >> 2;
	w ^= w >> 4;
	w ^= w >> 8;
	return (bool_t)(w & U16_1);
}

size_t SAFE(u16CTZ)(register u16 w)
{
	return 16 - u16Weight(w | (U16_0 - w));
}

size_t FAST(u16CTZ)(register u16 w)
{
	register size_t l = 16;
	register u16 t;
	if (t = w << 8)
		l -= 8, w = t;
	if (t = w << 4)
		l -= 4, w = t;
	if (t = w << 2)
		l -= 2, w = t;
	t = 0;
	return ((u16)(w << 1)) ? l - 2 : l - (w ? 1 : 0);
}

size_t SAFE(u16CLZ)(register u16 w)
{
	w = w | w >> 1;
	w = w | w >> 2;
	w = w | w >> 4;
	w = w | w >> 8;
	return u16Weight(~w);
}

size_t FAST(u16CLZ)(register u16 w)
{
	register size_t l = 16;
	register u16 t;
	if (t = w >> 8)
		l -= 8, w = t;
	if (t = w >> 4)
		l -= 4, w = t;
	if (t = w >> 2)
		l -= 2, w = t;
	t = 0;
	return (w >> 1) ? l - 2 : l - (w ? 1 : 0);
}

u16 u16Shuffle(register u16 w)
{
	register u16 t;
	t = (w ^ (w >> 4)) & 0x00F0, w ^= t ^ (t << 4);
	t = (w ^ (w >> 2)) & 0x0C0C, w ^= t ^ (t << 2);
	t = (w ^ (w >> 1)) & 0x2222, w ^= t ^ (t << 1);
	t = 0;
	return w;
}

u16 u16Deshuffle(register u16 w)
{
	register u16 t;
	t = (w ^ (w >> 1)) & 0x2222, w ^= t ^ (t << 1);
	t = (w ^ (w >> 2)) & 0x0C0C, w ^= t ^ (t << 2);
	t = (w ^ (w >> 4)) & 0x00F0, w ^= t ^ (t << 4);
	t = 0;
	return w;
}

u16 u16NegInv(register u16 w)
{
	register u16 ret = w;
	ASSERT(w & 1);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	w = 0;
	return ret;
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
