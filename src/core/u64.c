/*
*******************************************************************************
\file u64.c
\brief 64-bit unsigned words
\project bee2 [cryptographic library]
\created 2015.10.28
\version 2025.10.03
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u64.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Операции

Реализованные алгоритмы прокомментированы в u32.c.
*******************************************************************************
*/

u64 u64Rev(u64 w)
{
	return w << 56 | (w & 0xFF00) << 40 | (w & 0xFF0000) << 24 |
		(w & 0xFF000000) << 8 | (w >> 8 & 0xFF000000) |
		(w >> 24 & 0xFF0000) | (w >> 40 & 0xFF00) | w >> 56;
}

void u64Rev2(u64 buf[], size_t count)
{
	ASSERT(memIsValid(buf, count * 8));
	while (count--)
		buf[count] = u64Rev(buf[count]);
}

u64 u64Bitrev(register u64 w)
{
	w = ((w >> 1 ) & 0x5555555555555555) | ((w & 0x5555555555555555) << 1);
	w = ((w >> 2 ) & 0x3333333333333333) | ((w & 0x3333333333333333) << 2);
	w = ((w >> 4 ) & 0x0F0F0F0F0F0F0F0F) | ((w & 0x0F0F0F0F0F0F0F0F) << 4);
	w = ((w >> 8 ) & 0x00FF00FF00FF00FF) | ((w & 0x00FF00FF00FF00FF) << 8);
	w = ((w >> 16) & 0x0000FFFF0000FFFF) | ((w & 0x0000FFFF0000FFFF) << 16);
	w = (w >> 32) | (w << 32);
	return w;
}

size_t u64Weight(register u64 w)
{
	w -= ((w >> 1) & 0x5555555555555555);
	w = (w & 0x3333333333333333) + ((w >> 2) & 0x3333333333333333);
	w = (w + (w >> 4)) & 0x0F0F0F0F0F0F0F0F;
	w += w >> 8;
	w += w >> 16;
	w += w >> 32;
	return (size_t)(w & 0x000000000000007F);
}

bool_t u64Parity(register u64 w)
{
	w ^= w >> 1;
	w ^= w >> 2;
	w ^= w >> 4;
	w ^= w >> 8;
	w ^= w >> 16;
	w ^= w >> 32;
	return (bool_t)(w & U64_1);
}

size_t u64CTZ(register u64 w)
{
	return 64 - u64Weight(w | (U64_0 - w));
}

size_t FAST(u64CTZ)(register u64 w)
{
	register u64 t;
	size_t l = 64;
	if (t = w << 32)
		l -= 32, w = t;
	if (t = w << 16)
		l -= 16, w = t;
	if (t = w << 8)
		l -= 8, w = t;
	if (t = w << 4)
		l -= 4, w = t;
	if (t = w << 2)
		l -= 2, w = t;
	CLEAN(t);
	return ((u64)(w << 1)) ? l - 2 : l - (w ? 1 : 0);
}

size_t u64CLZ(register u64 w)
{
	w = w | w >> 1;
	w = w | w >> 2;
	w = w | w >> 4;
	w = w | w >> 8;
	w = w | w >> 16;
	w = w | w >> 32;
	return u64Weight(~w);
}

size_t FAST(u64CLZ)(register u64 w)
{
	register u64 t;
	size_t l = 64;
	if (t = w >> 32)
		l -= 32, w = t;
	if (t = w >> 16)
		l -= 16, w = t;
	if (t = w >> 8)
		l -= 8, w = t;
	if (t = w >> 4)
		l -= 4, w = t;
	if (t = w >> 2)
		l -= 2, w = t;
	CLEAN(t);
	return (w >> 1) ? l - 2 : l - (w ? 1 : 0);
}

u64 u64Shuffle(register u64 w)
{
	register u64 t;
	t = (w ^ (w >> 16)) & 0x00000000FFFF0000, w ^= t ^ (t << 16);
	t = (w ^ (w >> 8)) & 0x0000FF000000FF00, w ^= t ^ (t << 8);
	t = (w ^ (w >> 4)) & 0x00F000F000F000F0, w ^= t ^ (t << 4);
	t = (w ^ (w >> 2)) & 0x0C0C0C0C0C0C0C0C, w ^= t ^ (t << 2);
	t = (w ^ (w >> 1)) & 0x2222222222222222, w ^= t ^ (t << 1);
	CLEAN(t);
	return w;
}

u64 u64Deshuffle(register u64 w)
{
	register u64 t;
	t = (w ^ (w >> 1 )) & 0x2222222222222222, w ^= t ^ (t << 1);
	t = (w ^ (w >> 2 )) & 0x0C0C0C0C0C0C0C0C, w ^= t ^ (t << 2);
	t = (w ^ (w >> 4 )) & 0x00F000F000F000F0, w ^= t ^ (t << 4);
	t = (w ^ (w >> 8 )) & 0x0000FF000000FF00, w ^= t ^ (t << 8);
	t = (w ^ (w >> 16)) & 0x00000000FFFF0000, w ^= t ^ (t << 16);
	CLEAN(t);
	return w;
}

u64 u64NegInv(register u64 w)
{
	register u64 ret = w;
	ASSERT(w & 1);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	CLEAN(w);
	return ret;
}

void u64From(u64 dest[], const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, ((count + 7) / 8) * 8));
	ASSERT(memIsAligned(dest, 8));
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
		memMove(dest, src, t *= 8);
		for (; t < count; ++t, u >>= 8)
			((octet*)dest)[t] = (octet)u;
		CLEAN(u);
		count &= ~(size_t)7;
	}
	else
		memMove(dest, src, count);
	for (; count; count -= 8)
	{
		SWAP(((octet*)dest)[count - 8], ((octet*)dest)[count - 1]);
		SWAP(((octet*)dest)[count - 7], ((octet*)dest)[count - 2]);
		SWAP(((octet*)dest)[count - 6], ((octet*)dest)[count - 3]);
		SWAP(((octet*)dest)[count - 5], ((octet*)dest)[count - 4]);
	}
#endif // OCTET_ORDER
}
