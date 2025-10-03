/*
*******************************************************************************
\file u32.c
\brief 32-bit unsigned words
\project bee2 [cryptographic library]
\created 2015.10.28
\version 2025.10.03
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Использованы алгоритмы из следующих источников:
[1]	Уоррен Генри Мл. Алгоритмические трюки для программистов,
	М.: Издательский дом <<Вильямс>>, 2003.
[2]	Andersen S.A. Bit Twidding Hacks. Avail. at:
	http://graphics.stanford.edu/~seander/bithacks.html, 1997-2005.

Слово может интерпретироваться как вычет по модулю 2^32.

\remark Вторая редакция [1], дополнительные материалы:
http://www.hackersdelight.org/.
*******************************************************************************
*/

/*
*******************************************************************************
Реверс октетов
*******************************************************************************
*/

u32 u32Rev(u32 w)
{
	return w << 24 | (w & 0xFF00) << 8 | (w >> 8 & 0xFF00) | w >> 24;
}

void u32Rev2(u32 buf[], size_t count)
{
	ASSERT(memIsValid(buf, count * 4));
	while (count--)
		buf[count] = u32Rev(buf[count]);
}

/*
*******************************************************************************
Реверс битов

Реализован алгоритм, представленнный в [2] (Reverse an N-bit quantity
in parallel in 5 * lg(N) operations). Первоисточник:
* Freed, Edwin E. 1983. "Binary Magic Numbers," Dr. Dobb's Journal
  Vol. 78 (April), pp. 24-37.
*******************************************************************************
*/

u32 u32Bitrev(register u32 w)
{
	w = ((w >> 1) & 0x55555555) | ((w & 0x55555555) << 1);
	w = ((w >> 2) & 0x33333333) | ((w & 0x33333333) << 2);
	w = ((w >> 4) & 0x0F0F0F0F) | ((w & 0x0F0F0F0F) << 4);
	w = ((w >> 8) & 0x00FF00FF) | ((w & 0x00FF00FF) << 8);
	w = (w >> 16) | (w << 16);
	return w;
}

/*
*******************************************************************************
Вес

Реализованы алгоритмы из [1] (п.п. 5.1, 5.2).
*******************************************************************************
*/

size_t u32Weight(register u32 w)
{
	w -= ((w >> 1) & 0x55555555);
	w = (w & 0x33333333) + ((w >> 2) & 0x33333333);
	w = (w + (w >> 4)) & 0x0F0F0F0F;
	w += w >> 8;
	w += w >> 16;
	return (size_t)(w & 0x0000003F);
}

bool_t u32Parity(register u32 w)
{
	w ^= w >> 1;
	w ^= w >> 2;
	w ^= w >> 4;
	w ^= w >> 8;
	w ^= w >> 16;
	return (bool_t)(w & U32_1);
}

/*
*******************************************************************************
Число нулей

Реализованы алгоритмы из [1]:
-	u32CTZ_safe(): п. 5.4, второй абзац (стр. 92);
-	u32CTZ_fast(): листинг 5.13 (стр. 93);
-	u32CLZ_safe(): листинг 5.10 (стр. 89);
-	u32CLZ_fast(): листинг 5.6 (стр. 87).

\remark Приведение типа (u32)(w << 1) в последней строке FAST(u32CTZ) 
учитывает неявный integer promotion (см. zz_lcl.c) при "большом" int.
*******************************************************************************
*/

size_t u32CTZ(register u32 w)
{
	return 32 - u32Weight(w | (U32_0 - w));
}

size_t FAST(u32CTZ)(register u32 w)
{
	register u32 t;
	size_t l = 32;
	// дихотомия
	if (t = w << 16)
		l -= 16, w = t;
	if (t = w << 8)
		l -= 8, w = t;
	if (t = w << 4)
		l -= 4, w = t;
	if (t = w << 2)
		l -= 2, w = t;
	// возврат
	CLEAN(t);
	return ((u32)(w << 1)) ? l - 2 : l - (w ? 1 : 0);
}

size_t u32CLZ(register u32 w)
{
	w = w | w >> 1;
	w = w | w >> 2;
	w = w | w >> 4;
	w = w | w >> 8;
	w = w | w >> 16;
	return u32Weight(~w);
}

size_t FAST(u32CLZ)(register u32 w)
{
	register u32 t;
	size_t l = 32;
	// дихотомия
	if (t = w >> 16)
		l -= 16, w = t;
	if (t = w >> 8)
		l -= 8, w = t;
	if (t = w >> 4)
		l -= 4, w = t;
	if (t = w >> 2)
		l -= 2, w = t;
	// возврат
	CLEAN(t);
	return (w >> 1) ? l - 2 : l - (w ? 1 : 0);
}

/*
*******************************************************************************
Группировка четных и нечетных битов

Реализованы алгоритмы из [1]: п. 7.2 (с. 112).
*******************************************************************************
*/

u32 u32Shuffle(register u32 w)
{
	register u32 t;
	t = (w ^ (w >> 8)) & 0x0000FF00, w ^= t ^ (t << 8);
	t = (w ^ (w >> 4)) & 0x00F000F0, w ^= t ^ (t << 4);
	t = (w ^ (w >> 2)) & 0x0C0C0C0C, w ^= t ^ (t << 2);
	t = (w ^ (w >> 1)) & 0x22222222, w ^= t ^ (t << 1);
	CLEAN(t);
	return w;
}

u32 u32Deshuffle(register u32 w)
{
	register u32 t;
	t = (w ^ (w >> 1)) & 0x22222222, w ^= t ^ (t << 1);
	t = (w ^ (w >> 2)) & 0x0C0C0C0C, w ^= t ^ (t << 2);
	t = (w ^ (w >> 4)) & 0x00F000F0, w ^= t ^ (t << 4);
	t = (w ^ (w >> 8)) & 0x0000FF00, w ^= t ^ (t << 8);
	CLEAN(t);
	return w;
}

/*
*******************************************************************************
Аддитивно-мультипликативное обращение

Используется тот факт, что разрядность является степенью двойки: 
	32 = 2^k, k = 5. 
Корректность алгоритма, реализованного в u32NegInv(), обосновывается следующим 
образом:
	если c_i = - m^{-1} \mod 2^{2^i} и
		c_{i+1} = c_i(c_i m + 2) \mod 2^{2^{i+1}},
	то
		с_{i+1} m = c_i m (c_i m + 2) =
			(2^{2^i}r - 1)(2^{2^i}r + 1) =
			2^{2^{i+1}}r^2 - 1 =>
				c_{i+1} = m^{-1}2^{2^{i+1}}
*******************************************************************************
*/

u32 u32NegInv(register u32 w)
{
	register u32 ret = w;
	ASSERT(w & 1);
	// для t = 1,...,k: ret <- ret * (w * ret + 2)
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	CLEAN(w);
	return ret;
}

/*
*******************************************************************************
Загрузка/выгрузка
*******************************************************************************
*/

void u32From(u32 dest[], const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, ((count + 3) / 4) * 4));
	ASSERT(memIsAligned(dest, 4));
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
#if (OCTET_ORDER == BIG_ENDIAN)
 	if (count % 4)
	{
		size_t t = count / 4;
		register u32 u = src[t];
		memMove(dest, src, t *= 4);
		for (; t < count; ++t, u >>= 8)
			((octet*)dest)[t] = (octet)u;
		CLEAN(u);
		count &= ~(size_t)3;
	}
	else
		memMove(dest, src, count);
	for (; count; count -= 4)
	{
		SWAP(((octet*)dest)[count - 4], ((octet*)dest)[count - 1]);
		SWAP(((octet*)dest)[count - 3], ((octet*)dest)[count - 2]);
	}
#else
	memMove(dest, src, count);
#endif // OCTET_ORDER
}
