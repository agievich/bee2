/*
*******************************************************************************
\file word.c
\brief Machine words
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.18
\version 2015.10.29
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/word.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Вес

Реализованы алгоритмы из [1] (п.п. 5.1, 5.2).

\todo Проверить B_PER_W \in {16, 64}.
*******************************************************************************
*/

size_t wordWeight(register word w)
{
#if (B_PER_W == 16)
	w -= ((w >> 1) & 0x5555);
	w = (w & 0x3333) + ((w >> 2) & 0x3333);
	w = (w + (w >> 4)) & 0x0F0F;
	w += w >> 8;
	return (size_t)(w & 0x001F);
#elif (B_PER_W == 32)
	w -= ((w >> 1) & 0x55555555);
	w = (w & 0x33333333) + ((w >> 2) & 0x33333333);
	w = (w + (w >> 4)) & 0x0F0F0F0F;
	w += w >> 8;
	w += w >> 16;
	return (size_t)(w & 0x0000003F);
#elif (B_PER_W == 64)
	w -= ((w >> 1) & 0x5555555555555555);
	w = (w & 0x3333333333333333) + ((w >> 2) & 0x3333333333333333);
	w = (w + (w >> 4)) & 0x0F0F0F0F0F0F0F0F;
	w += w >> 8;
	w += w >> 16;
	w += w >> 32;
	return (size_t)(w & 0x000000000000007F);
#else 
	#error "Unsupported word size"
#endif 
}

bool_t wordParity(register word w)
{
	w ^= w >> 1;
	w ^= w >> 2;
	w ^= w >> 4;
	w ^= w >> 8;
#if (B_PER_W == 32)
	w ^= w >> 16;
#elif (B_PER_W == 64)
	w ^= w >> 16;
	w ^= w >> 32;
#endif
	return (bool_t)(w & WORD_1);
}

/*
*******************************************************************************
Число нулей

Реализованы алгоритмы из [1]:
-	wordCTZ_safe(): п. 5.4, второй абзац (стр. 92);
-	wordCTZ_fast(): листинг 5.13 (стр. 93);
-	wordCLZ_safe(): листинг 5.10 (стр. 89);
-	wordCLZ_fast(): листинг 5.6 (стр. 87).
*******************************************************************************
*/

size_t SAFE(wordCTZ)(register word w)
{
	return B_PER_W - wordWeight(w | (WORD_0 - w));
}

size_t FAST(wordCTZ)(register word w)
{
	register size_t l = B_PER_W;
	register word t;
	// дихотомия
#if (B_PER_W == 64)
	if (t = w << 32)
		l -= 32, w = t;
#endif 
#if (B_PER_W >= 32)
	if (t = w << 16)
		l -= 16, w = t;
#endif 
	if (t = w << 8)
		l -= 8, w = t;
	if (t = w << 4)
		l -= 4, w = t;
	if (t = w << 2)
		l -= 2, w = t;
	// возврат
	t = 0;
	return (w << 1) ? l - 2 : l - (w ? 1 : 0);
}

size_t SAFE(wordCLZ)(register word w)
{
	w = w | w >> 1;
	w = w | w >> 2;
	w = w | w >> 4;
	w = w | w >> 8;
#if (B_PER_W >= 32)
	w = w | w >> 16;
#endif 
#if (B_PER_W == 64)
	w = w | w >> 32;
#endif 
	return wordWeight(~w);
}

size_t FAST(wordCLZ)(register word w)
{
	register size_t l = B_PER_W;
	register word t;
	// дихотомия
#if (B_PER_W == 64)
	if (t = w >> 32)
		l -= 32, w = t;
#endif 
#if (B_PER_W >= 32)
	if (t = w >> 16)
		l -= 16, w = t;
#endif 
	if (t = w >> 8)
		l -= 8, w = t;
	if (t = w >> 4)
		l -= 4, w = t;
	if (t = w >> 2)
		l -= 2, w = t;
	// возврат
	t = 0;
	return (w >> 1) ? l - 2 : l - (w ? 1 : 0);
}

/*
*******************************************************************************
Аддитивно-мультипликативное обращение

Используется то факт, что B_PER_W = 2^k, где k = 4, 5 или 6. Корректность 
алгоритма, реализованного в wordNegInv(),
обосновывается следующим образом: 
	если c_t = - m^{-1} \mod 2^{2^t} и 
		c_{t+1} = c_t(c_t m + 2) \mod 2^{2^{t+1}},
	то
		с_{t+1} m = c_t m (c_t m + 2) = 
			(2^{2^t}r - 1)(2^{2^t}r + 1) =
			2^{2^{t+1}}r^2 - 1 => 
				c_{t+1} = m^{-1}2^{2^{t+1}}
*******************************************************************************
*/

word wordNegInv(register word w)
{
	register word ret = w;
	ASSERT(w & 1);
	// для t = 1,...,k: ret <- ret * (w * ret + 2)
#if (B_PER_W >= 16)
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
	ret = ret * (w * ret + 2);
#endif
#if (B_PER_W >= 32)
	ret = ret * (w * ret + 2);
#endif
#if (B_PER_W == 64)
	ret = ret * (w * ret + 2);
#endif
	w = 0;
	return ret;
}

