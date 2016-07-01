/*
*******************************************************************************
\file zz_add.c
\brief Multiple-precision unsigned integers: additive operations
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.22
\version 2016.07.01
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Аддитивные операции

Функции zzAddW(), zzAddW2() регулярны -- сложение не прекращается, даже если 
слово переноса w становится нулевым. Для ускорения сложения (с потерей)
регулярности оператор
	for (i = 0; i < n; ++i)
следует заменить на 
	for (i = 0; w && i < n; ++i)
Аналогичное замечание касается функций zzSubW(), zzSubW2().

В функциях zzSubW(), zzSubW2() использовано тождество:
	WORD_MAX - w = 11...11 + ~w + 00...01 = ~w
Если до вычитания a -= w выполняется неравенство a < w, то результат 
вычитания имеет вид 
	a' = WORD_MAX + 1 + a - w = a + 1 + ~w => ~w < a'.
Если же до вычитания a >= w, то
	a' = a - w <= WORD_MAX - w = ~w => ~w >= a'.
Таким образом, предикат (~w < a') является новым флагом заема.
*******************************************************************************
*/

word zzAdd(word c[], const word a[], const word b[], size_t n)
{
	register word carry = 0;
	register word w;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	for (i = 0; i < n; ++i)
	{
#ifndef SAFE_FAST
		w = a[i] + carry;
		carry = wordLess01(w, carry);
		c[i] = w + b[i];
		carry |= wordLess01(c[i], w);
#else
		w = a[i] + carry;
		if (w < carry)
			c[i] = b[i];
		else
			w += b[i], carry = w < b[i], c[i] = w;
#endif
	}
	w = 0;
	return carry;
}

word zzAdd2(word b[], const word a[], size_t n)
{
	register word carry = 0;
	register word w;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
#ifndef SAFE_FAST
		w = a[i] + carry;
		carry = wordLess01(w, carry);
		b[i] += w;
		carry |= wordLess01(b[i], w);
#else
		w = a[i] + carry;
		if (w >= carry)
			w += b[i], carry = w < b[i], b[i] = w;
#endif
	}
	w = 0;
	return carry;
}

word zzAdd3(word c[], const word a[], size_t n, const word b[], size_t m)
{
	if (n > m)
	{
		wwCopy(c + m, a + m, n - m);
		return zzAddW2(c + m, n - m, zzAdd(c, a, b, m));
	}
	if (n < m)
	{
		wwCopy(c + n, b + n, m - n);
		return zzAddW2(c + n, m - n, zzAdd(c, a, b, n));
	}
	return zzAdd(c, a, b, n);
}

word zzAddW(word b[], const word a[], size_t n, register word w)
{
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
#ifndef SAFE_FAST
		b[i] = a[i] + w, w = wordLess01(b[i], w);
#else
		b[i] = a[i] + w, w = b[i] < w;
#endif
	return w;
}

word zzAddW2(word a[], size_t n, register word w)
{
	size_t i;
	ASSERT(wwIsValid(a, n));
#ifndef SAFE_FAST
	for (i = 0; i < n; ++i)
		a[i] += w, w = wordLess(a[i], w);
#else
	for (i = 0; w && i < n; ++i)
		a[i] += w, w = a[i] < w;
#endif
	return w;
}

bool_t SAFE(zzIsSumEq)(const word c[], const word a[], const word b[], 
	size_t n)
{
	register word diff = 0;
	register word carry = 0;
	register word w;
	size_t i;
	ASSERT(wwIsValid(a, n));
	ASSERT(wwIsValid(b, n));
	ASSERT(wwIsValid(c, n));
	for (i = 0; i < n; ++i)
	{
		w = a[i] + carry;
		carry = wordLess01(w, carry);
		diff |= c[i] ^ (w + b[i]);
		carry |= wordLess01(c[i], w);
	}
	w = 0;
	return wordEq(diff | carry, 0);
}

bool_t FAST(zzIsSumEq)(const word c[], const word a[], const word b[], 
	size_t n)
{
	register word carry = 0;
	register word w;
	size_t i;
	ASSERT(wwIsValid(a, n));
	ASSERT(wwIsValid(b, n));
	ASSERT(wwIsValid(c, n));
	for (i = 0; i < n; ++i)
	{
		w = a[i] + carry;
		if (w < carry)
			if (c[i] != b[i])
				return FALSE;
			else
				continue;
		if (c[i] != (word)(w + b[i]))
			return FALSE;
		carry = c[i] < w;
	}
	w = 0;
	return carry == 0;
}

bool_t SAFE(zzIsSumWEq)(const word b[], const word a[], size_t n, 
	register word w)
{
	register word diff = 0;
	size_t i;
	ASSERT(wwIsValid(a, n));
	ASSERT(wwIsValid(b, n));
	for (i = 0; i < n; ++i)
	{
		diff |= b[i] ^ (a[i] + w);
		w = wordLess01(b[i], a[i]);
	}
	return wordEq(diff | w, 0);
}

bool_t FAST(zzIsSumWEq)(const word b[], const word a[], size_t n, 
	register word w)
{
	size_t i;
	ASSERT(wwIsValid(a, n));
	ASSERT(wwIsValid(b, n));
	for (i = 0; i < n; ++i)
	{
		if (b[i] != (word)(a[i] + w))
		{
			w = 0;
			return FALSE;
		}
		w = b[i] < a[i];
	}
	return w == 0;
}

word zzSub(word c[], const word a[], const word b[], size_t n)
{
	register word borrow = 0;
	register word w;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	for (i = 0; i < n; ++i)
	{
#ifndef SAFE_FAST
		w = b[i] + borrow;
		borrow = wordLess01(w, borrow);
		borrow |= wordLess01(a[i], w);
		c[i] = a[i] - w;
#else
		w = a[i] - borrow;
		if (w > (word)~borrow)
			c[i] = ~b[i];
		else
			w -= b[i], borrow = w > (word)~b[i], c[i] = w;
#endif
	}
	w = 0;
	return borrow;
}

word zzSub2(word b[], const word a[], size_t n)
{
	register word borrow = 0;
	register word w;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
#ifndef SAFE_FAST
		w = a[i] + borrow;
		borrow = wordLess01(w, borrow);
		borrow |= wordLess01(b[i], w);
		b[i] -= w;
#else
		w = b[i] - borrow;
		if (w > (word)~borrow)
			w = ~a[i];
		else
			w -= a[i], borrow = w > (word)~a[i];
		b[i] = w;
#endif
	}
	w = 0;
	return borrow;
}

word zzSubW(word b[], const word a[], size_t n, register word w)
{
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
#ifndef SAFE_FAST
		b[i] = a[i] - w, w = wordLess01(~w, b[i]);
#else
		b[i] = a[i] - w, w = b[i] > (word)~w;
#endif
	return w;
}

word zzSubW2(word a[], size_t n, register word w)
{
	size_t i;
	ASSERT(wwIsValid(a, n));
#ifndef SAFE_FAST
	for (i = 0; i < n; ++i)
		a[i] -= w, w = wordLess01(~w, a[i]);
#else
	for (i = 0; w && i < n; ++i)
		a[i] -= w, w = a[i] > (word)~w;
#endif
	return w;
}

void zzNeg(word b[], const word a[], size_t n)
{
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
		b[i] = ~a[i];
	zzAddW2(b, n, 1);
}

