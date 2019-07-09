/*
*******************************************************************************
\file zz_mod.c
\brief Multiple-precision unsigned integers: modular arithmetic
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Stanislav Poruchnik [poruchnikstanislav@gmail.com]
\created 2012.04.22
\version 2019.06.26
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "zz_lcl.h"

/*
*******************************************************************************
Модулярная арифметика: аддитивные операции

В первом проходе функции SAFE(zzAddMod)() выполняется сложение и 
одновременно проверяется, не превосходит ли сумма модуль. Во втором проходе 
выполняется вычитание либо собственно модуля, либо нуля.

Примерно так регуляризированы и другие функции.
*******************************************************************************
*/

void FAST(zzAddMod)(word c[], const word a[], const word b[], const word mod[],
	size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	ASSERT(wwIsDisjoint(c, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmp(b, mod, n) < 0);
	if (zzAdd(c, a, b, n) || FAST(wwCmp)(c, mod, n) >= 0)
		zzSub2(c, mod, n);
}

void SAFE(zzAddMod)(word c[], const word a[], const word b[], const word mod[],
	size_t n)
{
	register word carry = 0;
	register word mask = 1;
	register word w;
	size_t i;
	// pre
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	ASSERT(wwIsDisjoint(c, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmp(b, mod, n) < 0);
	// add 	
	for (i = 0; i < n; ++i)
	{
		w = a[i] + carry;
		carry = wordLess01(w, carry);
		c[i] = w + b[i];
		carry |= wordLess01(c[i], w);
		// mask <- mod[i] < c[i] || mask && mod[i] == c[i];
		mask &= wordEq01(mod[i], c[i]);
		mask |= wordLess01(mod[i], c[i]);
	}
	// sub
	mask |= carry;
	mask = WORD_0 - mask;
	zzSubAndW(c, mod, n, mask);
	w = mask = carry = 0;
}

void FAST(zzAddWMod)(word b[], const word a[], register word w, 
	const word mod[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmpW(mod, n, w) > 0);
	// a + w >= mod => a + w - mod < mod
	if (zzAddW(b, a, n, w) || wwCmp(b, mod, n) > 0)
		zzSub2(b, mod, n);
	w = 0;
}

void SAFE(zzAddWMod)(word b[], const word a[], register word w, 
	const word mod[], size_t n)
{
	register word mask = 1;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmpW(mod, n, w) > 0);
	// add
	for (i = 0; i < n; ++i)
	{
		b[i] = a[i] + w;
		w = wordLess01(b[i], w);
		// mask <-  mod[i] < b[i] | mask & mod[i] == b[i];
		mask &= wordEq01(mod[i], b[i]);
		mask |= wordLess01(mod[i], b[i]);
	}
	// sub
	mask |= w;
	mask = WORD_0 - mask;
	zzSubAndW(b, mod, n, mask);
	mask = w = 0;
}

void FAST(zzSubMod)(word c[], const word a[], const word b[], const word mod[],
	size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	ASSERT(wwIsDisjoint(c, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmp(b, mod, n) < 0);
	// a < b => a - b + mod < mod
	if (zzSub(c, a, b, n))
		zzAdd2(c, mod, n);
}

void SAFE(zzSubMod)(word c[], const word a[], const word b[], const word mod[],
	size_t n)
{
	register word mask = 0;
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	ASSERT(wwIsDisjoint(c, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmp(b, mod, n) < 0);
	// mask <- a < b ? WORD_MAX : WORD_0
	mask = WORD_0 - zzSub(c, a, b, n);
	zzAddAndW(c, mod,  n, mask);
	mask = 0;
}

void FAST(zzSubWMod)(word b[], const word a[], register word w, 
	const word mod[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmpW(mod, n, w) > 0);
	// a < w => a - w + mod < mod
	if (zzSubW(b, a, n, w))
		zzAdd2(b, mod, n);
	w = 0;
}

void SAFE(zzSubWMod)(word b[], const word a[], register word w, 
	 const word mod[], size_t n)
{
	register word mask;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmpW(mod, n, w) > 0);
	// mask <- a < w ? WORD_MAX : WORD_0
	mask = WORD_0 - zzSubW(b, a, n, w);
	zzAddAndW(b, mod,  n, mask);
	w = mask = 0;
}

void FAST(zzNegMod)(word b[], const word a[], const word mod[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0);
	// a != 0 => b <- mod - a
	if (!wwIsZero(a, n))
		zzSub(b, mod, a, n);
	else
		wwSetZero(b, n);
}

void SAFE(zzNegMod)(word b[], const word a[], const word mod[], size_t n)
{
	register word mask;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0);
	// b <- mod - a
	zzSub(b, mod, a, n);
	// mask <- b == mod ? WORD_MAX : WORD_0
	mask = WORD_0 - (word)wwEq(b, mod, n);
	// b <- b - mod & mask
	zzSubAndW(b, mod, n, mask);
	mask = 0;
}

/*
*******************************************************************************
Модулярная арифметика: мультипликативные операции

\remark Функции zzDivMod(), zzAlmostDivMod() реализованы в zz_gcd.c.
*******************************************************************************
*/

void zzMulMod(word c[], const word a[], const word b[], const word mod[],
	size_t n, void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * n;
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwCmp(b, mod, n) < 0);
	ASSERT(wwIsValid(c, n));
	ASSERT(n > 0 && mod[n - 1] != 0);
	zzMul(prod, a, n, b, n, stack);
	zzMod(c, prod, 2 * n, mod, n, stack);
}

size_t zzMulMod_deep(size_t n)
{
	return O_OF_W(2 * n) + 
		utilMax(2, 
			zzMul_deep(n, n), 
			zzMod_deep(2 * n, n));
}

void zzSqrMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	word* sqr = (word*)stack;
	stack = sqr + 2 * n;
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwIsValid(b, n));
	ASSERT(n > 0 && mod[n - 1] != 0);
	zzSqr(sqr, a, n, stack);
	zzMod(b, sqr, 2 * n, mod, n, stack);
}

size_t zzSqrMod_deep(size_t n)
{
	return O_OF_W(2 * n) +
		utilMax(2, 
			zzSqr_deep(n), 
			zzMod_deep(2 * n, n));
}

void zzInvMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	word* divident = (word*)stack;
	stack = divident + n;
	wwSetW(divident, n, 1);
	zzDivMod(b, divident, a, mod, n, stack);
}

size_t zzInvMod_deep(size_t n)
{
	return O_OF_W(n) + zzDivMod_deep(n);
}

void FAST(zzDoubleMod)(word b[], const word a[], const word mod[], size_t n)
{
	register word carry = 0;
	register word hi;
	size_t i;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	// b <- a * 2
	for (i = 0; i < n; ++i)
		hi = a[i] >> (B_PER_W - 1),
		b[i] = a[i] << 1 | carry,
		carry = hi;
	// sub mod
	if (carry || wwCmp(b, mod, n) >= 0)
		zzSub2(b, mod, n);
	// очистка
	hi = carry = 0;
}

void SAFE(zzDoubleMod)(word b[], const word a[], const word mod[], size_t n)
{
	register word carry = 0;
	register word hi;
	register word mask = 1;
	size_t i;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	// b <- a * 2
	for (i = 0; i < n; ++i)
	{
		hi = a[i] >> (B_PER_W - 1);
		b[i] = a[i] << 1 | carry;
		carry = hi;
		// mask <- mod[i] < b[i] || mask && mod[i] == b[i];
		mask &= wordEq01(mod[i], b[i]);
		mask |= wordLess01(mod[i], b[i]);
	}
	// sub mod
	mask |= carry;
	mask = WORD_0 - mask;
	zzSubAndW(b, mod, n, mask);
	// очистка
	hi = carry = mask = 0;
}

void FAST(zzHalfMod)(word b[], const word a[], const word mod[], size_t n)
{
	register word carry = 0;
	register word lo;
	// pre
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(mod, b, n));
	ASSERT(zzIsOdd(mod, n) && mod[n - 1] != 0);
	ASSERT(wwCmp(a, mod, n) < 0);
	// a -- нечетное? => b <- (a + p) / 2
	if (zzIsOdd(a, n))
	{
		carry = zzAdd(b, a, mod, n);
		while (n--)
			lo = b[n] & WORD_1,
			b[n] = b[n] >> 1 | carry << (B_PER_W - 1),
			carry = lo;
	}
	// a -- четное? => b <- a / 2
	else
		while (n--)
			lo = a[n] & WORD_1,
			b[n] = a[n] >> 1 | carry << (B_PER_W - 1),
			carry = lo;
	// очистка
	lo = carry = 0;
}

void SAFE(zzHalfMod)(word b[], const word a[], const word mod[], size_t n)
{
	register word carry = 0;
	register word mask = 0;
	register word w;
	size_t i;
	// pre
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(mod, b, n));
	ASSERT(zzIsOdd(mod, n) && mod[n - 1] != 0);
	ASSERT(wwCmp(a, mod, n) < 0);
	// mask <- (a -- нечетное) ? WORD_MAX : WORD_0
	mask = WORD_0 - (a[0] & WORD_1);
	// b <- (a + mod & mask) / 2 [(a -- нечетное) ? (a + mod) / 2 : a / 2]
	w = mask & mod[0];
	b[0] = a[0] + w;
	carry = wordLess01(b[0], w);
	b[0] >>= 1;
	for(i = 1; i < n; ++i)
	{
		b[i] = a[i];
		b[i] += carry;
		carry = wordLess01(b[i], carry);
		w = mask & mod[i];
		b[i] += w;
		carry |= wordLess01(b[i], w);
		b[i - 1] |= (b[i] & WORD_1) << (B_PER_W - 1);
		b[i] >>= 1;
	}
	b[n - 1] |= carry << (B_PER_W - 1);
	// очистка
	carry = mask = w = 0;
}

bool_t zzRandMod(word a[], const word mod[], size_t n, gen_i rng, 
	void* rng_state)
{
	register size_t l;
	register size_t i;
	// pre
	ASSERT(wwIsDisjoint(a, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0);
	// генерировать
	l = wwBitSize(mod, n);
	i =  B_PER_IMPOSSIBLE;
	do
	{
		rng(a, O_OF_B(l), rng_state);
		wwFrom(a, a, O_OF_B(l));
		wwTrimHi(a, n, l);
	}
	while (wwCmp(a, mod, n) >= 0 && i--);
	// выход
	l = 0;
	return i != SIZE_MAX;
}

bool_t zzRandNZMod(word a[], const word mod[], size_t n, gen_i rng, 
	void* rng_state)
{
	register size_t l;
	register size_t i;
	// pre
	ASSERT(wwIsDisjoint(a, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0 && wwCmpW(mod, n, 1) > 0);
	// генерировать
	l = wwBitSize(mod, n);
	i = (l <= 16) ? 2 * B_PER_IMPOSSIBLE : B_PER_IMPOSSIBLE;
	do
	{
		rng(a, O_OF_B(l), rng_state);
		wwFrom(a, a, O_OF_B(l));
		wwTrimHi(a, n, l);
	}
	while ((wwIsZero(a, n) || wwCmp(a, mod, n) >= 0) && i--);
	// выход
	l = 0;
	return i != SIZE_MAX;
}
