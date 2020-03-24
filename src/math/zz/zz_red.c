/*
*******************************************************************************
\file zz_mod.c
\brief Multiple-precision unsigned integers: modular reductions
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
Общая редукция
*******************************************************************************
*/

void zzRed(word a[], const word mod[], size_t n, void* stack)
{
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	zzMod(a, a, 2 * n, mod, n, stack);
}

size_t zzRed_deep(size_t n)
{
	return zzMod_deep(2 * n, n);
}

/*
*******************************************************************************
Редукция Крэндалла

[input]     a = a1 B^n + a0,  mod = B^n - c
[iter1]     a <- a0 + a1 c
            a <= (B^n - 1) + (B^n - 1)(B - 1) <= B^n(B - 1) => a1 < B
[iter2]     a <- a0 + a1 c
            a <= (B^n - 1) + (B - 1)c => a < 2 (B^n - c) (n >= 2)
[correct]   if (a >= B^n - c)
              a <- (a + c) \mod B^n = a - (B^n - c) \mod B^n
*******************************************************************************
*/

void FAST(zzRedCrand)(word a[], const word mod[], size_t n, void* stack)
{
	register word carry;
	register dword prod;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n >= 2 && mod[0] && wwIsRepW(mod + 1, n - 1, WORD_MAX));
	// iter1
	carry = zzAddMulW(a, a + n, n, WORD_0 - mod[0]);
	// iter2
	_MUL(prod, carry, WORD_0 - mod[0]);
	prod += a[0];
	a[0] = (word)prod;
	prod >>= B_PER_W;
	if (zzAddW2(a + 1, n - 1, (word)prod) || wwCmp(a, mod, n) >= 0)
		// correct
		zzAddW2(a, n, WORD_0 - mod[0]);
	// очистка
	prod = 0;
	carry = 0;
}

void SAFE(zzRedCrand)(word a[], const word mod[], size_t n, void* stack)
{
	register word carry;
	register dword prod;
	register word mask;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n >= 2 && mod[0] && wwIsRepW(mod + 1, n - 1, WORD_MAX));
	// iter1
	carry = zzAddMulW(a, a + n, n, WORD_0 - mod[0]);
	// iter2
	_MUL(prod, carry, WORD_0 - mod[0]);
	prod += a[0];
	a[0] = (word)prod;
	prod >>= B_PER_W;
	// add and cmp
	carry = (word)prod;
	mask = wordLeq01(mod[0], a[0]);
	for (i = 1; i < n; ++i)
	{
		a[i] += carry;
		carry = wordLess01(a[i], carry);
		// mask <-  mod[i] < a[i] | mask & mod[i] == a[i];
		mask &= wordEq01(mod[i], a[i]);
		mask |= wordLess01(mod[i], a[i]);
	}
	// correct
	mask |= carry;
	mask = WORD_0 - mask;
	mask &= (WORD_0 - mod[0]);
	zzAddW2(a, n, mask);
	// очистка
	prod = 0;
	carry = mask = 0;
}

size_t zzRedCrand_deep(size_t n)
{
	return 0;
}

/*
*******************************************************************************
Редукция Барретта

[pretime]   \mu <- B^{2n} / mod
[realtime]  q <- (a \div B^{n - 1} * \mu) \div B^{n + 1} (\approx a \div m)
            a <- a \mod B^{n + 1} - (q * mod) \mod B^{n + 1}
            if (a < 0)
              a <- a + B^n
            while (a >= mod) [не более 2 раз]
              a <- a - mod
*******************************************************************************
*/

void zzRedBarrStart(word barr_param[], const word mod[], size_t n, 
	void* stack)
{
	word* divident = (word*)stack;
	stack = divident + 2 * n + 1;
	// pre
	ASSERT(wwIsDisjoint2(barr_param, n + 2, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0);
	// divident <- B^{2n}
	wwSetZero(divident, 2 * n);
	divident[2 * n] = 1;
	// barr_param <- divident \div mod
	zzDiv(barr_param, divident, divident, 2 * n + 1, mod, n, stack);
}

size_t zzRedBarrStart_deep(size_t n)
{
	return O_OF_W(2 * n + 1) + zzDiv_deep(2 * n + 1, n);
}

void FAST(zzRedBarr)(word a[], const word mod[], size_t n, 
	const word barr_param[], void* stack)
{
	// переменные в stack
	word* q = (word*)stack;
	word* qm = q + (n + 1) + (n + 2);
	stack = qm + (n + 2) + n;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(wwIsDisjoint2(a, 2 * n, barr_param, n + 2));
	ASSERT(n > 0 && mod[n - 1] != 0);
	// q <- (a \div B^{n - 1}) * barr_param
	zzMul(q, a + n - 1, n + 1, barr_param, n + 2, stack);
	// qm <- (q \div B^{n + 1}) * mod
	zzMul(qm, q + n + 1, n + 2, mod, n, stack);
	// a <- [n + 1]a - [n + 1]qm
	zzSub2(a, qm, n + 1);
	// пока a >= mod: a <- a - mod
	while (wwCmp2(a, n + 1, mod, n) >= 0)
		a[n] -= zzSub2(a, mod, n);
}

void SAFE(zzRedBarr)(word a[], const word mod[], size_t n, 
	const word barr_param[], void* stack)
{
	register word w;
	size_t i;
	// переменные в stack
	word* q = (word*)stack;
	word* qm = q + (n + 1) + (n + 2);
	stack = qm + (n + 2) + n;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(wwIsDisjoint2(a, 2 * n, barr_param, n + 2));
	ASSERT(n > 0 && mod[n - 1] != 0);
	// q <- (a \div B^{n - 1}) * barr_param
	zzMul(q, a + n - 1, n + 1, barr_param, n + 2, stack);
	// qm <- (q \div B^{n + 1}) * mod
	zzMul(qm, q + n + 1, n + 2, mod, n, stack);
	// a <- [n + 1]a - [n + 1]qm
	zzSub2(a, qm, n + 1);
	// a >= mod? => a -= mod
	for (i = 0, w = 1; i < n; ++i)
	{
		w &= wordEq01(mod[i], a[i]);
		w |= wordLess01(mod[i], a[i]);
	}
	w |= a[n], w = WORD_0 - w;
	a[n] -= zzSubAndW(a, mod, n, w);
	// a >= mod? => a -= mod
	for (i = 0, w = 1; i < n; ++i)
	{
		w &= wordEq01(mod[i], a[i]);
		w |= wordLess01(mod[i], a[i]);
	}
	w |= a[n], w = WORD_0 - w;
	zzSubAndW(a, mod, n, w);
	// очистка
	w = 0;
}

size_t zzRedBarr_deep(size_t n)
{
	return O_OF_W(4 * n + 5) + 
		utilMax(2, 
			zzMul_deep(n + 1, n + 2), 
			zzMul_deep(n + 2, n));
}

/*
*******************************************************************************
Редукция Монтгомери

В функции zzModMont() реазизован алгоритм из работы 
[Dusse S. R., Kaliski B. S. A cryptographic library for the Motorola
DSP56000. Advances in Cryptology -- EUROCRYPT 90, LNCS 473, 230–244. 1990]:
[pretime]    m* <- -mod[0]^{-1} \bmod B
[realtime]   for (i = 0; i < n; ++i)
               t <- a[i] * m* \mod B
               a <- a + t * mod * B^i
               a <- a / B^n
             if (a >= mod)
               a <- a - mod
*******************************************************************************
*/

void FAST(zzRedMont)(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word w;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0 && mod[0] % 2);
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция в редакции Дуссе -- Калиски
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(w, a[i], mont_param);
		carry |= zzAddW2(a + i + n, n - i, zzAddMulW(a + i, mod, n, w));
	}
	ASSERT(wwIsZero(a, n));
	// a <- a / B^n
	wwCopy(a, a + n, n);
	a[n] = carry;
	// a >= mod?
	if (wwCmp2(a, n + 1, mod, n) >= 0)
		// a <- a - mod
		zzSub2(a, mod, n);
	// очистка
	carry = w = 0;
}

void SAFE(zzRedMont)(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word w = 0;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0 && mod[0] % 2);
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция в редакции Дуссе -- Калиски
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(w, a[i], mont_param);
		carry |= zzAddW2(a + i + n, n - i, zzAddMulW(a + i, mod, n, w));
	}
	ASSERT(wwIsZero(a, n));
	// a <- a / B^n, a >= mod?
	for (i = 0; i < n; ++i)
	{
		a[i] = a[n + i];
		w &= wordEq01(mod[i], a[i]);
		w |= wordLess01(mod[i], a[i]);
	}
	w |= carry, w = WORD_0 - w;
	zzSubAndW(a, mod, n, w);
	// очистка
	carry = w = 0;
}

size_t zzRedMont_deep(size_t n)
{
	return 0;
}

/*
*******************************************************************************
Редукция Крэндалла-Монтгомери

Редукция Монтгомери для модуля mod = B^n - c, 0 < c < B, n >= 2, упрощается:
[pretime]    m* <- c^{-1} \bmod B
[realtime]   carry <- 0, borrow <- 0
             for (i = 0; i < n; ++i)
               t1 <- a[i] * m* \mod B
               t2 <- t1 * c \div B
               a[i + 1] <- a[i - 1] - t2 - borrow (зафикс. новый borrow)
               a[i + n] <- a[i + n] + t1 + carry (зафикс. новый carry)
             a <- a - borrow * B^{n + 1}
             a <- a + carry * B^{n + n}
             a <- a / B^n
             if (a >= mod)
               a <- a - mod
*******************************************************************************
*/

void FAST(zzRedCrandMont)(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word borrow = 0;
	register dword prod;
	register word w;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n >= 2 && mod[0] % 2  && wwIsRepW(mod + 1, n - 1, WORD_MAX));
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(w, a[i], mont_param);
		_MUL(prod, w, WORD_0 - mod[0]);
		w += carry;
		if (w >= carry)
			a[i + n] += w, carry = a[i + n] < w;
		w = (word)(prod >> B_PER_W);
		w += borrow;
		if (w >= borrow)
			borrow = a[i + 1] < w, a[i + 1] -= w;
	}
	// a <- a - borrow * B^{n + 1}
	carry -= zzSubW2(a + n + 1, n - 1, borrow);
	// a <- a / B^n
	wwCopy(a, a + n, n);
	a[n] = carry;
	// a >= mod?
	if (wwCmp2(a, n + 1, mod, n) >= 0)
		// a <- a - mod
		zzSub2(a, mod, n);
	// очистка
	prod = 0;
	carry = borrow = w = 0;
}

void SAFE(zzRedCrandMont)(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word borrow = 0;
	register word w = 0;
	register dword prod;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n >= 2 && mod[0] % 2  && wwIsRepW(mod + 1, n - 1, WORD_MAX));
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(w, a[i], mont_param);
		_MUL(prod, w, WORD_0 - mod[0]);
		w += carry;
		carry = wordLess01(w, carry);
		a[i + n] += w;
		carry |= wordLess01(a[i + n], w); 
		w = (word)(prod >> B_PER_W);
		w += borrow;
		borrow = wordLess01(w, borrow);
		borrow |= wordLess01(a[i + 1], w);
		a[i + 1] -= w;
	}
	// a <- a - borrow * B^{n + 1}
	carry -= zzSubW2(a + n + 1, n - 1, borrow);
	// a <- a / B^n, a >= mod?
	for (i = 0; i < n; ++i)
	{
		a[i] = a[n + i];
		w &= wordEq01(mod[i], a[i]);
		w |= wordLess01(mod[i], a[i]);
	}
	w |= carry, w = WORD_0 - w;
	zzSubAndW(a, mod, n, w);
	// очистка
	prod = 0;
	carry = borrow = w = 0;
}

size_t zzRedCrandMont_deep(size_t n)
{
	return 0;
}
