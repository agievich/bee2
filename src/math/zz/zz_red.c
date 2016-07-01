/*
*******************************************************************************
\file zz_mod.c
\brief Multiple-precision unsigned integers: modular reductions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Stanislav Poruchnik [poruchnikstanislav@gmail.com]
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
#include "zz_int.h"

/*
*******************************************************************************
Специальные модули / специальные редукции

Редукция Крэндалла:
	[input]:	a = a1 B^n + a0,  mod = B^n - c
	[iter1]:	a <- a0 + a1 c
				a <= (B^n - 1) + (B^n - 1)(B - 1) <= B^n(B - 1) => a1 < B
	[iter2]:	a <- a0 + a1 c
				a <= (B^n - 1) + (B - 1)c => a < 2 (B^n - c) (n >= 2)
	[correct]:	if (a >= B^n - c)
					a <- (a + c) \mod B^n = a - (B^n - c) \mod B^n
Редукция Барретта:
	[pre]		\mu <- B^{2n} / mod
	[realtime]	q <- (a \div B^{n - 1} * \mu) \div B^{n + 1} (\approx a \div m)
				a <- a \mod B^{n + 1} - (q * mod) \mod B^{n + 1}
				if (a < 0)
					a <- a + B^n
				while (a >= mod) [не более 2 раз]
					a <- a - mod
Редукция Монтгомери (функция zzModMont(), алгоритм из работы
[Dusse S. R., Kaliski B. S. A cryptographic library for the Motorola
DSP56000. Advances in Cryptology -- EUROCRYPT 90, LNCS 473, 230–244. 1990]:
	[pre]		m* <- -mod[0]^{-1} \bmod B
	[realtime]	for (i = 0; i < n; ++i)
					t <- a[i] * m* \mod B
					a <- a + t * mod * B^i
				a <- a / B^n
				if (a >= mod)
					a <- a - mod

В алгоритме, реализованном в функции zzModMont(), на промежуточных шагах
вычислений получается число, не превосходящее 2 * mod * R. Для хранения
этого числа может потребоваться 2 * n + 1 машинных слов. Поэтому в функции
резервируется дополнительное машинное слово hi.

Редукция Монтгомери для модуля mod = B^n - c, 0 < c < B, n >= 2, упрощается:
	[pre]		m* <- c^{-1} \bmod B
	[realtime]	carry <- 0, borrow <- 0
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

void zzRed(word a[], const word mod[], size_t n, void* stack)
{
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	zzMod(a, a, 2 * n, mod, n, stack);
}

size_t zzRed_deep(size_t n)
{
	return zzMod_deep(2 * n, n);
}

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
	// todo: за 1 проход
	carry = zzAddW2(a + 1, n - 1, (word)prod);
	carry |= (word)(wwCmp(a, mod, n) >= 0);
	carry = WORD_0 - carry;
	carry &= (WORD_0 - mod[0]);
	zzAddW2(a, n, carry);
	// очистка
	prod = 0;
	carry = 0;
}

size_t zzRedCrand_deep(size_t n)
{
	return 0;
}

void zzCalcBarrParam(word barr_param[], const word mod[], size_t n, 
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

size_t zzCalcBarrParam_deep(size_t n)
{
	return O_OF_W(2 * n + 1) + zzDiv_deep(2 * n + 1, n);
}

void zzRedBarr(word a[], const word mod[], size_t n, const word barr_param[],
	void* stack)
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
	// пока a >= m: a <- a - m
	while (wwCmp2(a, n + 1, mod, n) >= 0)
		a[n] -= zzSub2(a, mod, n);
}

size_t zzRedBarr_deep(size_t n)
{
	return O_OF_W(4 * n + 5) + 
		utilMax(2, 
			zzMul_deep(n + 1, n + 2), 
			zzMul_deep(n + 2, n));
}

void FAST(zzRedMont)(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word t;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0 && mod[0] % 2);
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция в редакции Дуссе -- Калиски
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(t, a[i], mont_param);
		carry += zzAddW2(a + i + n, n - i, zzAddMulW(a + i, mod, n, t));
	}
	ASSERT(wwIsZero(a, n));
	ASSERT(carry <= 1);
	// a <- a / B^n
	wwCopy(a, a + n, n);
	a[n] = carry;
	// a >= mod?
	if (wwCmp2(a, n + 1, mod, n) >= 0)
		// a <- a - mod
		a[n] -= zzSub2(a, mod, n);
	// очистка
	carry = t = 0;
}

void SAFE(zzRedMont)(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word t;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0 && mod[0] % 2);
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция в редакции Дуссе -- Калиски
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(t, a[i], mont_param);
		carry += zzAddW2(a + i + n, n - i, zzAddMulW(a + i, mod, n, t));
	}
	ASSERT(wwIsZero(a, n));
	ASSERT(carry <= 1);
	// todo: объединить  wwCopy и wwCmp2 в один проход
	// a <- a / B^n
	wwCopy(a, a + n, n);
	a[n] = carry;
	// a >= mod?
	carry = WORD_0 - (word)(wwCmp2(a, n + 1, mod, n) >= 0);
	a[n] -= zzSubAndW(a, mod, n, carry);
	// очистка
	carry = t = 0;
}

size_t zzRedMont_deep(size_t n)
{
	return 0;
}

void FAST(zzRedCrandMont)(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word borrow = 0;
	register dword prod;
	register word t;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n >= 2 && mod[0] % 2  && wwIsRepW(mod + 1, n - 1, WORD_MAX));
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(t, a[i], mont_param);
		_MUL(prod, t, WORD_0 - mod[0]);
		t += carry;
		if (t >= carry)
			a[i + n] += t, carry = a[i + n] < t;
		t = (word)(prod >> B_PER_W);
		t += borrow;
		if (t >= borrow)
			borrow = a[i + 1] < t, a[i + 1] -= t;
	}
	// a <- a - borrow * B^{n + 1}
	carry -= zzSubW2(a + n + 1, n - 1, borrow);
	// a <- a / B^n
	wwCopy(a, a + n, n);
	a[n] = carry;
	// a >= mod?
	if (wwCmp2(a, n + 1, mod, n) >= 0)
		// a <- a - mod
		a[n] -= zzSub2(a, mod, n);
	// очистка
	prod = 0;
	carry = borrow = t = 0;
}

void SAFE(zzRedCrandMont)(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word borrow = 0;
	register dword prod;
	register word t;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n >= 2 && mod[0] % 2  && wwIsRepW(mod + 1, n - 1, WORD_MAX));
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(t, a[i], mont_param);
		_MUL(prod, t, WORD_0 - mod[0]);
		t += carry;
		carry = wordLess01(t, carry);
		a[i + n] += t;
		carry |= wordLess01(a[i + n], t); 
		t = (word)(prod >> B_PER_W);
		t += borrow;
		borrow = wordLess01(t, borrow);
		borrow |= wordLess01(a[i + 1], t);
		a[i + 1] -= t;
	}
	// a <- a - borrow * B^{n + 1}
	carry -= zzSubW2(a + n + 1, n - 1, borrow);
	// a <- a / B^n
	// todo: уменьшить число проходов: объединить wwCopy и wwCmp2
	wwCopy(a, a + n, n);
	a[n] = carry;
	// a >= mod?
	carry = WORD_0 - (word)(wwCmp2(a, n + 1, mod, n) >= 0);
	a[n] -= zzSubAndW(a, mod, n, carry);
	// очистка
	prod = 0;
	carry = borrow = t = 0;
}

size_t zzRedCrandMont_deep(size_t n)
{
	return 0;
}

