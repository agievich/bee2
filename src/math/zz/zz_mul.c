/*
*******************************************************************************
\file zz_mul.c
\brief Multiple-precision unsigned integers: multiplicative operations
\project bee2 [cryptographic library]
\created 2012.04.22
\version 2025.09.10
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "zz_lcl.h"

/*
*******************************************************************************
Умножение / возведение в квадрат

\todo Возведение в квадрат за один проход (?), сначала с квадратов (?).
\todo Умножение Карацубы.
*******************************************************************************
*/

word zzMulW(word b[], const word a[], size_t n, register word w)
{
	register word carry = 0;
	register dword prod;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
		zzMul11(prod, w, a[i]);
		prod += carry;
		b[i] = (word)prod;
		carry = (word)(prod >> B_PER_W);
	}
	CLEAN2(prod, w);
	return carry;
}

word zzAddMulW(word b[], const word a[], size_t n, register word w)
{
	register word carry = 0;
	register dword prod;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
		zzMul11(prod, w, a[i]);
		prod += carry;
		prod += b[i];
		b[i] = (word)prod;
		carry = (word)(prod >> B_PER_W);
	}
	CLEAN2(prod, w);
	return carry;
}

word zzSubMulW(word b[], const word a[], size_t n, register word w)
{
	register word borrow = 0;
	register dword prod;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
		zzMul11(prod, w, a[i]);
		prod = (dword)0 - prod;
		prod += b[i];
		prod -= borrow;
		b[i] = (word)prod;
		borrow = WORD_0 - (word)(prod >> B_PER_W);
	}
	CLEAN2(prod, w);
	return borrow;
}

void zzMul(word c[], const word a[], size_t n, const word b[], size_t m, 
	void* stack)
{
	register word carry = 0;
	register dword prod;
	size_t i, j;
	ASSERT(wwIsDisjoint2(a, n, c, n + m));
	ASSERT(wwIsDisjoint2(b, m, c, n + m));
	wwSetZero(c, n + m);
	for (i = 0; i < n; ++i)
	{
		for (j = 0; j < m; ++j)
		{
			zzMul11(prod, a[i], b[j]);
			prod += carry;
			prod += c[i + j];
			c[i + j] = (word)prod;
			carry = (word)(prod >> B_PER_W);
		}
		c[i + j] = carry;
		carry = 0;
	}
	CLEAN(prod);
}

size_t zzMul_deep(size_t n, size_t m)
{
	return 0;
}

void zzSqr(word b[], const word a[], size_t n, void* stack)
{
	register word carry = 0;
	register word carry1;
	register dword prod;
	size_t i, j;
	ASSERT(wwIsDisjoint2(a, n, b, n + n));
	// b <- \sum_{i < j} a_i a_j B^{i + j}
	wwSetZero(b, n + n);
	for (i = 0; i < n; ++i)
	{
		for (j = i + 1; j < n; ++j)
		{
			zzMul11(prod, a[i], a[j]);
			prod += carry;
			prod += b[i + j];
			b[i + j] = (word)prod;
			carry = (word)(prod >> B_PER_W);
		}
		b[i + j] = carry;
		carry = 0;
	}
	// b <- 2 b
	for (i = 0; i < n + n; ++i)
	{
		carry1 = b[i] >> (B_PER_W - 1);
		b[i] = (b[i] << 1) | carry;
		carry = carry1;
	}
	// b <- b + \sum_i a_i^2 B^{i + i}
	for (i = 0; i < n; ++i)
	{
		zzMul11(prod, a[i], a[i]);
		prod += carry;
		prod += b[i + i];
		b[i + i] = (word)prod;
		prod >>= B_PER_W;
		prod += b[i + i + 1];
		b[i + i + 1] = (word)prod;
		carry = (word)(prod >> B_PER_W);
	}
	CLEAN3(prod, carry, carry1);
}

size_t zzSqr_deep(size_t n)
{
	return 0;
}

/*
*******************************************************************************
Деление на машинное слово

В функции zzModW2() сначала определяется значение (b = B \mod mod):
	r = \sum_i a[i] b^i \equiv \sum_i a[i] B^i = a \mod mod,
которое затем приводится \mod mod.
Используется следующий алгоритм:
	r = (r1 r0) <- 0
	for i = n - 1,..., 0:
		r <- (r1 b + r0)b + a[i]	(*)
	while (r1 != 0)
		r <- r1 b + (r0 % mod)		(**)
	return r0 % mod
После каждой итерации (*):
	r <= (B - 1)(1 + b + b^2) <= (B - 1)(mod^2 - mod + 1)
	  <= (B - 1)(B + 1) < B^2.
По окончании первой итерации (**):
	r <= (B - 1)(mod - 1) + (mod - 1) = B(mod - 1).
По окончании второй итерации (**):
	r <= (mod - 1)(mod - 1) + (mod - 1) = mod(mod - 1) < B.
Таким образом, r \mod mod = r0 \mod mod.
*******************************************************************************
*/

word zzDivW(word q[], const word a[], size_t n, register word w)
{
	register word r = 0;
	register dword divisor;
	ASSERT(w > 0);
	ASSERT(wwIsSameOrDisjoint(a, q, n));
	while (n--)
	{
		divisor = r;
		divisor <<= B_PER_W;
		divisor |= a[n];
		q[n] = (word)(divisor / w);
		r = (word)(divisor % w);
	}
	CLEAN2(divisor, w);
	return r;
}

word zzModW(const word a[], size_t n, register word w)
{
	register word r = 0;
	register dword divisor;
	ASSERT(w > 0);
	ASSERT(wwIsValid(a, n));
	while (n--)
	{
		divisor = r;
		divisor <<= B_PER_W;
		divisor |= a[n];
		r = (word)(divisor % w);
	}
	CLEAN2(divisor, w);
	return r;
}

word zzModW2(const word a[], size_t n, register word w)
{
	register word r0 = 0;
	register dword r1 = 0;
	register word b;
	// pre
	ASSERT(w > 0);
	ASSERT(w <= WORD_MID);
	ASSERT(wwIsValid(a, n));
	// b <- B \mod mod
	b = (WORD_MAX - w + 1) % w;
	// (r1 r0) <- \sum_i a[i] b^i
	while (n--)
	{
		r1 *= b;
		r1 += r0;
		r1 *= b;
		r1 += a[n];
		r0 = (word)r1;
		r1 >>= B_PER_W;
	}
	// нормализация
#ifdef SAFE_FAST
	while (r1 != 0)
	{
		r1 *= b;
		r1 += r0 % w;
		r0 = (word)r1;
		r1 >>= B_PER_W;
	}
	r0 %= w;
#else
	r1 *= b;
	r1 += r0 % w;
	r0 = (word)r1;
	r1 >>= B_PER_W;
	r1 *= b;
	r1 += r0 % w;
	r0 = (word)r1 % w;
#endif
	// очистка и возврат
	CLEAN3(r1, b, w);
	return r0;
}

/*
*******************************************************************************
Общее деление

\todo Убрать ограничение n >= m в zzDiv().

\todo T. Jabelean. An Algorithm for exact division. J. of Symb. Computations, 
15 (2): 169-180, 1993.

\todo: В zzMod() отказаться от divident.

В функциях zzDiv(), zzMod() делимое a = a[n - 1]...a[0] и делитель
b = b[m - 1]...b[0] предварительно нормализуются:
	a = a[n]...a[0] <- a * 2^shift;
	b = b[m - 1]...b[0] <- b * 2^shift.
Здесь shift --- минимальное натуральное т.ч. старший бит b[m - 1] * 2^shift
равняется 1.

\remark Обратим внимание, что у делимого появляется дополнительный разряд a[n].
Этот разряд может быть нулевым. Например тогда, когда shift == 0.

\opt Сокращать длину a при нулевом a[n]. Экономится одно деление 2by1.

Деление выполняется по алгоритму 14.20 из [Menezes A., van Oorschot P.,
Vanstone S. Handbook of Applied Cryptography]:
	for i = n, n - 1, ...., m:
		if a[i] == b[m - 1]											(#)
			q[i - m] <- B - 1
		else
			q[i - m] <- a[i]a[i - 1] div b[m - 1]
		while (q[i - m] * b[m - 1]b[m - 2] > a[i]a[i - 1]a[i - 2])	(##)
			q[i - m]--
		a <- a - q[i - m] * b * B^{i - m}
		if (a < 0)
			a += b * B^{i - m}, q[i - m]--
	return q = q[n - m]...q[0] --- частное и a --- остаток

\opt Если известен остаток r = a[i]a[i - 1] mod b[m - 1], то (##) можно
	заменить на
		while (q[i - m] * b[m - 2] > d * B + a[i - 2])
			q[i - m]--, d += b[m - 1]
*******************************************************************************
*/

#define zzDiv_schema(n, m)\
/* divident */	O_OF_W(n + 1),\
/* divisor */	O_OF_W(m),\
/* mul */		O_OF_W(3)

void zzDiv(word q[], word r[], const word a[], size_t n, const word b[],
	size_t m, void* stack)
{
	register dword qhat;
	register size_t shift;
	register word t;
	size_t i;
	word* divident;			/* [n + 1] нормализованное делимое */
	word* divisor;			/* [m] нормализованный делитель */
	word* mul;				/* [3] вспомогательное произведение */
	// pre
	ASSERT(n >= m);
	ASSERT(wwIsValid(a, n) && wwIsValid(b, m));
	ASSERT(m > 0 && b[m - 1] > 0);
	ASSERT(wwIsDisjoint2(q, n + 1 - m, r, m));
	ASSERT(a == r || wwIsDisjoint2(a, n, r, m));
	// a < b?
	if (wwCmp2(a, n, b, m) < 0)
	{
		// q <- 0, r <- a
		wwSetZero(q, n - m + 1);
		wwCopy(r, a, m);
		return;
	}
	// делим на одноразрядное число?
	if (m == 1)
	{
		r[0] = zzDivW(q, a, n, b[0]);
		return;
	}
	// разметить стек
	memSlice(stack,
		zzDiv_schema(n, m), SIZE_MAX,
		&divident, &divisor, &mul);
	// divident <- a
	wwCopy(divident, a, n);
	divident[n] = 0;
	// divisor <- b
	wwCopy(divisor, b, m);
	// нормализация
	shift = wordCLZ(b[m - 1]);
	wwShHi(divident, n + 1, shift);
	wwShHi(divisor, m, shift);
	// цикл по разрядам делимого
	for (i = n; i >= m; --i)
	{
		// вычислить пробное частное
		if (divident[i] == divisor[m - 1])
			q[i - m] = WORD_MAX;
		else
		{
			qhat = divident[i];
			qhat <<= B_PER_W;
			qhat |= divident[i - 1];
			qhat /= divisor[m - 1];
			q[i - m] = (word)qhat;
		}
		// уточнить пробное частное
		wwCopy(mul, divisor + m - 2, 2);
		mul[2] = zzMulW(mul, mul, 2, q[i - m]);
		while (wwCmp2(mul, 3, divident + i - 2, 3) > 0)
		{
			q[i - m]--;
			mul[2] -= zzSub2(mul, divisor + m - 2, 2);
		}
		// учесть пробное частное
		t = zzSubMulW(divident + i - m, divisor, m, q[i - m]);
		divident[i] -= t;
		if (divident[i] > (word)~t)
		{
			// окончательно подправить пробное частное
			q[i - m]--;
			// корректирующее сложение
			divident[i] += zzAdd2(divident + i - m, divisor, m);
		}
	}
	// денормализация
	wwShLo(divident, n + 1, shift);
	// сохранить остаток
	wwCopy(r, divident, m);
	// очистить регистровые переменные
	CLEAN3(t, shift, qhat);
}

size_t zzDiv_deep(size_t n, size_t m)
{
	return memSliceSize(
		zzDiv_schema(n, m), SIZE_MAX);
}

#define zzMod_schema(n, m)\
/* divident */	O_OF_W(n + 1),\
/* divisor */	O_OF_W(m),\
/* mul */		O_OF_W(3)

void zzMod(word r[], const word a[], size_t n, const word b[], size_t m, 
void* stack) 
{
	register dword qhat;
	register size_t shift;
	register word t;
	size_t i;
	word* divident;		/*< [n + 1] нормализованное делимое */
	word* divisor;		/*< [m] нормализованный делитель */
	word* mul;			/*< [3] вспомогательное произведение */
	// pre
	ASSERT(wwIsValid(a, n) && wwIsValid(b, m));
	ASSERT(m > 0 && b[m - 1] > 0);
	ASSERT(a == r || wwIsDisjoint2(a, n, r, m));
	// a < b?
	if (wwCmp2(a, n, b, m) < 0)
	{
		// r <- a
		if (n < m)
			wwSetZero(r + n, m - n), m = n;
		wwCopy(r, a, m);
		return;
	}
	// делим на одноразрядное число?
	if (m == 1)
	{
		r[0] = zzModW(a, n, b[0]);
		return;
	}
	// разметить стек
	memSlice(stack,
		zzMod_schema(n, m), SIZE_MAX,
		&divident, &divisor, &mul);
	// divident <- a
	wwCopy(divident, a, n);
	divident[n] = 0;
	// divisor <- b
	wwCopy(divisor, b, m);
	// нормализация
	shift = wordCLZ(b[m - 1]);
	wwShHi(divident, n + 1, shift);
	wwShHi(divisor, m, shift);
	// цикл по разрядам делимого
	for (i = n; i >= m; --i)
	{
		// вычислить пробное частное
		if (divident[i] == divisor[m - 1])
			t = WORD_MAX;
		else
		{
			qhat = divident[i];
			qhat <<= B_PER_W;
			qhat |= divident[i - 1];
			qhat /= divisor[m - 1];
			t = (word)qhat;
		}
		// уточнить пробное частное
		wwCopy(mul, divisor + m - 2, 2);
		mul[2] = zzMulW(mul, mul, 2, t);
		while (wwCmp2(mul, 3, divident + i - 2, 3) > 0)
		{
			t--;
			mul[2] -= zzSub2(mul, divisor + m - 2, 2);
		}
		// учесть пробное частное
		t = zzSubMulW(divident + i - m, divisor, m, t);
		divident[i] -= t;
		if (divident[i] > (word)~t)
			// корректирующее сложение
			divident[i] += zzAdd2(divident + i - m, divisor, m);
	}
	// денормализация
	wwShLo(divident, n + 1, shift);
	// сохранить остаток
	wwCopy(r, divident, m);
	// очистить регистровые переменные
	CLEAN3(t, shift, qhat);
}

size_t zzMod_deep(size_t n, size_t m)
{
	return memSliceSize(
		zzMod_schema(n, m), SIZE_MAX);
}
