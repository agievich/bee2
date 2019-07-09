/*
*******************************************************************************
\file zz_etc.c
\brief Multiple-precision unsigned integers: other functions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
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
Свойства
*******************************************************************************
*/

bool_t zzIsEven(const word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	return n == 0 || a[0] % 2 == 0;
}

bool_t zzIsOdd(const word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	return n > 0 && a[0] % 2 == 1;
}

/*
*******************************************************************************
Примитивы регуляризации

Функция zzSubAndW() вычитает из [n]b число, полученнное из [n]a логическим 
умножением разрядов на w. При w == 0 вычитается 0, при w == WORD_MAX 
вычитается a. Функция маскирует вычитание и используется для организации 
регулярных вычислений.

Функция zzAddAndW() аналогична zzSubAndW(), только вместо вычитания 
выполняется сложение.
*******************************************************************************
*/

void zzAddAndW(word b[], const word a[], size_t n, register word w)
{
	register word carry = 0;
	register word prod;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
		prod = w & a[i];
		prod += carry;
		carry = wordLess01(prod, carry);
		b[i] += prod;
		carry |= wordLess01(b[i], prod);
	}
	prod = w = carry = 0;
}

word zzSubAndW(word b[], const word a[], size_t n, register word w)
{
	register word borrow = 0;
	register word prod;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
		prod = w & a[i];
		prod += borrow;
		borrow = wordLess01(prod, borrow);
		borrow |= wordLess01(b[i], prod);
		b[i] -= prod;
	}
	prod = w = 0;
	return borrow;
}

/*
*******************************************************************************
Квадратичные вычеты

Реализован алгоритм 2.148 из [Menezes A., van Oorschot P., Vanstone S.
Handbook of Applied Cryptography] в редакции CТБ 34.101.45 (приложение Ж).

В некоторых приложениях область определения символа Якоби расширяется
до любых b по следующим правилам:
	(a / 2) = 0, если a четное,
	(a / 2) = (-1)^{(a^2 - 1) / 8}, если a нечетное.
	(a / 1) = 1,
	(1 / 0) = 1,
	(a / 0) = 0, если a != 1.
Такое расширение реализовано, например, в пакете Mathematica. Мы не 
реализовали расширение, поскольку оно не востребовано в криптографическом 
контексте и только замедляет расчеты.
*******************************************************************************
*/

int zzJacobi(const word a[], size_t n, const word b[], size_t m, void* stack)
{
	register int t = 1;
	register size_t s;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	stack = v + m;
	// pre
	ASSERT(wwIsValid(a, n));
	ASSERT(zzIsOdd(b, m));
	// v <- b
	wwCopy(v, b, m);
	m = wwWordSize(v, m);
	// u <- a \mod b
	zzMod(u, a, n, v, m, stack);
	n = wwWordSize(u, n);
	// основной цикл
	while (wwCmpW(v, m, 1) > 0)
	{
		// u == 0 => (u / v) <- 0
		if (wwIsZero(u, n))
		{
			t = 0;
			break;
		}
		// u == 1 => (u / v) <- s
		if (wwIsW(u, n, 1))
			break;
		// s <- max_{2^i | u}i
		s = wwLoZeroBits(u, n);
		// s -- нечетное, v \equiv 3, 5 \mod 8 => t <- -t
		if (s % 2 && ((v[0] & 7) == 3 || (v[0] & 7) == 5))
			t = -t;
		// u <- u / 2^s
		wwShLo(u, n, s);
		n = wwWordSize(u, n);
		// u, v \equiv 3 \mod 4 => t <- -t
		if ((u[0] & 3) == 3 && (v[0] & 3) == 3)
			t = -t;
		// v <- v \mod u
		zzMod(v, v, m, u, n, stack);
		m = wwWordSize(v, m);
		// v <-> u
		wwSwap(u, v, n);
		s = m, m = n, n = s;
	}
	// символ Якоби
	return t;
}

size_t zzJacobi_deep(size_t n, size_t m)
{
	return O_OF_W(n + m) + 
		utilMax(2, 
			zzMod_deep(n, m), 
			zzMod_deep(m, n));
}

/*
*******************************************************************************
Квадратный корень

Базовый алгоритм [Cohen, A course in Computational Algebraic Number Theory]:
	t <- произвольное целое >= \sqrt(a) // например, 2^{(len(a) + 1) / 2}
	do
		b <- t
		t <- (b + a / b) / 2 // деления нацело
	while (b > t)
	return b

Обоснование:
-#	В начале непоследней итерации 
		t >= \sqrt(a) => 
		a / b <= \sqrt(a) => 
		t уменьшается или остается прежним.
-#	Если t остается прежним (t == b), то b -- искомый корень снизу (см. Cohen).

Реализация:
-#	Если a / b >= b, то итерации будут закончены. При этом a -- полный квадрат
	только если a делится нацело на b и a / b == b.
*******************************************************************************
*/

bool_t zzSqrt(word b[], const word a[], size_t n, void* stack)
{
	register int cmp;
	size_t m = (n + 1) / 2;
	word* t = (word*)stack;
	word* r = t + m + 1;
	stack = r + m;
	// pre
	ASSERT(wwIsDisjoint2(a, n, b, m));
	// нормализовать a и обработать a == 0
	if ((n = wwWordSize(a, n)) == 0)
	{
		wwSetZero(b, m);
		return TRUE;
	}
	// t <- 2^{(len(a) + 1) / 2} - 1 (умещается в m слов)
	wwSetZero(t, m + 1);
	wwSetBit(t, (wwBitSize(a, n) + 1) / 2, 1);
	zzSubW2(t, m + 1, 1);
	ASSERT(t[m] == 0);
	// итерации
	while (1)
	{
		// b <- t
		wwCopy(b, t, m);
		m = wwWordSize(b, m);
		// t <- a / b
		zzDiv(t, r, a, n, b, m, stack);
		// частное [n - m + 1]t включает ненулевое слово t[m] => t > b
		if (n - m == m && t[m] > 0)
			return FALSE;
		// сравнить [m]b и [m]t
		cmp = wwCmp(b, t, m);
		// b == t => a -- полный квадрат <=> r == 0
		if (cmp == 0)
			return wwIsZero(r, m);
		// b < t => выход, a -- не полный квадрат
		if (cmp < 0)
			break;
		// t <- (b + t) / 2
		t[m] = zzAdd2(t, b, m);
		wwShLo(t, m + 1, 1);
		ASSERT(t[m] == 0);
	}
	return FALSE;
}

size_t zzSqrt_deep(size_t n)
{
	const size_t m = (n + 1) / 2;
	return m + 1 + m + zzDiv_deep(n, m);
}

