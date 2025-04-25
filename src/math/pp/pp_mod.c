/*
*******************************************************************************
\file pp_mod.c
\brief Binary polynomials: modular arithmetic
\project bee2 [cryptographic library]
\created 2012.03.01
\version 2025.04.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/pp.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Модулярная арифметика

В ppDivMod() реализован упрощенный вариант ppExGCD(): рассчитываются
только da0, da, причем da0 = divident (а не 1).

\todo Реализовать в ppDivMod() случай произвольного (а не только
со свободным членом) mod.

\todo Хотя в ppDivMod() есть предусловие (a, mod) = 1 может оказаться так,
что оно не будет выполнено в верхней программе. Отказаться от ASSERT в этой
ситуации (аналогично -- в zz).
*******************************************************************************
*/

void ppMulMod(word c[], const word a[], const word b[], const word mod[],
	size_t n, void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * n;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmp(b, mod, n) < 0);
	ASSERT(n > 0 && mod[n - 1] != 0);
	ASSERT(wwIsValid(c, n));
	// умножить
	ppMul(prod, a, n, b, n, stack);
	// привести по модулю
	ppMod(c, prod, 2 * n, mod, n, stack);
}

size_t ppMulMod_deep(size_t n)
{
	return O_OF_W(2 * n) +
		utilMax(2,
			ppMul_deep(n, n),
			ppMod_deep(2 * n, n));
}

void ppSqrMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	word* sqr = (word*)stack;
	stack = sqr + 2 * n;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(n > 0 && mod[n - 1] != 0);
	ASSERT(wwIsValid(b, n));
	// вычисления
	ppSqr(sqr, a, n, stack);
	ppMod(b, sqr, 2 * n, mod, n, stack);
}

size_t ppSqrMod_deep(size_t n)
{
	return O_OF_W(2 * n) +
		utilMax(2,
			ppSqr_deep(n),
			ppMod_deep(2 * n, n));
}

void ppDivMod(word b[], const word divident[], const word a[],
	const word mod[], size_t n, void* stack)
{
	size_t nu, nv;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	word* da0 = v + n;
	word* da = da0 + n;
	stack = da + n;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwCmp(divident, mod, n) < 0);
	ASSERT(n > 0 && mod[n - 1] != 0 && wwTestBit(mod, 0));
	ASSERT(wwIsValid(b, n));
	// da0 <- divident, da <- 0
	wwCopy(da0, divident, n);
	wwSetZero(da, n);
	// u <- a, v <- mod
	wwCopy(u, a, n);
	nu = wwWordSize(u, n);
	wwCopy(v, mod, n);
	nv = n;
	// итерации со следующими инвариантами:
	//	da0 * a \equiv divident * u \mod mod
	//	da * a \equiv divident * v \mod mod
	while (!wwIsZero(u, nu))
	{
		// пока u делится на x
		for (; wwTestBit(u, 0) == 0; wwShLo(u, nu, 1))
			if (wwTestBit(da0, 0) == 0)
				// da0 <- da0 / x
				wwShLo(da0, n, 1);
			else
				// da0 <- (da0 + mod) / 2
				wwXor2(da0, mod, n), wwShLo(da0, n, 1);
		// пока v делится на x
		for (; wwTestBit(v, 0) == 0; wwShLo(v, nv, 1))
			if (wwTestBit(da, 0) == 0)
				// da <- da / x
				wwShLo(da, n, 1);
			else
				// da <- (da + mod) / 2
				wwXor2(da, mod, n), wwShLo(da, n, 1);
		// нормализация
		nu = wwWordSize(u, nu);
		nv = wwWordSize(v, nv);
		// u >= v?
		if (wwCmp2(u, nu, v, nv) >= 0)
		{
			// u <- u + v, da0 <- da0 + da
			wwXor2(u, v, nv);
			wwXor2(da0, da, n);
		}
		else
		{
			// v <- v + u, da <- da + da0
			wwXor2(v, u, nu);
			wwXor2(da, da0, n);
		}
	}
	// здесь v == \gcd(a, mod)
	EXPECT(wwIsW(v, nv, 1));
	// \gcd(a, mod) == 1 ? b <- da : b <- 0
	if (wwIsW(v, nv, 1))
		wwCopy(b, da, n);
	else
		wwSetZero(b, n);
}

size_t ppDivMod_deep(size_t n)
{
	return O_OF_W(4 * n);
}

void ppInvMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	word* divident = (word*)stack;
	stack = divident + n;
	wwSetW(divident, n, 1);
	ppDivMod(b, divident, a, mod, n, stack);
}

size_t ppInvMod_deep(size_t n)
{
	return O_OF_W(n) + ppDivMod_deep(n);
}

