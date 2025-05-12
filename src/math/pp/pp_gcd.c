/*
*******************************************************************************
\file pp_gcd.c
\brief Binary polynomials: Euclidian gcd algorithms
\project bee2 [cryptographic library]
\created 2012.03.01
\version 2025.05.12
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/util.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Алгоритм Евклида

В функциях ppGCD(), ppExGCD() реализованы бинарные алгоритмы,
не требующие прямых делений.

В функции ppExGCD() пересчитываются многочлены da, db, da0, db0
такие, что
	da0 * aa + db0 * bb = u,
	da * aa + db * bb = v,
где aa = a / x^s, bb = b / x^s, s -- max целое т.ч. x^s | a и x^s | b.
Многочлены u и v поддерживают вычисление \gcd(aa, bb). Если u >= v, то u
заменяется на u + v, а если u < v, то v заменяется на v + u.
Как только u == 0 вычисления останавливаются и возвращается тройка
	(2^s * v, da, db).
В функции ppExGCD() реализован алгоритм:
	u <- aa
	da0 <- 1, db0 <- 0
	v <- bb
	da <- 0, db <- 1
	пока (u != 0)
	{
		пока (u делится на x)
			u <- u / x
			если (da0 и db0 делятся на x)
				da0 <- da0 / x, db0 <- db0 / x
			иначе
				da0 <- (da0 + bb) / x, db0 <- (db0 + aa) / x
		пока (v делится на x)
			v <- v / x
			если (da и db делятся на x)
				da <- da / x, db <- db / x
			иначе
				da <- (da + bb) / x, db <- (db + aa) / x
		если (u >= v)
			u <- u + v
			da0 <- da0 + da, db0 <- db0 + db
		иначе // u < v
			v <- v + u
			da <- da + da0, db <- db + db0
	}
*******************************************************************************
*/

void ppGCD(word d[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	register size_t s;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	// pre
	ASSERT(wwIsDisjoint2(a, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MIN2(n, m)));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// d <- 0
	wwSetZero(d, MIN2(n, m));
	// u <- a, v <- b
	wwCopy(u, a, n);
	wwCopy(v, b, m);
	// найти максимальное s т.ч. x^s | u и x^s | v
	s = utilMin(2, wwLoZeroBits(u, n), wwLoZeroBits(v, m));
	// u <- u / x^s, v <- v / x^s
	wwShLo(u, n, s);
	n = wwWordSize(u, n);
	wwShLo(v, m, s);
	m = wwWordSize(v, m);
	// итерации
	do
	{
		wwShLo(u, n, wwLoZeroBits(u, n));
		n = wwWordSize(u, n);
		wwShLo(v, m, wwLoZeroBits(v, m));
		m = wwWordSize(v, m);
		// u >= v?
		if (wwCmp2(u, n, v, m) >= 0)
			// u <- u + v
			wwXor2(u, v, m);
		else
			// v <- v + u
			wwXor2(v, u, n);
	}
	while (!wwIsZero(u, n));
	// d <- v
	wwCopy(d, v, m);
	// d <- d * x^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	s = 0;
}

size_t ppGCD_deep(size_t n, size_t m)
{
	return O_OF_W(n + m);
}

void ppExGCD(word d[], word da[], word db[], const word a[], size_t n,
	const word b[], size_t m, void* stack)
{
	register size_t s;
	size_t nu, mv;
	// переменные в stack
	word* aa = (word*)stack;
	word* bb = aa + n;
	word* u = bb + m;
	word* v = u + n;
	word* da0 = v + m;
	word* db0 = da0 + m;
	// pre
	ASSERT(wwIsDisjoint3(da, m, db, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(a, n, da, m));
	ASSERT(wwIsDisjoint2(b, m, da, m));
	ASSERT(wwIsDisjoint2(a, n, db, n));
	ASSERT(wwIsDisjoint2(b, m, db, n));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// d <- 0, da0 <- 1, db0 <- 0, da <- 0, db <- 1
	wwSetZero(d, MIN2(n, m));
	wwSetW(da0, m, 1);
	wwSetZero(db0, n);
	wwSetZero(da, m);
	wwSetW(db, n, 1);
	// найти максимальное s т.ч. 2^s | aa и 2^s | bb
	s = utilMin(2, wwLoZeroBits(a, n), wwLoZeroBits(b, m));
	// aa <- a / x^s, bb <- b / x^s
	wwCopy(aa, a, n), wwShLo(aa, n, s), n = wwWordSize(aa, n);
	wwCopy(bb, b, m), wwShLo(bb, m, s), m = wwWordSize(bb, m);
	// u <- aa, v <- bb
	wwCopy(u, aa, n);
	wwCopy(v, bb, m);
	nu = n, mv = m;
	// итерации
	do
	{
		// пока u делится на x
		for (; wwTestBit(u, 0) == 0; wwShLo(u, nu, 1))
			if (wwTestBit(da0, 0) == 0)
			{
				// da0 <- da0 / x, db0 <- db0 / x
				wwShLo(da0, m, 1);
				ASSERT(wwTestBit(db0, 0) == 0);
				wwShLo(db0, n, 1);
			}
			else
			{
				// da0 <- (da0 + bb) / x, db0 <- (db0 + aa) / x
				wwXor2(da0, bb, m), wwShLo(da0, m, 1);
				ASSERT(wwTestBit(db0, 0) == 1);
				wwXor2(db0, aa, n), wwShLo(db0, n, 1);
			}
		// пока v делится на x
		for (; wwTestBit(v, 0) == 0; wwShLo(v, mv, 1))
			if (wwTestBit(da, 0) == 0)
			{
				// da <- da / x, db <- db / x
				wwShLo(da, m, 1);
				ASSERT(wwTestBit(db, 0) == 0);
				wwShLo(db, n, 1);
			}
			else
			{
				// da <- (da + bb) / x, db <- (db + aa) / x
				wwXor2(da, bb, m), wwShLo(da, m, 1);
				ASSERT(wwTestBit(db, 0) == 1);
				wwXor2(db, aa, n), wwShLo(db, n, 1);
			}
		// нормализация
		nu = wwWordSize(u, nu);
		mv = wwWordSize(v, mv);
		// u >= v?
		if (wwCmp2(u, nu, v, mv) >= 0)
		{
			// u <- u + v, da0 <- da0 + da, db0 <- db0 + db
			wwXor2(u, v, mv);
			wwXor2(da0, da, m);
			wwXor2(db0, db, n);
		}
		else
		{
			// v <- v + u, da <- da + da0, db <- db + db0
			wwXor2(v, u, nu);
			wwXor2(da, da0, m);
			wwXor2(db, db0, n);
		}
	}
	while (!wwIsZero(u, nu));
	// d <- v
	wwCopy(d, v, m);
	// d <- d * 2^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	s = 0;
}

size_t ppExGCD_deep(size_t n, size_t m)
{
	return O_OF_W(3 * n + 3 * m);
}

