/*
*******************************************************************************
\file pp_etc.c
\brief Binary polynomials: other functions
\project bee2 [cryptographic library]
\created 2012.03.01
\version 2025.09.12
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/util.h"
#include "bee2/math/pp.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Степень
*******************************************************************************
*/

size_t ppDeg(const word a[], size_t n)
{
	return wwBitSize(a, n) - SIZE_1;
}

/*
*******************************************************************************
Неприводимость

Реализован алгоритм Бен-Ора [Ben-Or M. Probabilistic algorithms in
finite fields. In Proc. 22nd IEEE Symp. Foundations Computer Science,
1981, 394--398]. По оценкам [Gao S., Panario D. Test and Construction of
Irreducible Polynomials over Finite Fields] этот алгоритм обрабатывает
случайные многочлены значительно быстрее, чем алгоритм Рабина
[Rabin M. Probabilistic algorithms in finite fields. SIAM J. Comp. 9,
1980, 273--280].

Алгоритм Рабина (m = deg(a)):
	для (i = 1,..., m)
		если (i | m && m / i -- простое && (a, x^{2^i} - x) != 1)
			возвратить 0
	если (x^{2^m} != x \mod f)
		возвратить 0
	возвратить 1

Алгоритм Бен-Ора:
	для (i = 1,..., m div 2)
		если (a, x^{2^i} - x) != 1
			возвратить 0
	возвратить 1
*******************************************************************************
*/

#define ppIsIrred_schema(n)\
/* h */		O_OF_W(n),\
/* d */		O_OF_W(n),\
/* stack */	ppSqrMod_deep(n)

bool_t ppIsIrred(const word a[], size_t n, void* stack)
{
	size_t i;
	word* h;			/* [n] */
	word* d;			/* [n] */
	// разметить стек
	memSlice(stack,
		ppIsIrred_schema(n), SIZE_MAX,
		&h, &d, &stack);
	// нормализация (нужна для \mod a)
	n = wwWordSize(a, n);
	// постоянный многочлен не является неприводимым
	if (wwCmpW(a, n, 1) <= 0)
		return FALSE;
	// h <- x^2
	wwSetW(h, n, 4);
	// основной цикл
	for (i = ppDeg(a, n) / 2; i; --i)
	{
		// (h + x, a) == 1?
		wwFlipBit(h, 1);
		if (wwIsZero(h, n))
			return FALSE;
		ppGCD(d, h, n, a, n, stack);
		if (wwCmpW(d, n, 1) != 0)
			return FALSE;
		wwFlipBit(h, 1);
		// h <- h^2 \mod a
		if (i > 1)
			ppSqrMod(h, h, a, n, stack);
	}
	return TRUE;
}

size_t ppIsIrred_deep(size_t n)
{
	return memSliceSize(
		ppIsIrred_schema(n), SIZE_MAX);
}

/*
*******************************************************************************
Минимальные многочлены

Реализован следующий алгоритм определения минимального многочлена
последовательности:
	aa <- a
	bb <- x^{2l}
	da <- 1, db <- 0
	пока (deg(aa) >= l)
	{
		[инвариант: da * a + db * x^{2l} == aa]
		(q, r) <- (bb div aa, bb mod aa)
		(db, da) <- (da, db + q da)
		(bb, aa) <- (aa, r)
	}
	вернуть da
Алгоритм формально определен в [Atti N.B., Diaz-Toca G.M., Lombardi H.
The Berlekamp-Massey Algorithm Revisited, AAECC (2006) 17: 75–82] и
неформально в [Shoup V. A Computational Introduction to Number Theory
and Algebra]. В последней работе можно найти обоснование алгоритма:
теорема 17.8, п. 17.5.1, рассуждения после теоремы 18.2.
Из этого обоснования, в частности, следует, что \deg da, \deg db <= l.
*******************************************************************************
*/

#define ppMinPoly_schema(n, m)\
/* aa */	O_OF_W(2 * n),\
/* bb */	O_OF_W(2 * n + 1),\
/* q */		O_OF_W(n + 2),\
/* r */		O_OF_W(2 * n),\
/* da */	O_OF_W(m),\
/* db */	O_OF_W(m + n + 2),\
			ppAddMulW_deep(m)

void ppMinPoly(word b[], const word a[], size_t l, void* stack)
{
	const size_t n = W_OF_B(l);
	const size_t m = W_OF_B(l + 1);
	size_t na, nb;
	word* aa; 			/* [2n] */
	word* bb;			/* [2n + 1] */
	word* q;			/* [n + 2] */
	word* r;			/* [2n] */
	word* da; 			/* [m] */
	word* db;			/* [m + n + 2] */
	// pre
	ASSERT(wwIsValid(b, m) && wwIsValid(a, 2 * n));
	// разметить стек
	memSlice(stack,
		ppMinPoly_schema(n, m), SIZE_MAX,
		&aa, &bb, &q, &r, &da, &db, &stack);
	// aa <- a
	wwCopy(aa, a, 2 * n);
	wwTrimHi(aa, 2 * n, 2 * l);
	na = wwWordSize(aa, 2 * n);
	// bb <- x^{2l}
	nb = W_OF_B(2 * l + 1);
	wwSetZero(bb, nb);
	wwSetBit(bb, 2 * l, 1);
	// da <- 1
	wwSetW(da, m, 1);
	// db <- 0
	wwSetZero(db, m);
	// пока deg(aa) >= len
	while (ppDeg(aa, na) + 1 > l)
	{
		size_t nq, nda;
		// (q, r) <- (bb div aa, bb mod aa)
		ppDiv(q, r, bb, nb, aa, na, stack);
		// db <- db + q * da
		nq = wwWordSize(q, nb - na + 1);
		nda = wwWordSize(da, m);
		while (nq--)
			db[nq + nda] ^= ppAddMulW(db + nq, da, nda, q[nq], stack);
		ASSERT(nq + nda <= m || wwIsZero(db, nq + nda - m));
		// da <-> db
		wwSwap(da, db, m);
		// bb <- aa
		wwCopy(bb, aa, na);
		nb = na;
		// aa <- r
		wwCopy(aa, r, na);
		na = wwWordSize(aa, na);
	}
	// b <- da
	wwCopy(b, da, m);
}

size_t ppMinPoly_deep(size_t l)
{
	const size_t n = W_OF_B(l);
	const size_t m = W_OF_B(l + 1);
	return memSliceSize( 
		ppMinPoly_schema(n, m), SIZE_MAX);
}

#define ppMinPolyMod_schema(n)\
/* t */		O_OF_W(n),\
/* s */		O_OF_W(2 * n),\
/* stack */	utilMax(2,\
				ppMulMod_deep(n),\
				ppMinPoly_deep(n * B_PER_W))

void ppMinPolyMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	size_t l, i;
	word* t;			/* [n] */
	word* s;			/* [2n] */
	// pre
	ASSERT(wwIsValid(b, n) && wwIsValid(a, n) && wwIsValid(mod, n));
	ASSERT(wwCmpW(mod, n, 1) > 0 && wwCmp(a, mod, n) < 0);
	// разметить стек
	memSlice(stack,
		ppMinPolyMod_schema(n), SIZE_MAX,
		&t, &s, &stack);
	// l <- \deg(mod)
	l = ppDeg(mod, n);
	// s[2 * l - 1 - i] <- a(x)^i при x = 0
	wwCopy(t, a, n);
	wwSetBit(s, 2 * l - 1, wwTestBit(t, 0));
	for (i = 2 * l - 1; i--;)
	{
		ppMulMod(t, t, a, mod, n, stack);
		wwSetBit(s, i, wwTestBit(t, 0));
	}
	wwTrimHi(s, 2 * n, 2 * l);
	// b <- минимальный многочлен s
	ppMinPoly(b, s, l, stack);
}

size_t ppMinPolyMod_deep(size_t n)
{
	return memSliceSize( 
		ppMinPolyMod_schema(n), SIZE_MAX);
}
