/*
*******************************************************************************
\file zz_gcd.c
\brief Multiple-precision unsigned integers: Euclidian gcd algorithms
\project bee2 [cryptographic library]
\created 2012.04.22
\version 2025.09.23
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/util.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Алгоритм Евклида

В функциях zzGCD(), zzExGCD() реализованы бинарные алгоритмы,
не требующие прямых делений.

В функции zzExGCD() пересчитываются числа da, db, da1, db1 такие, что
	da * aa - db * bb = u,
	da1 * aa - db1 * bb = -v,
где aa = a / 2^s, bb = b / 2^s, s -- max целое т.ч. 2^s | a и 2^s | b.

Числа u и v поддерживают вычисление НОД(aa, bb). Если u > v, то u
заменяется на u - v, а если u <= v, то v заменяется на v - u.
Как только v == 0 вычисления останавливаются и возвращается тройка
(2^s * u, da, db).

В функции zzExGCD() реализован алгоритм:
	u <- aa
	da <- 1, db <- 0
	v <- bb
	da1 <- 0, db1 <- 1
	пока (v != 0)
	{
		пока (u -- четное)
			u <- u / 2
			если (da и db -- четные)
				da <- da / 2, db <- db / 2
			иначе
				da <- (da + bb) / 2, db <- (db + aa) / 2
[
	Пусть da -- четное, db -- нечетное. Поскольку da * aa - db * bb -- четное,
	bb -- четное. Но aa и bb не могут быть одновременно четными.
	Поэтому aa -- нечетное. В конце концов, da + bb и db + aa -- четные.
	Аналогично рассматриваются другие варианты четности da и db.
]
		пока (v -- четное)
			v <- v / 2
			если (da1 и db1 -- четные)
				da1 <- da1 / 2, db1 <- db1 / 2
			иначе
				da1 <- (da1 + bb) / 2, db1 <- (db1 + aa) / 2
		если (u > v)
			u <- u - v
			da <- da + da1, db <- db + db1
			если (da > bb) // и, следовательно, db > aa
				da <- da - bb, db <- db - aa				(*)
		иначе // u <= v
			v <- v - u
			da1 <- da1 + da, db1 <- db1 + db
			если (da1 > bb) и, следовательно, db1 > aa
				da1 <- da1 - bb, db1 <- db1 - aa			(**)
	}
	Корректировки (*), (**) гарантируют, что da, da1 < bb и db, db1 < aa.

\remark Эксперименты с различными реализациями алгоритма Евклида:
1) бинарный алгоритм опережает обычный (полные деления) примерно в 2 раза и
2) опережает смешанный (полные деления и деления на 2) примерно в 1.5 раза.

\todo Регуляризация?
*******************************************************************************
*/

#define zzGCD_local(n, m)\
/* u */		O_OF_W(n),\
/* v */		O_OF_W(m)

void zzGCD(word d[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	register size_t s;
	word* u; 				/* [n] */
	word* v;				/* [m] */
	// pre
	ASSERT(wwIsDisjoint2(a, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MIN2(n, m)));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// разметить стек
	memSlice(stack,
		zzGCD_local(n, m), SIZE_MAX,
		&u, &v);
	// d <- 0
	wwSetZero(d, MIN2(n, m));
	// u <- a, v <- b
	wwCopy(u, a, n);
	wwCopy(v, b, m);
	// найти максимальное s т.ч. 2^s | u и 2^s | v
	s = utilMin(2, wwLoZeroBits(u, n), wwLoZeroBits(v, m));
	// u <- u / 2^s, v <- v / 2^s
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
		// u > v?
		if (wwCmp2(u, n, v, m) > 0)
			// u <- u - v
			zzSubW2(u + m, n - m, zzSub2(u, v, m));
		else
			// v <- v - u
			zzSubW2(v + n, m - n, zzSub2(v, u, n));
	} while (!wwIsZero(v, m));
	// d <- v
	wwCopy(d, u, n);
	// d <- d * 2^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	CLEAN(s);
}

size_t zzGCD_deep(size_t n, size_t m)
{
	return memSliceSize(
		zzGCD_local(n, m), 
		SIZE_MAX);
}

#define zzIsCoprime_local(n, m)\
/* d */		O_OF_W(MIN2(n, m))

bool_t zzIsCoprime(const word a[], size_t n, const word b[], size_t m, 
	void* stack)
{
	word* d;			/* [MIN2(n, m)] */
	// разметить стек
	memSlice(stack,
		zzIsCoprime_local(n, m), SIZE_0, SIZE_MAX,
		&d, &stack);
	// a == 0 => (a, b) = b
	if (wwIsZero(a, n))
		return wwIsW(b, m, 1);
	// b == 0 => (a, b) = a
	if (wwIsZero(b, m))
		return wwIsW(a, n, 1);
	// d <- (a, b), d == 1?
	zzGCD(d, a, n, b, m, stack);
	return wwIsW(d, MIN2(n, m), 1);
}

size_t zzIsCoprime_deep(size_t n, size_t m)
{
	return memSliceSize(
		zzIsCoprime_local(n, m), 
		zzGCD_deep(n, m),
		SIZE_MAX);
}

#define zzLCM_local(n, m)\
/* prod */	O_OF_W(n + m),\
/* gcd */	O_OF_W(MIN2(n, m)),\
/* r */		O_OF_W(MIN2(n, m))

void zzLCM(word d[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	word* prod;			/* [n + m] */
	word* gcd; 			/* [MIN2(n, m)] */
	word* r;			/* [MIN2(n, m)] */
	// pre
	ASSERT(wwIsDisjoint2(a, n, d, MAX2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MAX2(n, m)));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// разметить стек
	memSlice(stack,
		zzLCM_local(n, m), SIZE_0, SIZE_MAX,
		&prod, &gcd, &r, &stack);
	// d <- 0
	wwSetZero(d, n + m);
	// нормализация
	n = wwWordSize(a, n);
	m = wwWordSize(b, m);
	// prod <- a * b
	zzMul(prod, a, n, b, m, stack);
	// gcd <- (a, b)
	zzGCD(gcd, a, n, b, m, stack);
	// (n, m) <- (|prod|, |gcd|)
	if (n < m)
		SWAP(n, m);
	n += m;
	m = wwWordSize(gcd, m);
	// d <- prod \div gcd
	zzDiv(d, r, prod, n, gcd, m, stack);
}

size_t zzLCM_deep(size_t n, size_t m)
{
	return memSliceSize(
		zzLCM_local(n, m), 
		utilMax(3,
			zzMul_deep(n, m),
			zzGCD_deep(n, m),
			zzMod_deep(n + m, MIN2(n, m))),
		SIZE_MAX);
}

#define zzExGCD_local(n, m)\
/* aa */	O_OF_W(n),\
/* bb */	O_OF_W(m),\
/* u */		O_OF_W(n),\
/* v */		O_OF_W(m),\
/* da1 */	O_OF_W(m),\
/* db1 */	O_OF_W(n)

void zzExGCD(word d[], word da[], word db[], const word a[], size_t n,
	const word b[], size_t m, void* stack)
{
	register size_t s;
	register size_t nu;
	register size_t mv;
	word* aa;			/* [n] */
	word* bb;			/* [m] */
	word* u;			/* [n] */
	word* v;			/* [m] */
	word* da1;			/* [m] */
	word* db1;			/* [n] */
	// pre
	ASSERT(wwIsDisjoint3(da, m, db, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(a, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(a, n, da, m));
	ASSERT(wwIsDisjoint2(b, m, da, m));
	ASSERT(wwIsDisjoint2(a, n, db, n));
	ASSERT(wwIsDisjoint2(b, m, db, n));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// разметить стек
	memSlice(stack,
		zzExGCD_local(n, m), SIZE_MAX,
		&aa, &bb, &u, &v, &da1, &db1);
	// d <- 0, da <- 1, db <- 0, da1 <- 0, db1 <- 1
	wwSetZero(d, MIN2(n, m));
	wwSetW(da, m, 1);
	wwSetZero(db, n);
	wwSetZero(da1, m);
	wwSetW(db1, n, 1);
	// найти максимальное s т.ч. 2^s | a и 2^s | b
	s = utilMin(2, wwLoZeroBits(a, n), wwLoZeroBits(b, m));
	// aa <- a / 2^s, bb <- b / 2^s
	wwCopy(aa, a, n), wwShLo(aa, n, s), n = wwWordSize(aa, n);
	wwCopy(bb, b, m), wwShLo(bb, m, s), m = wwWordSize(bb, m);
	// u <- aa, v <- bb
	wwCopy(u, aa, n);
	wwCopy(v, bb, m);
	nu = n, mv = m;
	// итерации
	do
	{
		// пока u четное
		for (; u[0] % 2 == 0; wwShLo(u, nu, 1))
			if (da[0] % 2 == 0 && db[0] % 2 == 0)
			{
				// da <- da / 2, db <- db / 2
				wwShLo(da, m, 1);
				wwShLo(db, n, 1);
			}
			else
			{
				ASSERT((da[0] + bb[0]) % 2 == 0);
				ASSERT((db[0] + aa[0]) % 2 == 0);
				// da <- (da + bb) / 2, db <- (db0 + aa) / 2
				wwShLoCarry(da, m, 1, zzAdd2(da, bb, m));
				wwShLoCarry(db, n, 1, zzAdd2(db, aa, n));
			}
		// пока v четное
		for (; v[0] % 2 == 0; wwShLo(v, mv, 1))
			if (da1[0] % 2 == 0 && db1[0] % 2 == 0)
			{
				// da1 <- da1 / 2, db1 <- db1 / 2
				wwShLo(da1, m, 1);
				wwShLo(db1, n, 1);
			}
			else
			{
				ASSERT((da1[0] + bb[0]) % 2 == 0);
				ASSERT((db1[0] + aa[0]) % 2 == 0);
				// da1 <- (da1 + bb) / 2, db1 <- (db1 + aa) / 2
				wwShLoCarry(da1, m, 1, zzAdd2(da1, bb, m));
				wwShLoCarry(db1, n, 1, zzAdd2(db1, aa, n));
			}
		// нормализация
		nu = wwWordSize(u, nu);
		mv = wwWordSize(v, mv);
		// u > v?
		if (wwCmp2(u, nu, v, mv) > 0)
		{
			// u <- u - v
			zzSubW2(u + mv, nu - mv, zzSub2(u, v, mv));
			if (zzAdd2(da, da1, m) || wwCmp(da, bb, m) >= 0)
				zzSub2(da, bb, m);
			if (zzAdd2(db, db1, n) || wwCmp(db, aa, n) >= 0)
				zzSub2(db, aa, n);
		}
		else
		{
			// v <- v - u
			zzSubW2(v + nu, mv - nu, zzSub2(v, u, nu));
			if (zzAdd2(da1, da, m) || wwCmp(da1, bb, m) >= 0)
				zzSub2(da1, bb, m);
			if (zzAdd2(db1, db, n) || wwCmp(db1, aa, n) >= 0)
				zzSub2(db1, aa, n);
		}
	} while (!wwIsZero(v, mv));
	// d <- u
	wwCopy(d, u, nu);
	// d <- d * 2^s
	wwShHi(d, W_OF_B(wwBitSize(d, nu) + s), s);
	// очистка
	CLEAN3(s, nu, mv);
}

size_t zzExGCD_deep(size_t n, size_t m)
{
	return memSliceSize(
		zzExGCD_local(n, m), 
		SIZE_MAX);
}

/*
*******************************************************************************
Деление по модулю

В zzDivMod() реализован упрощенный вариант zzExGCD(): рассчитываются только
коэффициенты da, da1, причем первоначально da = divident (а не 1).

\todo Реализовать в zzDivMod() случай произвольного (а не только нечетного)
модуля mod.
*******************************************************************************
*/

#define zzDivMod_local(n)\
/* u */		O_OF_W(n),\
/* v */		O_OF_W(n),\
/* da */	O_OF_W(n),\
/* da1 */	O_OF_W(n)

void zzDivMod(word b[], const word divident[], const word a[],
	const word mod[], size_t n, void* stack)
{
	register size_t nu;
	register size_t nv;
	word* u; 			/* [n] */
	word* v;			/* [n] */
	word* da;			/* [n] */
	word* da1;			/* [n] */
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwCmp(divident, mod, n) < 0);
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(zzIsOdd(mod, n) && mod[n - 1] != 0);
	// разметить стек
	memSlice(stack,
		zzDivMod_local(n), SIZE_MAX,
		&u, &v, &da, &da1);
	// da <- divident, da1 <- 0
	wwCopy(da, divident, n);
	wwSetZero(da1, n);
	// u <- a, v <- mod
	wwCopy(u, a, n);
	wwCopy(v, mod, n);
	nu = wwWordSize(u, n);
	nv = n;
	// итерации со следующими инвариантами:
	//	da * a = divident * u \mod mod
	//	da1 * a = -divident * v \mod mod
	while (!wwIsZero(v, nv))
	{
		// пока u -- четное
		for (; u[0] % 2 == 0; wwShLo(u, nu, 1))
			if (da[0] % 2 == 0)
				// da <- da / 2
				wwShLo(da, n, 1);
			else
				// da <- (da + mod) / 2
				wwShLoCarry(da, n, 1, zzAdd2(da, mod, n));
		// пока v -- четное
		for (; v[0] % 2 == 0; wwShLo(v, nv, 1))
			if (da1[0] % 2 == 0)
				// da1 <- da1 / 2
				wwShLo(da1, n, 1);
			else
				// da1 <- (da1 + mod) / 2
				wwShLoCarry(da1, n, 1, zzAdd2(da1, mod, n));
		// нормализация
		nu = wwWordSize(u, nu);
		nv = wwWordSize(v, nv);
		// u > v?
		if (wwCmp2(u, nu, v, nv) > 0)
		{
			// u <- u - v
			zzSubW2(u + nv, nu - nv, zzSub2(u, v, nv));
			if (zzAdd2(da, da1, n) || wwCmp(da, mod, n) >= 0)
				zzSub2(da, mod, n);
		}
		else
		{
			// v <- v - u
			zzSubW2(v + nu, nv - nu, zzSub2(v, u, nu));
			if (zzAdd2(da1, da, n) || wwCmp(da1, mod, n) >= 0)
				zzSub2(da1, mod, n);
		}
	}
	// здесь u == gcd(a, mod)
	EXPECT(wwIsW(u, nu, 1));
	// gcd(a, mod) != 1? b <- 0
	if (!wwIsW(u, nu, 1))
		wwSetZero(b, n);
	// здесь da * a == divident \mod mod
	wwCopy(b, da, n);
	// очистка
	CLEAN2(nu, nv);
}

size_t zzDivMod_deep(size_t n)
{
	return memSliceSize(
		zzDivMod_local(n), 
		SIZE_MAX);
}

/*
*******************************************************************************
Почти обращение по модулю

В zzAlmostDivMod() реализован алгоритм Калиски [B.S.Kaliski Jr. The Montgomery
inverse and its applications. IEEE Transactions on Computers, 44(8):1064–1065,
1995]:
	u <- a
	da0 <- 1
	v <- mod
	da <- 0
	k <- 0
	пока (u != 0)
	{
		если (v -- четное)
			v <- v / 2, da0 <- da0 * 2
		иначе если (u -- четное)
			u <- u / 2, da <- da * 2
		иначе если (v > u)
			v <- (v - u) / 2, da <- da + da0, da0 <- da0 * 2
		иначе // если (u >= v)
			u <- (u - v) / 2, da0 <- da0 + da, da <- da * 2
		k <- k + 1
	}
	если (da >= mod)
		da <- da - mod
	da <- mod - da
	return (da, k)

Инварианты на итерациях zzAlmostDivMod():
	mod = v * da0 + u * da
	a * da = -v (\mod mod)

В оригинальной статье Калиски доказано, что при 0 < a < mod:
-	числа da, da0 лежат в интервале [0, 2 * mod - 1];
-	wwBitSize(mod) <= k <= 2 * wwBitSize(mod).

\remark В [E. Savas, K. Koc. The Montgomery Modular Inverse -- Revisited.
IEEE Transactions on Computers, 49(7):763–766, 2000] рассмотрен случай, когда
a и mod < 2^m, причем условие a < mod может нарушаться. Доказано, что в этом
случае
-	числа da, da0 лежат в интервале [0, 2 * mod - 1];
-	wwBitSize(mod) <= k <= m + wwBitSize(mod).

\todo В перечисленных статьях предполагается, что mod -- простое число.
Проверить, что результаты можно распространить на случай произвольного
нечетного mod. Можно ли сузить интервал [0, 2 * mod - 1]?
*******************************************************************************
*/

#define zzAlmostInvMod_local(n)\
/* u */		O_OF_W(n),\
/* v */		O_OF_W(n),\
/* da0 */	O_OF_W(n + 1),\
/* da */	O_OF_W(n + 1)

size_t zzAlmostInvMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	register size_t k = 0;
	size_t nu;
	size_t nv;
	word* u;			/* [n] */
	word* v;			/* [n] */
	word* da0;			/* [n + 1] */
	word* da;			/* [n + 1] */
	// разметить стек
	memSlice(stack,
		zzAlmostInvMod_local(n), SIZE_0, SIZE_MAX,
		&u, &v, &da0, &da, &stack);		
	// pre
	ASSERT(!wwIsZero(a, n));
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(zzIsOdd(mod, n) && mod[n - 1] != 0);
	// da0 <- 1, da <- 0
	wwSetW(da0, n + 1, 1);
	wwSetZero(da, n + 1);
	// u <- a, v <- mod
	wwCopy(u, a, n);
	wwCopy(v, mod, n);
	nu = wwWordSize(u, n);
	nv = n;
	// пока (u != 0)
	do
	{
		// v -- четное?
		if (zzIsEven(v, nv))
		{
			wwShLo(v, nv, 1);
			nv = wwWordSize(v, nv);
			wwShHi(da0, n + 1, 1);
		}
		// u -- четное?
		else if (zzIsEven(u, nu))
		{
			wwShLo(u, nu, 1);
			nu = wwWordSize(u, nu);
			wwShHi(da, n + 1, 1);
		}
		// v > u?
		else if (wwCmp2(v, nv, u, nu) > 0)
		{
			ASSERT(nv >= nu);
			zzSubW2(v + nu, nv - nu, zzSub2(v, u, nu));
			wwShLo(v, nv, 1);
			nv = wwWordSize(v, nv);
			zzAdd2(da, da0, n + 1);
			wwShHi(da0, n + 1, 1);
		}
		// u >= v?
		else
		{
			ASSERT(nu >= nv);
			zzSubW2(u + nv, nu - nv, zzSub2(u, v, nv));
			wwShLo(u, nu, 1);
			nu = wwWordSize(u, nu);
			zzAdd2(da0, da, n + 1);
			wwShHi(da, n + 1, 1);
		}
		// k <- k + 1
		k = k + 1;
	} while (!wwIsZero(u, nu));
	// здесь v == (a, mod)
	EXPECT(wwIsW(v, nv, 1));
	// \gcd(a, mod) != 1? b <- 0
	if (!wwIsW(v, nv, 1))
		wwSetZero(b, n);
	// da >= mod => da -= mod
	if (wwCmp2(da, n + 1, mod, n) >= 0)
		da[n] -= zzSub2(da, mod, n);
	ASSERT(wwCmp2(da, n + 1, mod, n) < 0);
	// b <- mod - da
	zzNegMod(b, da, mod, n);
	// возврат
	return k;
}

size_t zzAlmostInvMod_deep(size_t n)
{
	return memSliceSize(
		zzAlmostInvMod_local(n), 
		SIZE_MAX);
}
