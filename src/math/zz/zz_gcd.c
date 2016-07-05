/*
*******************************************************************************
\file zz_gcd.c
\brief Multiple-precision unsigned integers: Euclidian gcd algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.22
\version 2016.07.05
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Алгоритм Евклида

В функциях zzGCD(), zzExGCD() реализованы бинарные алгоритмы,
не требующие прямых делений.

В функции zzExGCD() пересчитываются числа da, db, da0, db0 такие, что
	da0 * aa - db0 * bb = (-1)^sign0 u,
	da * aa - db * bb = (-1)^sign v,
где aa = a / 2^s, bb = b / 2^s, s -- max целое т.ч. 2^s | a и 2^s | b.

Числа u и v поддерживают вычисление НОД(aa, bb). Если u >= v, то u
заменяется на u - v, а если u < v, то v заменяется на v - u.
Как только u == 0 вычисления останавливаются и возвращается тройка
(2^s * v, da, db).

В функции zzExGCD() реализован алгоритм:
	u <- aa
	da0 <- 1, db0 <- 0, sign0 <- 0
	v <- bb
	da <- 0, db <- 1, sign <- 0
	пока (u != 0)
	{
		пока (u -- четное)
			u <- u / 2
			если (da0 и db0 -- четные)
				da0 <- da0 / 2, db0 <- db0 / 2
			иначе 
[
	Пусть da0 -- четное, db0 -- нечетное. Поскольку da0 aa + db0 bb -- четное,
	bb -- четное. Но aa и bb не могут быть одновременно четными. 
	Поэтому aa -- нечетное. В конце концов, da0 + bb и db0 + aa -- четные.
	Аналогично рассматриваются другие варианты четности da0 и db0.
]
				da0 <- (da0 + bb) / 2, db0 <- (db0 + aa) / 2
		пока (v -- четное)
			v <- v / 2
			если (da и db -- четные)
				da <- da / 2, db <- db / 2
			иначе
				da <- (da + bb) / 2, db <- (db + aa) / 2
		если (u >= v)
			u <- u - v
			если (sign0 == sign)
				da0 <- da0 - da, db0 <- db0 - db
				если (da0 < 0)
					da0 <- -da0, db0 <- -db0, sign0 <- 1 - sign0
			иначе // sign0 != sign
				da0 <- da0 + da, db0 <- db0 + db
				если (da0 > bb)
					da0 <- da0 - bb, db0 <- db0 - aa			(*)
		иначе // u < v
			v <- v - u
			если (sign0 == sign)
				da <- da - da0, db <- db - db0
				если (da < 0)
					da <- -da, db <- -db, sign <- 1 - sign
			иначе // sign0 != sign
				da <- da + da0, db <- db + db0
				если (da > bb)
					da <- da - bb, db <- db - aa				(**)
	}
	Корректировки (*), (**) гарантируют, что da0, da < bb и db0, db < aa.

\remark Эксперименты с различными реализациями алгоритма Евклида:
1) бинарный алгоритм опережает обычный (полные деления) примерно в 2 раза и 
2) опережает смешанный (полные деления и деления на 2) примерно в 1.5 раза.

\todo Регуляризация?
*******************************************************************************
*/

void zzGCD(word d[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	register size_t s;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	stack = v + m;
	// pre
	ASSERT(wwIsDisjoint2(a, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MIN2(n, m)));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
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
		// u >= v?
		if (wwCmp2(u, n, v, m) >= 0)
			// u <- u - v
			zzSubW2(u + m, n - m, zzSub2(u, v, m));
		else
			// v <- v - u
			zzSubW2(v + n, m - n, zzSub2(v, u, n));
	}
	while (!wwIsZero(u, n));
	// d <- v
	wwCopy(d, v, m);
	// d <- d * 2^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	s = 0;
}

size_t zzGCD_deep(size_t n, size_t m)
{
	return O_OF_W(n + m);
}

bool_t zzIsCoprime(const word a[], size_t n, const word b[], size_t m, void* stack)
{
	word* d = (word*)stack;
	stack = d + MIN2(n, m);
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
	return O_OF_W(MIN2(n, m)) + zzGCD_deep(n, m);
}

void zzLCM(word d[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	// переменные в stack
	word* prod = (word*)stack;
	word* gcd = prod + n + m;
	word* r = gcd + MIN2(n, m);
	stack = r + MIN2(n, m);
	// pre
	ASSERT(wwIsDisjoint2(a, n, d, MAX2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MAX2(n, m)));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
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
	return O_OF_W(n + m + MIN2(n, m) + MIN2(n, m)) +
		utilMax(3, 
			zzMul_deep(n, m), 
			zzGCD_deep(n, m), 
			zzMod_deep(n + m, MIN2(n, m)));
}

int zzExGCD(word d[], word da[], word db[], const word a[], size_t n,
	const word b[], size_t m, void* stack)
{
	register size_t s;
	register size_t nu, mv;
	register int sign0 = 0, sign = 1;
	// переменные в stack
	word* aa = (word*)stack;
	word* bb = aa + n;
	word* u = bb + m;
	word* v = u + n;
	word* da0 = v + m;
	word* db0 = da0 + m;
	stack = db0 + n;
	// pre
	ASSERT(wwIsDisjoint3(da, m, db, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(a, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MIN2(n, m)));
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
			if (da0[0] % 2 == 0 && db0[0] % 2 == 0)
			{
				// da0 <- da0 / 2, db0 <- db0 / 2
				wwShLo(da0, m, 1);
				wwShLo(db0, n, 1);
			}
			else
			{
				ASSERT((da0[0] + bb[0]) % 2 == 0);
				ASSERT((db0[0] + aa[0]) % 2 == 0);
				// da0 <- (da0 + bb) / 2, db0 <- (db0 + aa) / 2
				wwShLoCarry(da0, m, 1, zzAdd2(da0, bb, m));
				wwShLoCarry(db0, n, 1, zzAdd2(db0, aa, n));
			}
		// пока v четное
		for (; v[0] % 2 == 0; wwShLo(v, mv, 1))
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
				// da <- (da + bb) / 2, db <- (db + aa) / 2
				wwShLoCarry(da, m, 1, zzAdd2(da, bb, m));
				wwShLoCarry(db, n, 1, zzAdd2(db, aa, n));
			}
		// нормализация
		nu = wwWordSize(u, nu);
		mv = wwWordSize(v, mv);
		// u >= v?
		if (wwCmp2(u, nu, v, mv) >= 0)
		{
			// u <- u - v
			zzSubW2(u + mv, nu - mv, zzSub2(u, v, mv));
			if (sign0 != sign)
			{
				if (zzAdd2(da0, da, m) || wwCmp(da0, bb, m) >= 0)
					zzSub2(da0, bb, m);
				if (zzAdd2(db0, db, n) || wwCmp(db0, aa, n) >= 0)
					zzSub2(db0, aa, n);
			}
			else if (wwCmp(da0, da, m) >= 0)
			{
				ASSERT(wwCmp(db0, db, n) >= 0);
				zzSub2(da0, da, m);
				zzSub2(db0, db, n);
			}
			else
			{
				ASSERT(wwCmp(db0, db, n) < 0);
				zzSub(da0, da, da0, m);
				zzSub(db0, db, db0, n);
				sign0 = 1 - sign0;
			}
		}
		else
		{
			// v <- v - u
			zzSubW2(v + nu, mv - nu, zzSub2(v, u, nu));
			if (sign0 != sign)
			{
				if (zzAdd2(da, da0, m) || wwCmp(da, bb, m) >= 0)
					zzSub2(da, bb, m);
				if (zzAdd2(db, db0, n) || wwCmp(db, aa, n) >= 0)
					zzSub2(db, aa, n);
			}
			else if (wwCmp(da, da0, m) >= 0)
			{
				ASSERT(wwCmp(db, db0, n) >= 0);
				zzSub2(da, da0, m);
				zzSub2(db, db0, n);
			}
			else
			{
				ASSERT(wwCmp(db, db0, n) < 0);
				zzSub(da, da0, da, m);
				zzSub(db, db0, db, n);
				sign = 1 - sign;
			}
		}
	}
	while (!wwIsZero(u, nu));
	// d <- v
	wwCopy(d, v, m);
	// d <- d * 2^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	s = 0;
	sign0 = sign = 0;
	nu = mv = 0;
	// возврат
	return sign;
}

size_t zzExGCD_deep(size_t n, size_t m)
{
	return O_OF_W(3 * n + 3 * m);
}


/*
*******************************************************************************
Деление по модулю

В zzDivMod() реализован упрощенный вариант zzExGCD(): рассчитываются
только da0, da, причем da0 = divident (а не 1).

\todo Реализовать в zzDivMod() случай произвольного (а не только 
нечетного) mod.
*******************************************************************************
*/

void zzDivMod(word b[], const word divident[], const word a[],
	const word mod[], size_t n, void* stack)
{
	register size_t nu, nv;
	register int sign0 = 0, sign = 1;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	word* da0 = v + n;
	word* da = da0 + n;
	stack = da + n;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwCmp(divident, mod, n) < 0);
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(zzIsOdd(mod, n) && mod[n - 1] != 0);
	// da0 <- divident, da <- 0
	wwCopy(da0, divident, n);
	wwSetZero(da, n);
	// u <- a, v <- mod
	wwCopy(u, a, n);
	wwCopy(v, mod, n);
	nu = wwWordSize(u, n);
	nv = n;
	// итерации со следующими инвариантами:
	//	da0 * a \equiv (-1)^sign0 * divident * u \mod mod
	//	da * a \equiv (-1)^sign * divident * v \mod mod
	while (!wwIsZero(u, nu))
	{
		// пока u -- четное
		for (; u[0] % 2 == 0; wwShLo(u, nu, 1))
			if (da0[0] % 2 == 0)
				// da0 <- da0 / 2
				wwShLo(da0, n, 1);
			else
				// da0 <- (da0 + mod) / 2
				wwShLoCarry(da0, n, 1, zzAdd2(da0, mod, n));
		// пока v -- четное
		for (; v[0] % 2 == 0; wwShLo(v, nv, 1))
			if (da[0] % 2 == 0)
				// da <- da / 2
				wwShLo(da, n, 1);
			else
				// da <- (da + mod) / 2
				wwShLoCarry(da, n, 1, zzAdd2(da, mod, n));
		// нормализация
		nu = wwWordSize(u, nu);
		nv = wwWordSize(v, nv);
		// u >= v?
		if (wwCmp2(u, nu, v, nv) >= 0)
		{
			// u <- u - v
			zzSubW2(u + nv, nu - nv, zzSub2(u, v, nv));
			if (sign0 != sign)
			{
				if (zzAdd2(da0, da, n) || wwCmp(da0, mod, n) >= 0)
					zzSub2(da0, mod, n);
			}
			else if (wwCmp(da0, da, n) >= 0)
				zzSub2(da0, da, n);
			else
				zzSub(da0, da, da0, n),
				sign0 = 1 - sign0;
		}
		else
		{
			// v <- v - u
			zzSubW2(v + nu, nv - nu, zzSub2(v, u, nu));
			if (sign0 != sign)
			{
				if (zzAdd2(da, da0, n) || wwCmp(da, mod, n) >= 0)
					zzSub2(da, mod, n);
			}
			else if (wwCmp(da, da0, n) >= 0)
				zzSub2(da, da0, n);
			else
				zzSub(da, da0, da, n),
				sign = 1 - sign;
		}
	}
	// здесь v == (a, mod)
	EXPECT(wwIsW(v, nv, 1));
	// \gcd(a, mod) != 1? b <- 0
	if (!wwIsW(v, nv, 1))
		wwSetZero(b, n);
	// здесь da * a \equiv (-1)^sign * divident \mod mod
	// если sign == 1, то b <- mod - da, иначе b <- da
	else if (sign == 1)
		zzSub(b, mod, da, n);
	else
		wwCopy(b, da, n);
	// очистка
	sign0 = sign = 0;
	nu = nv = 0;
}

size_t zzDivMod_deep(size_t n)
{
	return O_OF_W(4 * n);
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

size_t zzAlmostInvMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	register size_t k = 0;
	size_t nu, nv;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	word* da0 = v + n;
	word* da = da0 + n + 1;
	stack = da + n + 1;
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
	}
	while (!wwIsZero(u, nu));
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
	return O_OF_W(4 * n + 2);
}
