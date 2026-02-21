/*
*******************************************************************************
\file ecp_pre.c
\brief Elliptic curves over prime fields: precomputations
\project bee2 [cryptographic library]
\created 2021.07.18
\version 2026.02.21
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/util.h"
#include "bee2/math/ecp.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "ecp_lcl.h"

/*
*******************************************************************************
Одновременное обращение элементов кольца вычетов

Реализован алгоритм Монтгомери, предложенный в [Mon87] (см. также 
[Doc05; algorithm 11.15, p. 209]). Сложность обращения count элементов:
	1I + 3(count - 1)M.

[Mon87] Montogomery P, Speeding the Pollard and elliptic curve method of
		factorization. Mathematics of Computation, 48 (177), 1987, 243--264.
[Doc05] Doche C. Finite Field Arithmetic. In: Handbook of Elliptic and
		Hyperelliptic Curve Cryptography. Chapman & Hall/CRC, 2005.
*******************************************************************************
*/

#define qrInvBatch_local(n, count)\
/* t */		O_OF_W(n),\
/* vs */	O_OF_W(count * n)

static bool_t qrInvBatch(word* bs, const word* as, size_t count, 
	const qr_o* r, void* stack)
{
	size_t n;
	word* t;			/* [n] */
	word* vs;			/* [count * n] */
	size_t i;
	// pre 
	ASSERT(qrIsOperable(r));
	ASSERT(wwIsSameOrDisjoint(as, bs, count * r->n));
	ASSERT(count > 0);
	// разметить стек
	n = r->n;
	memSlice(stack,
		qrInvBatch_local(n, count), SIZE_0, SIZE_MAX,
		&t, &vs, &stack);
	// v[i] <- (prod_j a[j]: j <= i)
	wwCopy(vs + 0 * n,  as + 0 * n, n);
	for (i = 1; i < count; ++i)
		qrMul(vs + i * n, as + i * n, vs + (i - 1) * n, r, stack);
	// t <- 1 / (prod_j a[j]: j < count)
	if (qrIsZero(vs + (count - 1) * n, r))
		return FALSE;
	qrInv(t, vs + (count - 1) * n, r, stack);
	// одновременное обрашение
	for (--i; i >= 1; --i)
	{
		// v[i] <- (prod_j a[j]: j < i) / (prod_j a[j]: j <= i) == 1/a[i]
		qrMul(vs + i * n, t, vs + (i - 1) * n, r, stack);
		// t <- a[i] / (prod_j a[j]: j <= i) == (prod_j a[j]: j < i)
		qrMul(t, t, as + i * n, r, stack);
		// b[i] <- 1/a[i]
		wwCopy(bs + i * n, vs + i * n, n);
	}
	// b[0] <- 1/a[0]
	wwCopy(bs + 0 * n, t, n);
	return TRUE;
}

static size_t qrInvBatch_deep(size_t n, size_t f_deep, size_t count)
{
	return memSliceSize(
		qrInvBatch_local(n, count),
		f_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Арифметика Co-Z

Aрифметика Co-Z --- это формулы сложения якобиевых точек с совпадающими
Z-координатами. Арифметика предложена в [Mel06]. Детальные и дополнительные
алгоритмы представлены в [Riv11].

В функции ecpIDblAJ() выполняется удвоение JJ <- 2A. Результатом удвоения
аффинной точки a являются якобиевы точки a1 и b такие, что:
- a1 == a;
- b == 2a;
- ecZ(a1, n) == ecZ(b, n).
Реализован модифицированный алгоритм XYCZ-IDBL из [Riv11]. Модификация состоит
в сокращении числа переменных и отказе от двух удвоений взамен на одно
уполовинивание. Сложность алгоритма:
	2M + 4S + 6add + 1half + 2*2 \approx 6M.

В функции ecpReaddJ() выполняется сложение JJ <- J + J. Предполагается,
что это сложение выполняется сразу после предыдущего такого же сложения
или после операции JJ <- 2A и тогда у слагаемых совпадают z-координаты.
Результатом сложения якобиевых точек a и b с одинаковыми z-координатами
являются якобиевы точки a1 и c такие, что:
- a1 == a;
- c == a + b;
- ecZ(a1, n) == ecZ(c, n).
Реализован модифицированный алгоритм XYCZ-ADD из [Riv11]. Модификация состоит
в сокращении числа переменных и дополнительном умножении для вычисления
выходной z-координаты. Сложность алгоритма:
	5M + 2S + 7add \approx 7M.

\pre В ecpReaddJ() у точек a и b совпадают z-координаты.

\expect В ecpIDblAJ() у точки a ненулевая y-координата, т.е. в результате
удвоения не может быть получена точка O.

\expect В ecpReaddJ() точки a и b отличаются.

\post В ecpIDblAJ() у точек b и a1 совпадают z-координаты.

\post В ecpReaddJ() у точек c и a1 совпадают z-координаты.

[Mel07] Meloni N. New Point Addition Formulae for ECC Applications.
        In: Arithmetic of Finite Fields, First International Workshop --
        WAIFI 2007, volume 4547 of Lecture Notes in Computer Science,
        pp. 189–201. Springer, 2007.
[Riv11] Rivain M. Fast and Regular Algorithms for Scalar Multiplication
        over Elliptic Curves. Cryptology ePrint Archive, Report 2011/338.
        https://eprint.iacr.org/2011/338.
*******************************************************************************
*/

#define ecpIDblAJ_local(n)\
/* t3 */	O_OF_W(n),\
/* t4 */	O_OF_W(n)

// ([3n]b, [3n]a1) <- (2[2n]a, [3n]a) (JJ <- 2A)
static void ecpIDblAJ(word b[], word a1[], const word a[], const ec_o* ec,
	void* stack)
{
	size_t n;
	word* t3;			/* [n] */
	word* t4;			/* [n] */
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(a == b || wwIsDisjoint2(a, 2 * ec->f->n, b, 3 * ec->f->n));
	ASSERT(a == a1 || wwIsDisjoint2(a, 2 * ec->f->n, a1, 3 * ec->f->n));
	ASSERT(wwIsDisjoint2(a1, 3 * ec->f->n, b, 3 * ec->f->n));
	EXPECT(!wwIsZero(ecY(a, ec->f->n), ec->f->n));
	// разметить стек
	n = ec->f->n;
	memSlice(stack,
		ecpIDblAJ_local(n), SIZE_0, SIZE_MAX,
		&t3, &t4, &stack);
	// t3 <- xa^2 [x1^2]
	qrSqr(t3, ecX(a), ec->f, stack);
	// t4 <- 2 t3 [2x1^2]
	gfpDouble(t4, t3, ec->f);
	// t3 <- t3 + t4 [3x1^2]
	zmAdd(t3, t3, t4, ec->f);
	// t3 <- t3 + A [3x1^2 + A = BB]
	zmAdd(t3, t3, ec->A, ec->f);
	// zb <- 2 ya [2y1 = z2], za1 <- zb
	gfpDouble(ecZ(b, n), ecY(a, n), ec->f);
	wwCopy(ecZ(a1, n), ecZ(b, n), n);
	// t4 <- zb^2 [4y1^2]
	qrSqr(t4, ecZ(b, n), ec->f, stack);
	// xa1 <- t4 xa [4x1y1^2 = AA]
	qrMul(ecX(a1), t4, ecX(a), ec->f, stack);
	// xb <- t3^2 [BB^2]
	qrSqr(ecX(b), t3, ec->f, stack);
	// xb <- xb - xa1 [BB^2 - AA]
	zmSub(ecX(b), ecX(b), ecX(a1), ec->f);
	// xb <- xb - xa1 [BB^2 - 2AA = x2]
	zmSub(ecX(b), ecX(b), ecX(a1), ec->f);
	// yb <- xa1 - xb [AA - x2]
	zmSub(ecY(b, n), ecX(a1), ecX(b), ec->f);
	// yb <- yb t3 [BB(AA - x2)]
	qrMul(ecY(b, n), ecY(b, n), t3, ec->f, stack);
	// ya1 <- t4^2 [16y1^4]
	qrSqr(ecY(a1, n), t4, ec->f, stack);
	// ya1 <- ya1/2 [8y1^4 = y1']
	gfpHalf(ecY(a1, n), ecY(a1, n), ec->f);
	// yb <- yb - ya1 [BB(AA - x2) - 8y1^4 = y2]
	zmSub(ecY(b, n), ecY(b, n), ecY(a1, n), ec->f);
	// post
	ASSERT(wwEq(ecZ(b, n), ecZ(a1, n), n));
}

static size_t ecpIDblAJ_deep(size_t n, size_t f_deep)
{
	return memSliceSize(
		ecpIDblAJ_local(n),
		f_deep,
		SIZE_MAX);
}

#define ecpReaddJ_local(n)\
/* t3 */	O_OF_W(n),\
/* t4 */	O_OF_W(n),\
/* t5 */	O_OF_W(n)

// ([3n]c, [3n]a1) <- ([3n]a + [3n]b, [3n]a) (JJ <- J + J)
static void ecpReaddJ(word c[], word a1[], const word a[], const word b[],
	const ec_o* ec, void* stack)
{
	size_t n;
	word* t3;			/* [n] */
	word* t4;			/* [n] */
	word* t5;			/* [n] */
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOnJ(a, ec));
	ASSERT(ecpSeemsOnJ(b, ec));
	ASSERT(wwIsSameOrDisjoint(a, c, 3 * ec->f->n));
	ASSERT(wwIsSameOrDisjoint(b, c, 3 * ec->f->n));
	ASSERT(wwIsSameOrDisjoint(a, a1, 3 * ec->f->n));
	ASSERT(wwIsSameOrDisjoint(b, a1, 3 * ec->f->n));
	ASSERT(wwIsDisjoint(c, a1, 3 * ec->f->n));
	ASSERT(wwEq(ecZ(a, ec->f->n), ecZ(b, ec->f->n), ec->f->n));
	EXPECT(!wwEq(a, b, 2 * ec->f->n));
	// разметить стек
	n = ec->f->n;
	memSlice(stack,
		ecpReaddJ_local(n), SIZE_0, SIZE_MAX,
		&t3, &t4, &t5, &stack);
	// t5 <- xb - xa [x2 - x1]
	zmSub(t5, ecX(b), ecX(a), ec->f);
	// zc <- t5 za [z(x2 - x1) = z3], za1 <- zc
	qrMul(ecZ(c, n), t5, ecZ(a, n), ec->f, stack);
	wwCopy(ecZ(a1, n), ecZ(c, n), n);
	// t5 <- t5^2 [(x2 - x1)^2 = AA]
	qrSqr(t5, t5, ec->f, stack);
	// t3 <- t5 xb [x2 AA = CC]
	qrMul(t3, t5, ecX(b), ec->f, stack);
	// xa1 <- t5 xa [x1 AA = BB]
	qrMul(ecX(a1), t5, ecX(a), ec->f, stack);
	// t4 <- yb - ya [y2 - y1]
	zmSub(t4, ecY(b, n), ecY(a, n), ec->f);
	// t5 <- t4^2 [(y2 - y1)^2 = DD]
	qrSqr(t5, t4, ec->f, stack);
	// t5 <- t5 - xa1 [DD - BB]
	zmSub(t5, t5, ecX(a1), ec->f);
	// xc <- t5 - t3 [DD - BB - CC = x3]
	zmSub(ecX(c), t5, t3, ec->f);
	// t3 <- t3 - xa1 [CC - BB]
	zmSub(t3, t3, ecX(a1), ec->f);
	// ya1 <- ya1 t3 [y1(CC - BB)]
	qrMul(ecY(a1, n), ecY(a1, n), t3, ec->f, stack);
	// t3 <- xa1 - xc [BB - x3]
	zmSub(t3, ecX(a1), ecX(c), ec->f);
	// t4 <- t4 t3 [(y2 - y1)(BB - x3)]
	qrMul(t4, t4, t3, ec->f, stack);
	// yc <- t4 - ya1 [(y2 - y1)(BB - x3) - y1(CC - BB) = y3]
	zmSub(ecY(c, n), t4, ecY(a1, n), ec->f);
	// post
	ASSERT(wwEq(ecZ(c, n), ecZ(a1, n), n));
}

static size_t ecpReaddJ_deep(size_t n, size_t f_deep)
{
	return memSliceSize(
		ecpReaddJ_local(n),
		f_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Предвычисления: схема SO

Алгоритм (см. [Mel07], [Riv11]):
1. t <- 2a. 						// JJ <- 2A, с обновлением a
2. pre[i] <- a.
3. Для i = 2, 3, ..., 2^{i-1}:
   1) pre[i] <- t + pre[i-1].		// JJ <- J + J, с обновлением t
*******************************************************************************
*/

#define ecpPreSO_local(n)\
/* t */		O_OF_W(3 * n)

void ecpPreSO(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack) 
{
	word* t;			/* [3 * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(0 < w && w < B_PER_W);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(SIZE_BIT_POS(w - 1) * 3 * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecpPreSO_local(ec->f->n), SIZE_0, SIZE_MAX,
		&t, &stack);
	// вычислить малые кратные
	if (w > 1)
	{
		size_t i;
		// (t, pre[0]) <- (2a, a)
		ecpIDblAJ(t, ecPrePt(pre, 0, ec), a, ec, stack);
		// pre[i] <- t + pre[i - 1] (с обновлением t)
		for (i = 1; i < SIZE_BIT_POS(w - 1); ++i)
			ecpReaddJ(ecPrePt(pre, i, ec), t, t, ecPrePt(pre, i - 1, ec),
				ec, stack);
	}
	else
		ecFromA(ecPrePt(pre, 0, ec), a, ec, stack);
	// заполнить служебные поля
	pre->type = ec_pre_so;
	pre->w = w, pre->h = 0;
}

size_t ecpPreSO_deep(size_t n, size_t f_deep)
{
	return memSliceSize(
		ecpPreSO_local(n),
		utilMax(2,
			ecpIDblAJ_deep(n, f_deep),
			ecpReaddJ_deep(n, f_deep)),
		SIZE_MAX);
}

/*
*******************************************************************************
Предвычисления: схема SOA

Реализован алгоритм схемы SO с дополнением -- преобразованием якобиевых точек
в аффинные. 

Требуется преобразовать count = 2^{w-1} - 1 точек. Для мульпликативного 
обращения z-координат используется алгоритм Монтгомери. Затем для каждой точки 
выполняется стандартное преобрвзование
	(X : Y : Z) -> (X * (1/Z)^2, Y * (1/Z)^3)
со сложостью 1S + 3M. Общая сложность преобразования count точек:
	1I + (6 count - 1)M + count S.
*******************************************************************************
*/

#define ecpPreSOA_local(n, w)\
/* t1 */	O_OF_W(3 * n),\
/* t2 */	O_OF_W(3 * n),\
/* zs */	O_OF_W((SIZE_BIT_POS(w - 1) - 1) * n)

bool_t ecpPreSOA(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack) 
{
	size_t n;
	word* t1;			/* [3 * n] */
	word* t2;			/* [3 * n] */
	word* zs;			/* [(SIZE_BIT_POS(w - 1) - 1) * n] */
	size_t i;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(0 < w && w < B_PER_W);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(SIZE_BIT_POS(w - 1) * 2 * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	n = ec->f->n;
	memSlice(stack,
		ecpPreSOA_local(n, w), SIZE_0, SIZE_MAX,
		&t1, &t2, &zs, &stack);
	// pre[0] <- a
	wwCopy(ecPrePtA(pre, 0, ec), a, 2 * n);
	// остальные кратные точки
	if (w > 1)
	{
		// (t2, t1) <- (2a, a)
		ecpIDblAJ(t2, t1, a, ec, stack);
		// pre[1] <- t2 + t1 (с обновлением t2)
		ecpReaddJ(t1, t2, t2, t1, ec, stack);
		wwCopy(ecPrePtA(pre, 1, ec), t1, 2 * n);
		// z[0] <- z-координата pre[1]
		wwCopy(zs + 0 * n, ecZ(t1, n), n);
		// остальные кратные точки
		for (i = 2; i < SIZE_BIT_POS(w - 1); ++i)
		{
			// pre[i] <- t2 + pre[i-1] (с обновлением t2)
			ecpReaddJ(t1, t2, t2, t1, ec, stack);
			wwCopy(ecPrePtA(pre, i, ec), t1, 2 * n);
			// z[i-1] <- z-координата pre[i]
			wwCopy(zs + (i - 1) * n, ecZ(t1, n), n);
		}
		// обратить z-координаты
		if (!qrInvBatch(zs, zs, SIZE_BIT_POS(w - 1) - 1, ec->f, stack))
			return FALSE;
		// построить аффинные точки
		for (i = 1; i < SIZE_BIT_POS(w - 1); ++i)
		{
			word* pt = ecPrePtA(pre, i, ec);
			// t2 <- (1/z[i-1])^2
			qrSqr(t2, zs + (i - 1) * n, ec->f, stack);
			// нормировать x-координату pre[i]
			qrMul(ecX(pt), ecX(pt), t2, ec->f, stack);
			// t2 <- (1/z[i-1])^3
			qrMul(t2, zs + (i - 1) * n, t2, ec->f, stack);
			// нормировать y-координату pre[i]
			qrMul(ecY(pt, n), ecY(pt, n), t2, ec->f, stack);
		}
	}
	// заполнить служебные поля
	pre->type = ec_pre_soa;
	pre->w = w, pre->h = 0;
	return TRUE;
}

size_t ecpPreSOA_deep(size_t n, size_t f_deep, size_t w)
{
	return memSliceSize(
		ecpPreSOA_local(n, w),
		utilMax(3,
			ecpIDblAJ_deep(n, f_deep),
			ecpReaddJ_deep(n, f_deep),
			qrInvBatch_deep(n, f_deep, SIZE_BIT_POS(w - 1) - 1)),
		SIZE_MAX);
}
