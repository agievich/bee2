/*
*******************************************************************************
\file ecp_pre.c
\brief Elliptic curves over prime fields: precomputations
\project bee2 [cryptographic library]
\created 2021.07.18
\version 2026.02.20
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
Арифметика Co-Z

Aрифметика Co-Z --- это формулы сложения якобиевых точек с совпадающими
Z-координатами. Арифметика предложена в [Mel06]. Детальные и дополнительные
алгоритмы представлены в [Riv11].

В функции ecpIDblAJ() выполняется удвоение (J, J) <- 2A. Результатом удвоения
аффинной точки a являются якобиевы точки a1 и b такие, что:
- a1 == a;
- b == 2a;
- ecZ(a1, n) == ecZ(b, n).
Реализован модифицированный алгоритм XYCZ-IDBL из [Riv11]. Модификация состоит
в сокращении числа переменных и отказе от двух удвоений взамен на одно
уполовинивание. Сложность алгоритма:
	2M + 4S + 6add + 1half + 2*2 \approx 6M.

В функции ecpReaddJ() выполняется сложение (J, J) <- J + J. Предполагается,
что это сложение выполняется сразу после предыдущего такого же сложения
или после операции (J, J) <- 2A и тогда у слагаемых совпадают z-координаты.
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

// ([3n]b, [3n]a1) <- (2[2n]a, [3n]a) ((J, J) <- 2A)
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
	// t4 <- zb^2 [2y1^2]
	qrSqr(t4, ecZ(b, n), ec->f, stack);
	// t4 <- t4^2 [4y1^2]
	qrSqr(t4, t4, ec->f, stack);
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

// ([3n]c, [3n]a1) <- ([3n]a + [3n]b, [3n]a) ((J, J) <- J + J)
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
	zmSub(t3, t3, t4, ec->f);
	// zc <- t5 za [z(x2 - x1) = z3], za1 <- zc
	qrMul(ecZ(c, n), t5, ecZ(a, n), ec->f, stack);
	wwCopy(ecZ(a1, n), ecZ(c, n), n);
	// t5 <- t5^2 [(x2 - x1)^2 = AA]
	qrSqr(t3, ecX(a), ec->f, stack);
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
	// ya1 <- ya t3 [y1(CC - BB)]
	qrMul(ecY(a1, n), ecY(a, n), t3, ec->f, stack);
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
Ускорители

В gfpMul2 выражение a * b при известных a^2 и b^2 вычисляется как
	((a + b)^2 - a^2 - b^2) / 2
*******************************************************************************
*/

#define gfpMul2(c, a, b, a2, b2, f, stack)\
	do {\
		qrAdd(c, a, b, f);\
		qrSqr(c, c, f, stack);\
		qrSub(c, c, a2, f);\
		qrSub(c, c, b2, f);\
		gfpHalf(c, c, f);\
	} while(0)

/*
*******************************************************************************
Предвычисления: схема SO
*******************************************************************************
*/

#define ecpPreSO_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

void ecpPreSO(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack) 
{
	word* t;			/* [ec->d * ec->f->n] */
	size_t i;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(0 < w && w < B_PER_W);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(SIZE_BIT_POS(w - 1) * ec->d * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecpPreSO_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	// вычислить малые кратные
	if (w > 1)
	{
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

size_t ecpPreSO_deep(size_t n, size_t ec_d, size_t f_deep)
{
	return memSliceSize(
		ecpPreSO_local(n, ec_d),
		utilMax(2,
			ecpIDblAJ_deep(n, f_deep),
			ecpReaddJ_deep(n, f_deep)),
		SIZE_MAX);
}

/*
*******************************************************************************
Предвычисления: схема SOA

Реализован алгоритм SmallMultA, предложенный в [APS22]. Алгоритм основан на
многочленах деления и требует примерно 25/2 M + 5 S операций на каждую
кратную точку и дополнительно операцию 1I для одновременнного обращения 
нескольких элементов поля.

Алгоритм выполняется в 4 этапа. Этапам соответствуют следующие шаги алгоритма:
- этап 1 -- шаги 1 -- 13 (расчет начальных выражений);
- этап 2 -- шаг 14 (расчет основных выражений);
- этап 3 -- шаг 15 (обращение элементов поля);
- этап 4 -- шаги 16 -- 20 (формирование точек).

В целом кэшируются те же выражения, что и в ecpPreSO(). Отличия:
- не кэшируется выражение Wᵢ₊₂Wᵢ₋₁² - Wᵢ₋₂Wᵢ₊₁². Соответственно макрос 
  WWW не используется;
- выражения (2y)²WᵢWᵢ₊₂ сохраняются в координатах выходных точек.
  В частности, при четном i выражение (2y)²WᵢWᵢ₊₂ сохраняется в x-координате
  (i + 1)-й точки и используется на этапе 4 для вычисления xᵢ₊₁;
- кэшируется не 2, а 3 последовательных значения WᵢWᵢ₊₂. Это связано
  с тем, что на итерациях этапа 2 используются пары выражений 
  Wᵢ₋₁Wᵢ₊₁ и WᵢWᵢ₊₂, а на итерациях этапа 4 -- пары Wᵢ₋₂Wᵢ и WᵢWᵢ₊₂.

Дополнительный макрос:
7. W2I(i) -- выражения Wᵢ⁻², i = 3, 5, ..., 2ʷ - 1:
	* память: 2ʷ⁻¹ - 1;
	* вычисляются на этапе 3, используются на этапе 4;
	* предварительно в ячейках памяти для выражений размещаются произведения
	  (∏ᵥ Wᵥ²: v <= i).

\remark Произведения (∏ᵥ Wᵥ²: v <= i) используются для одновременного
обращения (Wᵢ²) с помощью следующего алгоритма:
1. V₃ <- W₃².
2. Для i = 5, 7, ..., m = 2ʷ - 1:
   1) Vᵢ <- Vᵢ₋₂Wᵢ² == (∏ᵥ Wᵥ²: v <= i).
3. t <- Vₘ⁻¹ = (∏ᵥ Wᵥ²: v <= m)⁻¹.
4. Для i = m, m - 2, ..., 5:
   1) (Wᵢ⁻², t) <- (t Vᵢ₋₂, t Wᵢ²).
5. W₃⁻² <- t.
Алгоритм предложен в [Mon87] (см. также [Doc05; algorithm 11.15, p. 209])
и известен как трюк Монтгомери.

[Mon87] Montogomery P, Speeding the Pollard and elliptic curve method of
		factorization. Mathematics of Computation, 48 (177), 1987, 243--264.
[Doc05] Doche C. Finite Field Arithmetic. In: Handbook of Elliptic and
		Hyperelliptic Curve Cryptography. Chapman & Hall/CRC, 2005.
*******************************************************************************
*/

#if defined(W) || defined(W2) || defined(WW) || defined(WWy2) ||\
	defined(WWy4) || defined(W2I)
	#error "Conflicting preprocessor definitions"
#endif

#define ecpPreSOA_local(n, w)\
/* t */			O_OF_W(n),\
/* dy2 */		O_OF_W(n),\
/* Ws */		O_OF_W((SIZE_BIT_POS(w) - 1) * n),\
/* W2s */		O_OF_W((SIZE_BIT_POS(w) - 2) * n),\
/* WWs */		O_OF_W(3 * n),\
/* WWy4s */		O_OF_W(n),\
/* W2Is */		O_OF_W((SIZE_BIT_POS(w - 1) - 1) * n)

bool_t ecpPreSOA(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack) 
{
	size_t n;
	word* t;				/* [n] */
	word* dy2;				/* [n] (2y)² */
	word* Ws;				/* [(2^w - 1) * n] Wᵢ */
	word* W2s;				/* [(2^w - 2) * n] Wᵢ² */
	word* WWs;				/* [3 * n] WᵢWᵢ₊₂ */
	word* WWy4s;			/* [n] (2y)⁴WᵢWᵢ₊₂ */
	word* W2Is;				/* [(2^{w-1} - 1) * n] Wᵢ⁻² */
	size_t i;
	word* pt;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(w >= 3);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(2 * ec->f->n * SIZE_BIT_POS(w - 1)),
		a, O_OF_W(2 * ec->f->n)));
	// размерности
	n = ec->f->n;
	// разметить стек
	memSlice(stack,
		ecpPreSOA_local(n, w), SIZE_0, SIZE_MAX,
		&t, &dy2, &Ws, &W2s, &WWs, &WWy4s, &W2Is, &stack);
	// первая точка
	pt = pre->pts;
	wwCopy(pt, a, 2 * n);
	pt += 2 * n;

/*** SmallMultA: begin ***/
#define W(i) (Ws + ((i) - 3) * n)
#define W2(i) (W2s + ((i) - 3) * n)
#define WW(i) (WWs + ((i) % 3) * n)
#define WWy2(i) (pre->pts + (i) * n)
#define WWy4(i) (WWy4s)
#define W2I(i) (W2Is + (((i) - 3) >> 1) * n)

/* SmallMultA: этап 1 */

	// dy2 <- (2y)²
	gfpDouble(dy2, ecY(a, n), ec->f);
	qrSqr(dy2, dy2, ec->f, stack);
	// W₃, W₄
	{
		word* t1 = W2s;
		word* x2 = t1 + n;
		word* bx = x2 + n;
		word* a2 = bx + n;
		// (x2, bx, a2) <- (x², b x, A²)
		qrSqr(x2, ecX(a), ec->f, stack);
		qrMul(bx, ec->B, ecX(a), ec->f, stack);
		qrSqr(a2, ec->A, ec->f, stack);
		// [W₃] <- 3(x²+A)² − 4(a²−3Bx)
		qrAdd(t, x2, ec->A, ec->f);				// x²+A
		qrSqr(t, t, ec->f, stack);				// (x²+A)²
		gfpDouble(t1, t, ec->f);				// 2(x²+A)²
		qrAdd(W(3), t, t1, ec->f);				// 3(x²+A)²
		gfpDouble(t, bx, ec->f);				// 2Bx
		qrAdd(t, t, bx, ec->f);					// 3Bx
		qrSub(t, a2, t, ec->f);					// A²−3Bx
		gfpDouble(t, t, ec->f);					// 2(A²−3Bx)
		gfpDouble(t, t, ec->f);					// 4(A²−3Bx)
		qrSub(W(3), W(3), t, ec->f);
		// [W₄] <- 4Bx(5x²-A)
		gfpDouble(t, x2, ec->f);				// 2x²
		gfpDouble(t, t, ec->f);					// 4x²
		qrAdd(t, t, x2, ec->f);					// 5x²
		qrSub(t, t, ec->A, ec->f);				// 5x²-A
		qrMul(t, bx, t, ec->f, stack);			// Bx(5x²-A)
		gfpDouble(t, t, ec->f);					// 2Bx(5x²-A)
		gfpDouble(W(4), t, ec->f);				// 4Bx(5x²-A)
		// [W₄] <- x⁶+4Bx(5x²-A)
		qrMul(t, x2, ecX(a), ec->f, stack);
		qrSqr(t1, t, ec->f, stack);
		qrAdd(W(4), t1, W(4), ec->f);
		// [W₄] <- x⁶+4Bx(5x²-A)+5Ax(x³-Ax)
		qrMul(t1, ec->A, ecX(a), ec->f, stack);	// Ax
		qrSub(t, t, t1, ec->f);					// x³-Ax
		qrMul(t, t, t1, ec->f, stack);			// Ax(x³-Ax)
		gfpDouble(t1, t, ec->f);				// 2Ax(x³-Ax)
		gfpDouble(t1, t1, ec->f);				// 4Ax(x³-Ax)
		qrAdd(t, t, t1, ec->f);					// 5Ax(x³-Ax)
		qrAdd(W(4), W(4), t, ec->f);
		// [W₄] <- x⁶+4Bx(5x²-A)+5Ax(x³-Ax)-8B²
		qrSqr(t, ec->B, ec->f, stack);			// B²
		gfpDouble(t, t, ec->f);					// 2B²
		gfpDouble(t, t, ec->f);					// 4B²
		gfpDouble(t, t, ec->f);					// 8B²
		qrSub(W(4), W(4), t, ec->f);
		// [W₄] <- 2(x⁶+4Bx(5x²-A)+5Ax(x³-Ax)-8B²-A³)
		qrMul(t1, a2, ec->A, ec->f, stack);		// A³
		qrSub(W(4), W(4), t1, ec->f);
		gfpDouble(W(4), W(4), ec->f);
	}
	// [W₃²] <- W₃²
	qrSqr(W2(3), W(3), ec->f, stack);
	// [W₄²] <- W₄²
	qrSqr(W2(4), W(4), ec->f, stack);
	// [W₁W₃] <- W₃
	qrCopy(WW(1), W(3), ec->f);
	// [W₂W₄] <- W₄
	qrCopy(WW(2), W(4), ec->f);
	// [(2y)²W₂W₄] <- (2y)² W₂W₄
	qrMul(WWy2(2), dy2, WW(2), ec->f, stack);
	// [(2y)⁴W₂W₄] <- (2y)² (2y)²W₂W₄
	qrMul(WWy4(2), dy2, WWy2(2), ec->f, stack);
	// [W₅] <- (2y)⁴W₂W₄−W₁W₃W₃²
	qrMul(t, WW(1), W2(3), ec->f, stack);
	qrSub(W(5), WWy4(2), t, ec->f);
	// [W₅²] <- W₅²
	qrSqr(W2(5), W(5), ec->f, stack);
	// [W₆] <- W₃(W₅W₂²−W₁W₄²)
	qrSqr(W2(5), W(5), ec->f, stack);

/* SmallMultA: этап 2 */

	// W₂ᵢ, W₂ᵢ₊₁, WᵢWᵢ₊₂ для i=3,4...,2ʷ⁻¹
	for (i = 3; i <= SIZE_BIT_POS(w - 1); ++i)
	{
		// [WᵢWᵢ₊₂] <- ((Wᵢ+Wᵢ₊₂)²-Wᵢ²-Wᵢ₊₂²)/2
		gfpMul2(WW(i), W(i), W(i + 2), W2(i), W2(i + 2), ec->f, stack);
		// W₂ᵢ
		if (i == 3)
		{
			// [W₆] <- W₃W₅-(W₁W₃)W₄²
			qrMul(t, WW(1), W2(4), ec->f, stack);
			qrSub(W(6), WW(3), t, ec->f);
		}
		else
		{
			// [W₂ᵢ] <- (WᵢWᵢ₊₂)Wᵢ₋₁² - (Wᵢ₋₂Wᵢ)Wᵢ₊₁²
			qrMul(t, WW(i - 2), W2(i + 1), ec->f, stack);
			qrMul(W(2 * i), WW(i), W2(i - 1), ec->f, stack);
			qrSub(W(2 * i), W(2 * i), t, ec->f);
		}
		// [W₂ᵢ²] <- W₂ᵢ²
		qrSqr(W2(2 * i), W(2 * i), ec->f, stack);
		// W₂ᵢ₊₁
		if (i & 1)
		{
			// [W₂ᵢ₊₁] <- (WᵢWᵢ₊₂)Wᵢ²-((2y)⁴Wᵢ₋₁Wᵢ₊₁)Wᵢ₊₁²
			qrMul(t, WWy4(i - 1), W2(i + 1), ec->f, stack);
			qrMul(W(2 * i + 1), WW(i), W2(i), ec->f, stack);
			qrSub(W(2 * i + 1), W(2 * i + 1), t, ec->f);
 		}
		else
		{
			// [(2y)²WᵢWᵢ₊₂] <- (2y)²(WᵢWᵢ₊₂)
			qrMul(WWy2(i), dy2, WW(i), ec->f, stack);
			// [(2y)⁴WᵢWᵢ₊₂] <- (2y)²((2y)²WᵢWᵢ₊₂)
			qrMul(WWy4(i), dy2, WWy2(i), ec->f, stack);
			// [W₂ᵢ₊₁] <- ((2y)⁴WᵢWᵢ₊₂)Wᵢ²-(Wᵢ₋₁Wᵢ₊₁)Wᵢ₊₁²
			qrMul(t, WW(i - 1), W2(i + 1), ec->f, stack);
			qrMul(W(2 * i + 1), WWy4(i), W2(i), ec->f, stack);
			qrSub(W(2 * i + 1), W(2 * i + 1), t, ec->f);
		}
		// [W₂ᵢ₊₁²] <- W₂ᵢ₊₁²
		if (i != SIZE_BIT_POS(w - 1))
			qrSqr(W2(2 * i + 1), W(2 * i + 1), ec->f, stack);
	}

/* SmallMultA: этап 3 */

	// (∏ᵥ Wᵥ²: v <= i)
	wwCopy(W2I(3), W2(3), n);
	for (i = 3; i + 2 < SIZE_BIT_POS(w); i += 2)
		qrMul(W2I(i + 2), W2I(i), W2(i + 2), ec->f, stack);
	// t <- (∏ᵥ Wᵥ²: v <= 2ʷ-1)⁻¹
	ASSERT(i == SIZE_BIT_POS(w) - 1);
	if (qrIsZero(W2I(i), ec->f))
		return FALSE;
	qrInv(t, W2I(i), ec->f, stack);
	// Wᵢ⁻²
	{
		word* t1 = WWy4s;
		for (; i > 3; i -= 2)
		{
			// t1 <- (∏ᵥ Wᵥ²: v <= i)⁻¹ Wᵢ² == (∏ᵥ Wᵥ²: v < i)⁻¹
			qrMul(t1, t, W2(i), ec->f, stack);
			// [Wᵢ⁻²] <- (∏ᵥ Wᵥ²: v <= i)⁻¹ (∏ᵥ Wᵥ²: v < i) == Wᵥ⁻²
			qrMul(W2I(i), t, W2I(i - 2), ec->f, stack);
			// t <- t1
			wwCopy(t, t1, n);
		}
		// [W₃⁻²] <- (∏ᵥ Wᵥ²: v = 3)⁻¹
		wwCopy(W2I(3), t, n);
	}

/* SmallMultA: этап 4 */

	// (xᵢ,yᵢ) для i=3,5,..,2ʷ⁻¹-1
	ASSERT(i == 3);
	for (; i < SIZE_BIT_POS(w - 1); i += 2, pt += 2 * n)
	{
		// [xᵢ] <- x-((2y)²Wᵢ₋₁Wᵢ₊₁)Wᵢ⁻²
		qrMul(ecX(pt), WWy2(i - 1), W2I(i), ec->f, stack);
		qrSub(ecX(pt), ecX(a), ecX(pt), ec->f);
		// [yᵢ] <- yW₂ᵢ(Wᵢ⁻²)²
		qrSqr(t, W2I(i), ec->f, stack);
		qrMul(ecY(pt, n), ecY(a, n), W(2 * i), ec->f, stack);
		qrMul(ecY(pt, n), ecY(pt, n), t, ec->f, stack);
	}
	// [xᵢ] <- x-((2y)²Wᵢ₋₁Wᵢ₊₁)Wᵢ⁻² для i=2ʷ⁻¹+1
	ASSERT(i == SIZE_BIT_POS(w - 1) + 1);
	qrMul(ecX(pt), WWy2(i - 1), W2I(i), ec->f, stack);
	qrSub(ecX(pt), ecX(a), ecX(pt), ec->f);

	// (xᵢ,yᵢ) для i=2ʷ⁻¹+1,2ʷ⁻¹+3,...,2ʷ-1
	while (1)
	{
		if (i != SIZE_BIT_POS(w) - 1)
			// [WᵢWᵢ₊₂] <- ((Wᵢ+Wᵢ₊₂)²-Wᵢ²-Wᵢ₊₂²)/2
			gfpMul2(WW(i), W(i), W(i + 2), W2(i), W2(i + 2), ec->f, stack);
		else
			// [WᵢWᵢ₊₂] <- WᵢWᵢ₊₂
			qrMul(WW(i), W(i), W(i + 2), ec->f, stack);
		// [yᵢ] <- y((WᵢWᵢ₊₂)Wᵢ₋₁²-(Wᵢ₋₂Wᵢ)Wᵢ₊₁²)(Wᵢ⁻²)²
		qrMul(t, WW(i), W2(i - 1), ec->f, stack);
		qrMul(ecY(pt, n), WW(i - 2), W2(i + 1), ec->f, stack);
		qrSub(ecY(pt, n), t, ecY(pt, n), ec->f);
		qrMul(ecY(pt, n), ecY(a, n), ecY(pt, n), ec->f, stack);
		qrSqr(t, W2I(i), ec->f, stack);
		qrMul(ecY(pt, n), ecY(pt, n), t, ec->f, stack);
		// последняя точка?
		if (i == SIZE_BIT_POS(w) - 1)
			break;
		// к следующей точке
		i += 2, pt += 2 * n;
		// [xᵢ] <- x−(2y)²(Wᵢ₋₁Wᵢ₊₁)Wᵢ⁻²
		gfpMul2(t, W(i - 1), W(i + 1), W2(i - 1), W2(i + 1), ec->f, stack);
		qrMul(t, dy2, t, ec->f, stack);
		qrMul(t, t, W2I(i), ec->f, stack);
		qrSub(ecX(pt), ecX(a), t, ec->f);
	}
	
#undef W2I
#undef WWy4
#undef WWy2
#undef WW
#undef W2
#undef W
/* SmallMultA: end */

	// заполнить служебные поля
	pre->type = ec_pre_soa;
	pre->w = w, pre->h = 0;
	return TRUE;
}

size_t ecpPreSOA_deep(size_t n, size_t f_deep, size_t w)
{
	return memSliceSize(
		ecpPreSOA_local(n, w),
		f_deep,
		SIZE_MAX);
}
