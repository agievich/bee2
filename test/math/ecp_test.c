/*
*******************************************************************************
\file ecp_test.c
\brief Tests for elliptic curves over prime fields
\project bee2/test
\created 2017.05.29
\version 2026.02.23
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>
#include <bee2/math/ecp.h>
#include <bee2/math/gfp.h>
#include <bee2/math/ww.h>
#include <bee2/math/zz.h>
#include <crypto/bign/bign_lcl.h>

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
Предвычисления: SmallMultJ

Реализован алгоритм SmallMultJ, предложенный в [APS22]. Алгоритм основан на
многочленах деления и требует примерно 19/2 M + 7/2 S операций на каждую
кратную точку.

Алгоритм выполняется в 3 этапа. Этапам соответствуют следующие шаги алгоритма:
- этап 1 -- шаги 1 -- 16 (расчет начальных выражений);
- этап 2 -- шаги 17, 18, 20 (расчет основных выражений, формирование первой
  половины точек);
- этап 3 -- шаги 19, 21, 22 (формирование оставшихся точек).

Для повышения читабельности используются макросы, которые покрывают следующие
выражения:
1. W(i) -- значения многочленов Wᵢ, i = 3, 4, ..., 2ʷ + 1:
	* память: 2ʷ - 1 (элементов поля);
	* вычисляются на этапах 1 и 2, используются на этапах 1--3;
	* кэшируются все значения.
2. W2(i) --	квадраты Wᵢ², i = 3, 4, ..., 2ʷ:
	* память: 2ʷ - 2.
3. WW(i) -- произведения WᵢWᵢ₊₂, i = 1, 2, ..., 2ʷ⁻¹:
	* память: 2;
	* вычисляются на этапах 1 и 2, используются на этапах 1--3;
	* кэшируются все значения.
4. WWy2(i) -- произведения (2y)²WᵢWᵢ₊₂, i = 2, 4, ..., 2ʷ⁻¹:
	* память: 2;
	* вычисляются и используются на этапах 1 и 2;
	* кэшируются 2 последовательных значения: текущее и предыдущее.
5. WWy4(i) -- произведения (2y)⁴WᵢWᵢ₊₂, i = 2, 4, ..., 2ʷ⁻¹:
	* память: 1;
	* вычисляются и используются на этапах 1 и 2;
	* кэшируется только текущее значение.
6. WWW(i) -- выражения Wᵢ₊₂Wᵢ₋₁² - Wᵢ₋₂Wᵢ₊₁², i = 3, 4, ..., 2ʷ⁻¹:
	* память: 2ʷ⁻¹ - 2;
	* вычисляются на этапах 1 и 2, используются на этапах 1--3;
	* кэшируются все значения.

[APS22]    Agievich S., Poruchnik S., Semenov V. Small scalar multiplication
		   on Weierstrass curves using division polynomials. Mat. Vopr.
		   Kriptogr., 13:2, 2022, https://doi.org/10.4213/mvk406.
*******************************************************************************
*/

#if defined(W) || defined(W2) || defined(WW) || defined(WWy2) ||\
	defined(WWy4) || defined(WWW)
#error "Conflicting preprocessor definitions"
#endif

#define ecpSmallMultJ_local(n, w)\
/* t */			O_OF_W(n),\
/* dy2 */		O_OF_W(n),\
/* Ws */		O_OF_W((SIZE_BIT_POS(w) - 1) * n),\
/* W2s */		O_OF_W((SIZE_BIT_POS(w) - 2) * n),\
/* WWs */		O_OF_W(2 * n),\
/* WWy2s */		O_OF_W(2 * n),\
/* WWy4s */		O_OF_W(n),\
/* WWWs */		O_OF_W((SIZE_BIT_POS(w - 1) - 2) * n)

static void ecpSmallMultJ(ec_pre_t* pre, const word a[], size_t w,
	const ec_o* ec, void* stack)
{
	size_t n;
	word* t;				/* [n] */
	word* dy2;				/* [n] (2y)² */
	word* Ws;				/* [(2^w - 1) * n] Wᵢ */
	word* W2s;				/* [(2^w - 2) * n] Wᵢ² */
	word* WWs;				/* [2 * n] WᵢWᵢ₊₂ */
	word* WWy2s;			/* [2 * n] (2y)²WᵢWᵢ₊₂ */
	word* WWy4s;			/* [n] (2y)⁴WᵢWᵢ₊₂ */
	word* WWWs;				/* [(2^{w-1} - 2) * n] Wᵢ₊₂Wᵢ₋₁² - Wᵢ₋₂Wᵢ₊₁² */
	size_t i;
	word* pt;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(w >= 3);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(3 * ec->f->n * SIZE_BIT_POS(w - 1)),
		a, O_OF_W(2 * ec->f->n)));
	// размерности
	n = ec->f->n;
	// разметить стек
	memSlice(stack,
		ecpSmallMultJ_local(n, w), SIZE_0, SIZE_MAX,
		&t, &dy2, &Ws, &W2s, &WWs, &WWy2s, &WWy4s, &WWWs, &stack);
	// первая точка
	pt = pre->pts;
	ecFromA(pt, a, ec, stack);
	pt += 3 * n;

/*** SmallMultJ: begin ***/
#define W(i) (Ws + ((i) - 3) * n)
#define W2(i) (W2s + ((i) - 3) * n)
#define WW(i) (WWs + ((i) % 2) * n)
#define WWy2(i) (WWy2s + ((i) % 2) * n)
#define WWy4(i) (WWy4s)
#define WWW(i) (WWWs + ((i) - 3) * n)

/* SmallMultJ: этап 1 */

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
		// [W₃] <- 3(x²+A)²−4(a²−3Bx)
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
	// [(2y)²W₂W₄] <- (2y)²(W₂W₄)
	qrMul(WWy2(2), dy2, WW(2), ec->f, stack);
	// [(2y)⁴W₂W₄] <- (2y)²((2y)²W₂W₄)
	qrMul(WWy4(2), dy2, WWy2(2), ec->f, stack);
	// [W₅] <- (2y)⁴W₂W₄−(W₁W₃)W₃²
	qrMul(t, WW(1), W2(3), ec->f, stack);
	qrSub(W(5), WWy4(2), t, ec->f);
	// [W₅²] <- W₅²
	qrSqr(W2(5), W(5), ec->f, stack);
	// [W₅W₂² − W₁W₄²] <- W₅-W₄²
	qrSub(WWW(3), W(5), W2(4), ec->f);
	// [W₆] <- W₃(W₅W₂²−W₁W₄²)
	qrMul(W(6), W(3), WWW(3), ec->f, stack);
	// [W₆W₃²−W₂W₅²] <- (W₆W₃)W₃-W₅²
	qrMul(WWW(4), W(6), W2(3), ec->f, stack);
	qrSub(WWW(4), WWW(4), W2(5), ec->f);

/* SmallMultJ: этап 2 */

		// W₂ᵢ, W₂ᵢ₊₁, Wᵢ₊₂Wᵢ²−Wᵢ₋₂Wᵢ₊₁², WᵢWᵢ₊₂ для i=3,4,...,2ʷ⁻¹
		// (Xᵢ:Yᵢ:Zᵢ) для нечетных i
	for (i = 3; i <= SIZE_BIT_POS(w - 1); ++i)
	{
		// [Wᵢ₊₂Wᵢ²−Wᵢ₋₂Wᵢ₊₁²] <- Wᵢ₊₂Wᵢ²−Wᵢ₋₂Wᵢ₊₁²
		if (i >= 5)
		{
			qrMul(WWW(i), W(i + 2), W2(i - 1), ec->f, stack);
			qrMul(t, W(i - 2), W2(i + 1), ec->f, stack);
			qrSub(WWW(i), WWW(i), t, ec->f);
		}
		// [W₂ᵢ] <- Wᵢ(Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁²)
		if (i >= 4)
			qrMul(W(2 * i), W(i), WWW(i), ec->f, stack);
		// [W₂ᵢ²] <- W₂ᵢ²
		qrSqr(W2(2 * i), W(2 * i), ec->f, stack);
		// [WᵢWᵢ₊₂] <- ((Wᵢ+Wᵢ₊₂)²-Wᵢ²-Wᵢ₊₂²)/2
		gfpMul2(WW(i), W(i), W(i + 2), W2(i), W2(i + 2), ec->f, stack);
		// W₂ᵢ₊₁
		//(Xᵢ:Yᵢ:Zᵢ) при нечетном i
		if (i & 1)
		{
			// [W₂ᵢ₊₁] <- (WᵢWᵢ₊₂)Wᵢ²-((2y)⁴Wᵢ₋₁Wᵢ₊₁)Wᵢ₊₁²
			qrMul(t, WWy4(i - 1), W2(i + 1), ec->f, stack);
			qrMul(W(2 * i + 1), WW(i), W2(i), ec->f, stack);
			qrSub(W(2 * i + 1), W(2 * i + 1), t, ec->f);
			// [Xᵢ] <- xWᵢ²−(2y)²Wᵢ₋₁Wᵢ₊₁
			qrMul(ecX(pt), ecX(a), W2(i), ec->f, stack);
			qrSub(ecX(pt), ecX(pt), WWy2(i - 1), ec->f);
			// [Yᵢ] <- y(Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁²)
			qrMul(ecY(pt, n), ecY(a, n), WWW(i), ec->f, stack);
			// [Zᵢ] <- Wᵢ
			wwCopy(ecZ(pt, n), W(i), n);
			// к следующей точке
			pt += 3 * n;
		}
		else
		{
			// [(2y)²WᵢWᵢ₊₂] <- (2y)²WᵢWᵢ₊₂
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
	// [Xᵢ] <- xWᵢ²−(2y)²Wᵢ₋₁Wᵢ₊₁ для i = 2ʷ⁻¹ + 1
	ASSERT(i == SIZE_BIT_POS(w - 1) + 1);
	qrMul(ecX(pt), ecX(a), W2(i), ec->f, stack);
	qrSub(ecX(pt), ecX(pt), WWy2(i - 1), ec->f);

/* SmallMultJ: этап 3 */

		// (Xᵢ:Yᵢ:Zᵢ) для i=2ʷ⁻¹+1,2ʷ⁻¹+3,...,2ʷ-1
	while (1)
	{
		// [Yᵢ] <- y(Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁²)
		qrMul(t, W(i + 2), W2(i - 1), ec->f, stack);
		qrMul(ecY(pt, n), W(i - 2), W2(i + 1), ec->f, stack);
		qrSub(ecY(pt, n), t, ecY(pt, n), ec->f);
		qrMul(ecY(pt, n), ecY(a, n), ecY(pt, n), ec->f, stack);
		// [Zᵢ] <- Wᵢ
		wwCopy(ecZ(pt, n), W(i), n);
		// последняя точка?
		if (i == SIZE_BIT_POS(w) - 1)
			break;
		// к следующей точке
		i += 2, pt += 3 * n;
		// [Xᵢ] <- x Wᵢ²−(2y)²Wᵢ₋₁Wᵢ₊₁
		gfpMul2(t, W(i - 1), W(i + 1), W2(i - 1), W2(i + 1), ec->f, stack);
		qrMul(t, dy2, t, ec->f, stack);
		qrMul(ecX(pt), ecX(a), W2(i), ec->f, stack);
		qrSub(ecX(pt), ecX(pt), t, ec->f);
	}

#undef WWW
#undef WWy4
#undef WWy2
#undef WW
#undef W2
#undef W
/* SmallMultJ: end */

		// заполнить служебные поля
	pre->type = ec_pre_so;
	pre->w = w, pre->h = 0;
}

static size_t ecpSmallMultJ_deep(size_t n, size_t f_deep, size_t w)
{
	return memSliceSize(
		ecpSmallMultJ_local(n, w),
		f_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Предвычисления: SmallMultA

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

#define ecpSmallMultA_local(n, w)\
/* t */			O_OF_W(n),\
/* dy2 */		O_OF_W(n),\
/* Ws */		O_OF_W((SIZE_BIT_POS(w) - 1) * n),\
/* W2s */		O_OF_W((SIZE_BIT_POS(w) - 2) * n),\
/* WWs */		O_OF_W(3 * n),\
/* WWy4s */		O_OF_W(n),\
/* W2Is */		O_OF_W((SIZE_BIT_POS(w - 1) - 1) * n)

static bool_t ecpSmallMultA(ec_pre_t* pre, const word a[], size_t w,
	const ec_o* ec, void* stack)
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
		ecpSmallMultA_local(n, w), SIZE_0, SIZE_MAX,
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

static size_t ecpSmallMultA_deep(size_t n, size_t f_deep, size_t w)
{
	return memSliceSize(
		ecpSmallMultA_local(n, w),
		f_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Контрольная сумма

Для предвычисленных точек pre[0..count) вычисляется контрольная сумма
	pre[0] \pm pre[1] \pm ... \pm pre[count-1],
где знаки определяются псевдослучайным образом с помощью генератора COMBO.
Генератор инициализируется затравочным значением seed.
*******************************************************************************
*/

#define ecPreChecksum_local(n, ec_d)\
/* state */		prngCOMBO_keep(),\
/* t1 */		O_OF_W(ec_d * n),\
/* t2 */		O_OF_W(ec_d * n),\
/* r */			1

static bool_t ecPreChecksum(word a[], const ec_pre_t* pre, u32 seed,
	const ec_o* ec, void* stack)
{
	octet* state;			/* [prngCOMBO_keep()] */
	word* t1;				/* [ec->d * ec->f->n] */
	word* t2;				/* [ec->d * ec->f->n] */
	octet* r;				/* [1] */
	size_t count;
	size_t i;
	// pre
	ASSERT(sizeof(state) >= prngCOMBO_keep());
	ASSERT(ecIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	// разметить стек
	memSlice(stack,
		ecPreChecksum_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&state, &t1, &t2, &r, &stack);
	// инициализировать генератор COMBO
	prngCOMBOStart(state, seed);
	// число предвычисленных точек
	count = SIZE_BIT_POS(pre->w - 1);
	if (pre->type == ec_pre_sh)
		++count;
	else if (pre->type == ec_pre_so)
		count *= pre->h;
	// проективные предвычисленные точки?
	if (pre->type == ec_pre_so || pre->type == ec_pre_sh)
	{
		wwCopy(t1, ecPrePt(pre, 0, ec), ec->d * ec->f->n);
		for (i = 1; i < count; ++i)
		{
			prngCOMBOStepR(r, 1, state);
			if (r[0] & 1)
				ecNeg(t2, ecPrePt(pre, i, ec), ec, stack);
			else
				wwCopy(t2, ecPrePt(pre, i, ec), ec->d * ec->f->n);
			ecAdd(t1, t1, t2, ec, stack);
		}
	}
	else
	{
		ecFromA(t1, ecPrePtA(pre, 0, ec), ec, stack);
		for (i = 1; i < count; ++i)
		{
			prngCOMBOStepR(r, 1, state);
			if (r[0] & 1)
				ecNegA(t2, ecPrePtA(pre, i, ec), ec, stack);
			else
				wwCopy(t2, ecPrePtA(pre, i, ec), 2 * ec->f->n);
			ecAddA(t1, t1, t2, ec, stack);
		}
	}
	return ecToA(a, t1, ec, stack);
}

static size_t ecPreChecksum_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecPreChecksum_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Тестирование на заданной кривой
*******************************************************************************
*/

static bool_t ecpTestEc(const ec_o* ec)
{
	// размерности
	const size_t n = ec->f->n;
	const size_t min_w = 1;
	const size_t max_w = 6;
	const size_t max_pre_count = SIZE_BIT_POS(max_w - 1) + 1;
	// состояние
	void* state;
	ec_pre_t* pre;	/* [max_pre_count проективных точек] */
	word* pt0;		/* [ec->d * n] */
	word* pt1;		/* [ec->d * n] */
	word* d;		/* [n + 1] */
	void* stack;
	// другие переменные
	size_t w;
	// создать состояние
	state = blobCreate2(
		sizeof(ec_pre_t) + O_OF_W(max_pre_count * ec->d * n),
		O_OF_W(ec->d * n),
		O_OF_W(ec->d * n),
		O_OF_W(n + 1),
		utilMax(17,
			ec->deep,
			ecpIsValid_deep(n, ec->f->deep),
			ecpGroupSeemsValid_deep(n, ec->f->deep),
			ecpGroupIsSafe_deep(n),
			ecpIsOnA_deep(n, ec->f->deep),
			ecpAddAA_deep(n, ec->f->deep),
			ecpSubAA_deep(n, ec->f->deep),
			ecMulA_deep(n, ec->d, ec->deep, n),
			ecPreSO_deep(n, ec->d, ec->deep),
			ecpPreSOJ_deep(n, ec->f->deep),
			ecpSmallMultJ_deep(n, ec->f->deep, max_w),
			ecPreSOA_deep(n, ec->d, ec->deep),
			ecpPreSOA_deep(n, ec->f->deep, max_w),
			ecpSmallMultA_deep(n, ec->f->deep, max_w),
			ecPreSH_deep(ec->deep),
			ecpPreSHJ_deep(n, ec->f->deep, ec->deep),
			ecPreChecksum_deep(n, ec->d, ec->f->deep)),
		SIZE_MAX,
		&pre, &pt0, &pt1, &d, &stack);
	if (state == 0)
		return FALSE;
	// корректная кривая?
	// корректная группа?
	// надежная группа?
	if (!ecpIsValid(ec, stack) ||
		!ecpGroupSeemsValid(ec, stack) ||
		!ecpGroupIsSafe(ec, 40, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// утроить базовую точку разными способами
	{
		// d <- 3
		d[0] = 3;
		// удвоить и сложить
		if (!ecpIsOnA(ec->base, ec, stack) ||
			!ecpAddAA(pt0, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pt0, pt0, ec->base, ec, stack) ||
		// дважды удвоить и вычесть
			!ecpAddAA(pt1, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pt1, pt1, pt1, ec, stack) ||
			!ecpSubAA(pt1, pt1, ec->base, ec, stack) ||
			!wwEq(pt0, pt1, 2 * n) ||
			(ecpNegA(pt1, pt1, ec), ecpAddAA(pt1, pt0, pt1, ec, stack)) ||
		// вычислить кратную точку
			!ecMulA(pt1, ec->base, ec, d, 1, stack) ||
			!wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// предвычисления: схема SO
	for (w = min_w; w <= max_w; ++w)
	{
		const u32 seed = 23;
		bool_t is_zero;
		// эталонная контрольная сумма
		ecPreSO(pre, ec->base, w, ec, stack);
		is_zero = ecPreChecksum(pt0, pre, seed, ec, stack);
		// проверить ecpPreSO()
		ecpPreSOJ(pre, ec->base, w, ec, stack);
		if (ecPreChecksum(pt1, pre, seed, ec, stack) != is_zero ||
			!is_zero && !wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// проверить ecpSmallMultJ()
		if (w < 3)
			continue;
		ecpSmallMultJ(pre, ec->base, w, ec, stack);
		if (ecPreChecksum(pt1, pre, seed, ec, stack) != is_zero ||
			!is_zero && !wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// предвычисления: схема SOA
	for (w = min_w; w <= max_w; ++w)
	{
		const u32 seed = 34;
		bool_t is_zero;
		// эталонная контрольная сумма
		ecPreSOA(pre, ec->base, w, ec, stack);
		is_zero = ecPreChecksum(pt0, pre, seed, ec, stack);
		// проверить ecpPreSOA()
		ecpPreSOA(pre, ec->base, w, ec, stack);
		if (ecPreChecksum(pt1, pre, seed, ec, stack) != is_zero ||
			!is_zero && !wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// проверить ecpSmallMultA()
		if (w < 3)
			continue;
		ecpSmallMultA(pre, ec->base, w, ec, stack);
		if (ecPreChecksum(pt1, pre, seed, ec, stack) != is_zero ||
			!is_zero && !wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// предвычисления: схема SH
	for (w = min_w; w <= max_w; ++w)
	{
		const u32 seed = 43;
		bool_t is_zero;
		// эталонная контрольная сумма
		ecPreSH(pre, ec->base, w, ec, stack);
		is_zero = ecPreChecksum(pt0, pre, seed, ec, stack);
		// проверить ecpPreSOA()
		ecpPreSHJ(pre, ec->base, w, ec, stack);
		if (ecPreChecksum(pt1, pre, seed, ec, stack) != is_zero ||
			!is_zero && !wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// все хорошо
	blobClose(state);
	return TRUE;
}

/*
*******************************************************************************
Тестирование на кривой bign-curve256v1
*******************************************************************************
*/

bool_t ecpTest()
{
	bool_t ret;
	bign_params params[1];
	ec_o* ec;
	// создать кривую
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignEcCreate(&ec, params) != ERR_OK)
		return FALSE;
	// оценка
	ret = ecpTestEc(ec);
	// завершение
	bignEcClose(ec);
	return ret;
}
