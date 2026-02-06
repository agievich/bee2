/*
*******************************************************************************
\file ecp_pre.c
\brief Elliptic curves over prime fields: precomputations
\project bee2 [cryptographic library]
\created 2021.07.18
\version 2026.02.06
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/util.h"
#include "bee2/math/ecp.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

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
Предвычисления: схема SNZ

Реализован алгоритм SmallMultJ, предложенный в [APS22]. Алгоритм основан на
многочленах деления и требует примерно 19/2 M + 7/2 S операций на каждую
кратную точку.

Алгоритм выполняется в 3 этапа. Этапам соответствуют следующие шаги алгоритма:
- этап 1 -- шаги 1 -- 16;
- этап 2 -- шаги 17, 18, 20;
- этап 3 -- шаги 19, 21.

Для повышения читабельности используются макросы, которые покрывают следующие
переменные алгоритма:
1. W(i) -- значения многочленов Wᵢ, i=3,4,...,2ʷ+1:
	* память: 2ʷ-1 (элементов поля);
	* вычисляются на этапах 1 и 2, используются на этапах 1--3;
	* кэшируются все значения.
2. W2(i) --	квадраты Wᵢ², i=3,4...,2ʷ:
	* память: 2ʷ-2.
3. WW(i) -- произведения WᵢWᵢ₊₂, i=1,3...,2ʷ⁻¹:
	* память: 2;
	* вычисляются на этапах 1 и 2, используются на этапах 1--3;
	* кэшируются все значения.
4. WWy2(i) -- произведения (2y)²WᵢWᵢ₊₂, i=3,5,...,2ʷ⁻¹+1:
	* память: 2;
	* вычисляются и используются на этапах 1 и 2;
	* можно хранить только 2 последовательных значения.
5. WWy4(i) -- произведения (2y)⁴WᵢWᵢ₊₂, i=3,5,...,2ʷ⁻¹-1:
	* память: 1;
	* вычисляются и используются на этапах 1 и 2;
	* можно хранить только текущее значение.
6. WWW(i) -- выражения Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁², i=3,4,...,2ʷ⁻¹:
	* память: 2ʷ⁻¹-2;
	* вычисляются на этапах 1 и 2, используются на этапах 1--3;
	* кэшируются все значения.

[APS22]    Agievich S., Poruchnik S., Semenov V. Small scalar multiplication
		   on Weierstrass curves using division polynomials. Mat. Vopr.
		   Kriptogr., 13:2, 2022, https://doi.org/10.4213/mvk406.
*******************************************************************************
*/

#define ecpPreSNZ_local(n, w)\
/* t1 */		O_OF_W(n),\
/* t2 */		O_OF_W(n),\
/* dy2 */		O_OF_W(n),\
/* Ws */		O_OF_W((SIZE_BIT_POS(w) - 1) * n),\
/* W2s */		O_OF_W((SIZE_BIT_POS(w) - 2) * n),\
/* WWs */		O_OF_W(2 * n),\
/* WWy2s */		O_OF_W(2 * n),\
/* WWy4s */		O_OF_W(n),\
/* WWWs */		O_OF_W((SIZE_BIT_POS(w - 1) - 2) * n)

void ecpPreSNZ(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack) 
{
	size_t n;
	word* t1;				/* [n] */
	word* t2;				/* [n] */
	word* dy2;				/* [n] (2y)² */
	word* Ws;				/* [(2^w - 1) * n] Wᵢ */
	word* W2s;				/* [(2^w - 2) * n] Wᵢ² */
	word* WWs;				/* [2 * n] WᵢWᵢ₊₂ */
	word* WWy2s;			/* [2 * n] (2y)²WᵢWᵢ₊₂ */
	word* WWy4s;			/* [n] (2y)⁴WᵢWᵢ₊₂ */
	word* WWWs;				/* [(2^{w-1} - 2) * n] Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁² */
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
		ecpPreSNZ_local(n, w), SIZE_0, SIZE_MAX,
		&t1, &t2, &dy2, &Ws, &W2s, &WWs, &WWy2s, &WWy4s, &WWWs, &stack);
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
		word* x2 = WWs;
		word* bx = x2 + n;
		word* a2 = bx + n;
		// (x2, bx, a2) <- (x², b x, A²)
		qrSqr(x2, ecX(a), ec->f, stack);
		qrMul(bx, ec->B, ecX(a), ec->f, stack);
		qrSqr(a2, ec->A, ec->f, stack);
		// [W₃] <- 3(x²+A)² − 4(a²−3Bx)
		qrAdd(t1, x2, ec->A, ec->f);			// x²+A
		qrSqr(t1, t1, ec->f, stack);			// (x²+A)²
		gfpDouble(t2, t1, ec->f);				// 2(x²+A)²
		qrAdd(W(3), t1, t2, ec->f);				// 3(x²+A)²
		gfpDouble(t1, bx, ec->f);				// 2Bx
		qrAdd(t1, t1, bx, ec->f);				// 3Bx
		qrSub(t1, a2, t1, ec->f);				// A²−3Bx
		gfpDouble(t1, t1, ec->f);				// 2(A²−3Bx)
		gfpDouble(t1, t1, ec->f);				// 4(A²−3Bx)
		qrSub(W(3), W(3), t1, ec->f);
		// [W₄] <- 4Bx(5x²-A)
		gfpDouble(t1, x2, ec->f);				// 2x²
		gfpDouble(t1, t1, ec->f);				// 4x²
		qrAdd(t1, t1, x2, ec->f);				// 5x²
		qrSub(t1, t1, ec->A, ec->f);			// 5x²-A
		qrMul(t1, bx, t1, ec->f, stack);		// Bx(5x²-A)
		gfpDouble(t1, t1, ec->f);				// 2Bx(5x²-A)
		gfpDouble(W(4), t1, ec->f);				// 4Bx(5x²-A)
		// [W₄] <- x⁶+4Bx(5x²-A)
		qrMul(t1, x2, ecX(a), ec->f, stack);
		qrSqr(t2, t1, ec->f, stack);
		qrAdd(W(4), t2, W(4), ec->f);
		// [W₄] <- x⁶+4Bx(5x²-A)+5Ax(x³-Ax)
		qrMul(t2, ec->A, ecX(a), ec->f, stack);	// Ax
		qrSub(t1, t1, t2, ec->f);				// x³-Ax
		qrMul(t1, t1, t2, ec->f, stack);		// Ax(x³-Ax)
		gfpDouble(t2, t1, ec->f);				// 2Ax(x³-Ax)
		gfpDouble(t2, t2, ec->f);				// 4Ax(x³-Ax)
		qrAdd(t1, t1, t2, ec->f);				// 5Ax(x³-Ax)
		qrAdd(W(4), W(4), t1, ec->f);
		// [W₄] <- x⁶+4Bx(5x²-A)+5Ax(x³-Ax)-8B²
		qrSqr(t1, ec->B, ec->f, stack);			// B²
		gfpDouble(t1, t1, ec->f);				// 2B²
		gfpDouble(t1, t1, ec->f);				// 4B²
		gfpDouble(t1, t1, ec->f);				// 8B²
		qrSub(W(4), W(4), t1, ec->f);
		// [W₄] <- 2(x⁶+4Bx(5x²-A)+5Ax(x³-Ax)-8B²-A³)
		qrMul(t2, a2, ec->A, ec->f, stack);		// A³
		qrSub(W(4), W(4), t2, ec->f);
		gfpDouble(W(4), W(4), ec->f);
	}
	// [W₃²] <- W₃²
	qrSqr(W2(3), W(3), ec->f, stack);
	// [W₁W₃] <- W₃
	qrCopy(WW(1), W(3), ec->f);
	// [W₄²] <- W₄²
	qrSqr(W2(4), W(4), ec->f, stack);
	// [W₂W₄] <- W₄
	qrCopy(WW(2), W(4), ec->f);
	// [(2y)²W₂W₄] <- (2y)² W₂W₄
	qrMul(WWy2(2), dy2, WW(2), ec->f, stack);
	// [(2y)⁴W₂W₄] <- (2y)² (2y)²W₂W₄
	qrMul(WWy4(2), dy2, WWy2(2), ec->f, stack);
	// [W₅] <- (2y)⁴W₂W₄−W₁W₃W₃²
	qrMul(t1, WW(1), W2(3), ec->f, stack);
	qrSub(W(5), WWy4(2), t1, ec->f);
	// [W₅²] <- W₅²
	qrSqr(W2(5), W(5), ec->f, stack);
	// [W₅W₂²−W₁W₄²] <- W₅-W₄²
	qrSub(WWW(3), W(5), W2(4), ec->f);
	// [W₆] <- W₃(W₅W₂²−W₁W₄²)
	qrMul(W(6), W(3), WWW(3), ec->f, stack);
	// [W₆W₃²−W₂W₅²] <- W₆W₃²-W₅²
	qrMul(WWW(4), W(6), W2(3), ec->f, stack);
	qrSub(WWW(4), WWW(4), W2(5), ec->f);

/* SmallMultJ: этап 2 */

	// W₂ᵢ, W₂ᵢ₊₁, Wᵢ₊₂Wᵢ²−Wᵢ₋₂Wᵢ₊₁², WᵢWᵢ₊₂ для i=3,4...,2ʷ⁻¹
	// (Xᵢ:Yᵢ:Zᵢ) для нечетных i
	for (i = 3; i <= SIZE_BIT_POS(w - 1); ++i)
	{
		// [Wᵢ₊₂Wᵢ²−Wᵢ₋₂Wᵢ₊₁²] <- Wᵢ₊₂Wᵢ²−Wᵢ₋₂Wᵢ₊₁²
		if (i >= 5)
		{
			qrMul(WWW(i), W(i + 2), W2(i - 1), ec->f, stack);
			qrMul(t1, W(i - 2), W2(i + 1), ec->f, stack);
			qrSub(WWW(i), WWW(i), t1, ec->f);
		}
		// [W₂ᵢ] <- Wᵢ(Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁²)
		if (i >= 4)
			qrMul(W(2 * i), W(i), WWW(i), ec->f, stack);
		// [W₂ᵢ²] <- W₂ᵢ²
		qrSqr(W2(2 * i), W(2 * i), ec->f, stack);
		// [WᵢWᵢ₊₂] <- ((Wᵢ+Wᵢ₊₂)²-Wᵢ²-Wᵢ₊₂²)/2
		gfpMul2(WW(i), W(i), W(i + 2), W2(i), W2(i + 2), ec->f, stack);
		// W₂ᵢ₊₁, (Xᵢ:Yᵢ:Zᵢ) при нечетном i
		if (i & 1)
		{
			// [W₂ᵢ₊₁] <- WᵢWᵢ₊₂Wᵢ²-(2y)⁴Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
			qrMul(t1, WWy4(i - 1), W2(i + 1), ec->f, stack);
			qrMul(W(2 * i + 1), WW(i), W2(i), ec->f, stack);
			qrSub(W(2 * i + 1), W(2 * i + 1), t1, ec->f);
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
			// [(2y)⁴WᵢWᵢ₊₂] <- (2y)²(2y)²WᵢWᵢ₊₂
			qrMul(WWy4(i), dy2, WWy2(i), ec->f, stack);
			// [W₂ᵢ₊₁] <- (2y)⁴WᵢWᵢ₊₂Wᵢ²-Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
			qrMul(t1, WW(i - 1), W2(i + 1), ec->f, stack);
			qrMul(W(2 * i + 1), WWy4(i), W2(i), ec->f, stack);
			qrSub(W(2 * i + 1), W(2 * i + 1), t1, ec->f);
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

	// (Xᵢ:Yᵢ:Zᵢ) для i=2ʷ⁻¹+1,...,2ʷ-1
	while (1)
	{
		// [Yᵢ] <- y(Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁²)
		qrMul(t1, W(i + 2), W2(i - 1), ec->f, stack);
		qrMul(ecY(pt, n), W(i - 2), W2(i + 1), ec->f, stack);
		qrSub(ecY(pt, n), t1, ecY(pt, n), ec->f);
		qrMul(ecY(pt, n), ecY(a, n), ecY(pt, n), ec->f, stack);
		// [Zᵢ] <- Wᵢ
		wwCopy(ecZ(pt, n), W(i), n);
		// последняя точка?
		if (i == SIZE_BIT_POS(w) - 1)
			break;
		// к следующей точке
		i += 2, pt += 3 * n;
		// [Xᵢ] <- x Wᵢ²−(2y)²Wᵢ₋₁Wᵢ₊₁
		gfpMul2(t1, W(i - 1), W(i + 1), W2(i - 1), W2(i + 1), ec->f, stack);
		qrMul(t1, dy2, t1, ec->f, stack);
		qrMul(ecX(pt), ecX(a), W2(i), ec->f, stack);
		qrSub(ecX(pt), ecX(pt), t1, ec->f);
	}

#undef W
#undef W2
#undef WW
#undef WWy2
#undef WWy4
/* SmallMultJ: end */

	// заполнить служебные поля
	pre->type = ec_pre_snz;
	pre->w = w, pre->h = 0;
}

size_t ecpPreSNZ_deep(size_t n, size_t f_deep, size_t w)
{
	return memSliceSize(
		ecpPreSNZ_local(n, w),
		f_deep,
		SIZE_MAX);
}
