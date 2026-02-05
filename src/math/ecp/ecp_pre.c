/*
*******************************************************************************
\file ecp_pre.c
\brief Elliptic curves over prime fields: precomputations
\project bee2 [cryptographic library]
\created 2021.07.18
\version 2026.02.05
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
Вспомогательные макросы
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

Алгоритм выполняется в 4 этапа. Этапам соответствуют следующие шаги алгоритма:
- этап 1 -- шаги 1 -- 13;
- этап 2 -- шаги 14 -- 16;
- этап 3 -- шаги 17, 19;
- этап 4 -- шаги 18, 20.

Для повышения читабельности используются макросы, которые покрывают следующие
переменные алгоритма:
1. W(i) -- значения многочленов Wᵢ, i=3,4,...,2ʷ+1:
	* этапы: 0), 1), 3), 4);
	* память: 2ʷ-1 (элементов поля);
	* значения рассчитываются на этапе 2 по индексам 2i и 2i+1.
	* на этапе 1) значения считываются последовательно, по индексам i, i+2;
	* на этапе 3) значения считываются по чётным индексам 2i;
	* на этапе 4) значения считываются последовательно, по индексам
	  i-1,i,i+1,i+2;
	* упростить кэширование не получается -- необходимо выделять память под
	  все значения.
2. W2(i) --	квадраты Wᵢ², i=3,4...,2ʷ:
	* этапы: 2), 3), 4);
	* память: 2ʷ-2.
3. WW(i) -- произведения Wᵢ₋₁ Wᵢ₊₁, i=2,3...,2ʷ⁻¹+1:
	* этапы: 0), 1), 4);
	* память: 3;
	* на этапе 1) значения формируются и используются последовательно
	  с индексами i-1,i,i+1 и поэтому можно выделять память лишь под 3 текущие
	  значения;
	* на этапе 4) происходит чтение по индексу i-1 и запись по индексу i+1,
	  поэтому память можно выделять только под 1 значение.
4. WWy2(i) -- произведения (2y)² Wᵢ₋₁ Wᵢ₊₁, i=3,5,...,2ʷ⁻¹+1:
	* этапы: 0), 1), 3);
	* память: 2ʷ⁻²;
	* значения формируются на этапах 0), 1), чтение -- на этапе 3). Кэшировать
	* нужно все значения.
5. WWy4(i) -- текущее произведение (2y)⁴ Wᵢ₋₁ Wᵢ₊₁, i=3,5,...,2ʷ⁻¹-1:
	* этапы: 0), 1);
	* память: 1;
	* запись на предыдущем шаге, чтение на текущем. Кэшируется только текущее
	  значение.

[APS22]    Agievich S., Poruchnik S., Semenov V. Small scalar multiplication
		   on Weierstrass curves using division polynomials. Mat. Vopr.
		   Kriptogr., 13:2, 2022, https://doi.org/10.4213/mvk406.

\todo Разобраться с шагом 15 SmallMultJ: на этом шаге значение W6 еще не
вычислено.
*******************************************************************************
*/

#define ecpPreSNZ_local(n, w)\
/* t1 */		O_OF_W(n),\
/* t2 */		O_OF_W(n),\
/* dy2 */		O_OF_W(n),\
/* pW */		O_OF_W((SIZE_BIT_POS(w) - 1) * n),\
/* pW2 */		O_OF_W((SIZE_BIT_POS(w) - 2) * n),\
/* pWW */		O_OF_W(3 * n),\
/* pWW2 */		O_OF_W(SIZE_BIT_POS(w - 2) * n),\
/* pWW4 */		O_OF_W(n)

void ecpPreSNZ(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack) 
{
	size_t n;
	word* t1;				/* [n] */
	word* t2;				/* [n] */
	word* dy2;				/* [n] (2y)² */
	word* pW;				/* [(2^w - 1) * n] Wᵢ */
	word* pW2;				/* [2 * (2^{w-1} - 1) * n] Wᵢ² */
	word* pWW;				/* [3 * n] Wᵢ₋₁ Wᵢ₊₁ */
	word* pWWy2;			/* [2^{w-2} * n] (2y)² Wᵢ₋₁ Wᵢ₊₁ */
	word* pWWy4;			/* [n] (2y)² Wᵢ₋₁ Wᵢ₊₁ */
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
		&t1, &t2, &dy2, &pW, &pW2, &pWW, &pWWy2, &pWWy4, &stack);
	// первая точка
	pt = pre->pts;
	ecFromA(pt, a, ec, stack);
	pt += 3 * n;

/*** SmallMultJ: этап 1 ***/

#define W(i) (pW + ((i) - 3) * n)
#define W2(i) (pW2 + ((i) - 3) * n)
#define WW(i) (pWW + ((i) % 3) * n)
#define WWy2(i) (pWWy2 + (((i) - 3) >> 1) * n)
#define WWy4(i) (pWWy4)

	// dy2 <- (2y)²
	gfpDouble(dy2, ecY(a, n), ec->f);
	qrSqr(dy2, dy2, ec->f, stack);
	// [W₃], [W₄]
	{
		word* x2 = pWW;
		word* bx = x2 + n;
		word* a2 = bx + n;
		// (x2, bx, a2) <- (x², b x, A²)
		qrSqr(x2, ecX(a), ec->f, stack);
		qrMul(bx, ec->B, ecX(a), ec->f, stack);
		qrSqr(a2, ec->A, ec->f, stack);
		// [W₃]
		{
			// [W₃] <- 3(x²+A)²
			qrAdd(t1, x2, ec->A, ec->f);	// x²+A
			qrSqr(t1, t1, ec->f, stack);	// (x²+A)²
			gfpDouble(t2, t1, ec->f);		// 2(x²+A)²
			qrAdd(W(3), t1, t2, ec->f);		// 3(x²+A)²
			// [W₃] <- 3(x²+A)² − 4(a²−3Bx)
			gfpDouble(t1, bx, ec->f);		// 2Bx
			qrAdd(t1, t1, bx, ec->f);		// 3Bx
			qrSub(t1, a2, t1, ec->f);		// A²−3Bx
			gfpDouble(t1, t1, ec->f);		// 2(A²−3Bx)
			gfpDouble(t1, t1, ec->f);		// 4(A²−3Bx)
			qrSub(W(3), W(3), t1, ec->f);
		}
		// [W₄]
		{
			// [W₄] <- 4Bx(5x²-A)
			gfpDouble(t1, x2, ec->f);				// 2x²
			gfpDouble(t1, t1, ec->f);				// 4x²
			qrAdd(t1, t1, x2, ec->f);				// 5x²
			qrSub(t1, t1, ec->A, ec->f);			// 5x²-A
			qrMul(t1, bx, t1, ec->f, stack);		// Bx(5x²-A)
			gfpDouble(t1, t1, ec->f);				// 2Bx(5x²-A)
			gfpDouble(W(4), t1, ec->f);				// 4Bx(5x²-A)
			// [W₄] <- x⁶ + 4Bx(5x²-A)
			qrMul(t1, x2, ecX(a), ec->f, stack);
			qrSqr(t2, t1, ec->f, stack);
			qrAdd(W(4), t2, W(4), ec->f);
			// [W₄] <- x⁶ + 4Bx(5x²-A) + 5Ax(x³-Ax)
			qrMul(t2, ec->A, ecX(a), ec->f, stack);	// Ax
			qrSub(t1, t1, t2, ec->f);				// x³-Ax
			qrMul(t1, t1, t2, ec->f, stack);		// Ax(x³-Ax)
			gfpDouble(t2, t1, ec->f);				// 2Ax(x³-Ax)
			gfpDouble(t2, t2, ec->f);				// 4Ax(x³-Ax)
			qrAdd(t1, t1, t2, ec->f);				// 5Ax(x³-Ax)
			qrAdd(W(4), W(4), t1, ec->f);
			// [W₄] <- x⁶ + 4Bx(5x²-A) + 5Ax(x³-Ax) - 8B²
			qrSqr(t1, ec->B, ec->f, stack);			// B²
			gfpDouble(t1, t1, ec->f);				// 2B²
			gfpDouble(t1, t1, ec->f);				// 4B²
			gfpDouble(t1, t1, ec->f);				// 8B²
			qrSub(W(4), W(4), t1, ec->f);
			// [W₄] <- 2(x⁶ + 4Bx(5x²-A) + 5Ax(x³-Ax) - 8B² - A³)
			qrMul(t2, a2, ec->A, ec->f, stack);		// A³
			qrSub(W(4), W(4), t2, ec->f);
			gfpDouble(W(4), W(4), ec->f);
		}
	}
	// [W₃²] <- W₃²
	qrSqr(W2(3), W(3), ec->f, stack);
	// [W₁W₃] <- W₃
	qrCopy(WW(2), W(3), ec->f);
	// [W₄²] <- W₄²
	qrSqr(W2(4), W(4), ec->f, stack);
	// [W₂W₄] <- W₄
	qrCopy(WW(3), W(4), ec->f);
	// [(2y)²W₂W₄] <- (2y)²W₂W₄
	qrMul(WWy2(3), dy2, WW(3), ec->f, stack);
	// [(2y)⁴W₂W₄] <- (2y)²(2y)²W₂W₄
	qrMul(WWy4(3), dy2, WWy2(3), ec->f, stack);
	// [W₅] <- (2y)⁴W₂W₄ − W₁W₃W₃²
	qrMul(t1, WW(2), W2(3), ec->f, stack);	// W₁W₃W₃²
	qrSub(W(5), WWy4(3), t1, ec->f);
	// [W₅²] <- W₅²
	qrSqr(W2(5), W(5), ec->f, stack);

/* Этап 2 */

	// [W₂ᵢ], [W₂ᵢ₊₁], [Wᵢ Wᵢ₊₂], i=3,4...,2ʷ⁻¹
	for (i = 3; i <= SIZE_BIT_POS(w - 1); ++i)
	{
		// [WᵢWᵢ₊₂] <- ((Wᵢ + Wᵢ₊₂)² - Wᵢ² - Wᵢ₊₂²) / 2
		gfpMul2(WW(i+1), W(i), W(i+2), W2(i), W2(i+2), ec->f, stack);
		// [W₆] <- W₃W₅ - W₁W₃W₄²
		if (i == 3)
		{
			qrMul(t1, WW(i-1), W2(i+1), ec->f, stack);		// (W₁W₃) W₄²
			qrSub(W(2*i), WW(i+1), t1, ec->f);
		}
		// [W₂ᵢ] <- (WᵢWᵢ₊₂)Wᵢ₋₁² - (Wᵢ₋₂Wᵢ)Wᵢ₊₁²
		else
		{
			qrMul(t1, WW(i-1), W2(i+1), ec->f, stack);		// (Wᵢ₋₂Wᵢ)Wᵢ₊₁²
			qrMul(W(2*i), WW(i+1), W2(i-1), ec->f, stack);	// (WᵢWᵢ₊₂)Wᵢ₋₁²
			qrSub(W(2*i), W(2*i), t1, ec->f);
		}
		// [W₂ᵢ²] <- W₂ᵢ²
		qrSqr(W2(2*i), W(2*i), ec->f, stack);
		// [W₂ᵢ₊₁]
		if (i & 1)
		{
			// [W₂ᵢ₊₁] <- WᵢWᵢ₊₂Wᵢ² - (2y)⁴Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
			qrMul(t1, WWy4(i), W2(i+1), ec->f, stack);	// (2y)⁴Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
			qrMul(W(2*i+1), WW(i+1), W2(i), ec->f, stack);	// WᵢWᵢ₊₂Wᵢ²
			qrSub(W(2*i+1), W(2*i+1), t1, ec->f);
 		}
		else
		{
			// [W₂ᵢ₊₁] <- (2y)² WᵢWᵢ₊₂
			qrMul(WWy2(i+1), dy2, WW(i+1), ec->f, stack);
			// [(2y)⁴WᵢWᵢ₊₂] <- (2y)² (2y)²WᵢWᵢ₊₂
			qrMul(WWy4(i+1), dy2, WWy2(i+1), ec->f, stack);
			// [W₂ᵢ₊₁] <- 2y)⁴WᵢWᵢ₊₂Wᵢ² - Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
			qrMul(t1, WW(i), W2(i+1), ec->f, stack);		// Wᵢ₋₁Wᵢ₊₁ Wᵢ₊₁²
			qrMul(W(2*i+1), WWy4(i+1), W2(i), ec->f, stack);
			qrSub(W(2*i+1), W(2*i+1), t1, ec->f);
		}
		// [W₂ᵢ₊₁²] <- W₂ᵢ₊₁²
		if (i != SIZE_BIT_POS(w - 1))
			qrSqr(W2(2 * i + 1), W(2 * i + 1), ec->f, stack);
	}

/* SmallMultJ: этап 3 */

	for (i = 3;;)
	{
		// [Xᵢ] <- x Wᵢ² − (2y)²Wᵢ₋₁Wᵢ₊₁, i=3,5,...,2ʷ⁻¹+1 
		qrMul(ecX(pt), ecX(a), W2(i), ec->f, stack);
		qrSub(ecX(pt), ecX(pt), WWy2(i), ec->f);
		if (i == SIZE_BIT_POS(w - 1) + 1)
			break;
		// [Yᵢ] <- y(Wᵢ₊₂ Wᵢ₋₁² - Wᵢ₋₂ Wᵢ₊₁²), i=3,5,...,2ʷ⁻¹-1
		if (i < 4)
			wwCopy(t1, W(i + 2), n);
		else
			qrMul(t1, W(i + 2), W2(i - 1), ec->f, stack);
		if (i < 5)
			wwCopy(ecY(pt, n), W2(i + 1), n);
		else
			qrMul(ecY(pt, n), W(i - 2), W2(i + 1), ec->f, stack);
		qrSub(ecY(pt, n), t1, ecY(pt, n), ec->f);
		qrMul(ecY(pt, n), ecY(a, n), ecY(pt, n), ec->f, stack);
		// [Zᵢ] <- Wᵢ
		wwCopy(ecZ(pt, n), W(i), n);
		// к следующей точке
		i += 2, pt += 3 * n;
	}

/* SmallMultJ: этап 4 */

	for (; i <= SIZE_BIT_POS(w) - 1;)
	{
		// [Yᵢ] <- y(Wᵢ₊₂ Wᵢ₋₁² - Wᵢ₋₂ Wᵢ₊₁²), i=2ʷ⁻¹+1,2ʷ⁻¹+3,...,2ʷ-1
		if (i < 4)
			wwCopy(t1, W(i + 2), n);
		else
			qrMul(t1, W(i + 2), W2(i - 1), ec->f, stack);
		if (i < 5)
			wwCopy(ecY(pt, n), W2(i + 1), n);
		else
			qrMul(ecY(pt, n), W(i - 2), W2(i + 1), ec->f, stack);
		qrSub(ecY(pt, n), t1, ecY(pt, n), ec->f);
		qrMul(ecY(pt, n), ecY(a, n), ecY(pt, n), ec->f, stack);
		// [Zᵢ] <- Wᵢ
		wwCopy(ecZ(pt, n), W(i), n);
		// к следующей точке
		if (i == SIZE_BIT_POS(w) - 1)
			break;
		i += 2, pt += 3 * n;
		// [Xᵢ] <- x Wᵢ² − (2y)² Wᵢ₋₁ Wᵢ₊₁, i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1
		gfpMul2(t1, W(i-1), W(i+1), W2(i-1), W2(i+1), ec->f, stack);
		qrMul(t1, dy2, t1, ec->f, stack);					// (2y)² Wᵢ₋₁Wᵢ₊₁
		qrMul(ecX(pt), ecX(a), W2(i), ec->f, stack);		// x Wᵢ²
		qrSub(ecX(pt), ecX(pt), t1, ec->f);
	}

#undef W
#undef W2
#undef WW
#undef WWy2
#undef WWy4

/* SmallMultJ: end */

	// заполнить служебные поля
	pre->type = ec_pre_snza;
	pre->w = w, pre->h = 0;
}

size_t ecpPreSNZ_deep(size_t n, size_t f_deep, size_t w)
{
	return memSliceSize(
		ecpPreSNZ_local(n, w),
		f_deep,
		SIZE_MAX);
}
