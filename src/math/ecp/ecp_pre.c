/*
*******************************************************************************
\file ecp_pre.c
\brief Elliptic curves over prime fields: precomputations
\project bee2 [cryptographic library]
\created 2021.07.18
\version 2026.02.04
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

Реализован алгоритм, предложенный в [APS22]. Алгоритм основан на многочленах
деления и требует примерно 11/2 M + 7/2 S операций для каждой кратной точки.

[APS22]    Agievich S., Poruchnik S., Semenov V. Small scalar multiplication
		   on Weierstrass curves using division polynomials. Mat. Vopr.
		   Kriptogr., 13:2, 2022, https://doi.org/10.4213/mvk406.
*******************************************************************************
*/

#define stack_walloc(p, k)				\
	do {								\
		(p) = (word*)(stack);			\
		stack = (word*)(stack) + (k);	\
	} while(0)
#define stack_wfree(p)

void ecpPreSNZ(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack) 
{
	// размер координаты
	const size_t n = ec->f->n;
	// размер якобиевой точки
	const size_t nj = n * ec->d;
	// координата x базовой точки
	const word* x = ecX(a);
	// координата y базовой точки
	const word* y = ecY(a, n);

	size_t i;

	// Основные этапы алгоритма:
	// 0) Wᵢ, i=3,4,5
	// 1) for i=3,4..2ʷ⁻¹
	// 3*) for i=3,5..2ʷ⁻¹-1
	// 3) for i=3,5..2ʷ⁻¹+1
	// 4) for i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1
	// 4*) for i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1
	//
	// Таблица. Подвыражения на этапах.
	// Подвыражение    | 0)       | 1)                | 3)         | 4)                 |
	// ----------------------------------------------------------------------------------
	// Wᵢ              | W[3,4,5] | R[i,i+2,2i+1]     | R[*2i]     | R[*i-1,i,*i+1,i+2] |
	//                 |          | W[2i,2i+1]        |            |                    |
	// Wᵢ²             | W[3,4,5] | R[i-1,i,i+1,'i+2] |            | R[i-1,'i,i+1,'i+2] |
	//                 |          | W[2i,2i+1]        |            |                    |
	// Wᵢ₋₁ Wᵢ₊₁       | W[2,3]   | W[i+1]            |            | R[i-1], W[i+1]     |
	//                 |          | R[i-1,i(e),i+1]   |            |                    |
	// (2y)² Wᵢ₋₁ Wᵢ₊₁ | W[3]     | W[i(e)+1]         | R[i]       |                    |
	// (2y)⁴ Wᵢ₋₁ Wᵢ₊₁ | W[3]     | R[i(o)]           |            |                    |
	//                 |          | WR[i(e)+1]        |            |                    |
	//

	// Выделяемая память
	word* tmp;
	word* tmp2;
	// 2y
	word* dy;
	// (2y)²
	word* dy2;
	// полиномы деления: Wᵢ, i=3,4..(2ʷ+1)
	// этапы: 0), 1), 3), 4)
	// память: 2ʷ-1
	// Значения расчитываются на этапе 1) по индексам 2i и 2i+1.
	// На этапе 1) значения считываются последовательно, по индексам i, i+2.
	// На этапе 3) значения считываются по чётным индексам 2i.
	// На этапе 4) значения считываются последовательно, по индексам i-1,i,i+1,i+2.
	// Упростить кэширование не получается - необходимо выделять память под все значения.
	word* pW;
#define W(i) (pW + ((i)-3) * n)
	// квадраты: Wᵢ², i=3,4..2ʷ
	// этапы: 2), 3), 4)
	// память: 2ʷ-2[+1]
	// Квадраты с нечётными индексами сгруппированы вместе для упрощения их обращения.
	// Квадраты по чётным индексам: W₂ᵢ², i=2,3..2ʷ⁻¹, - выделяются в pW2[0].
	// Квадраты по нечётным индексам: W₂ᵢ₋₁², i=2,3..2ʷ⁻¹, - выделяются в pw2[1].
	word* pW2[2];
#define W2(i) (pW2[(i)&1] + (((i)-3)>>1) * n)
	// произведения: Wᵢ₋₁ Wᵢ₊₁, i=2,3..2ʷ⁻¹+1
	// этапы: 0), 1), 4)
	// память: 3
	// На этапе 1) значения формируются и используются последовательно с индексами i-1,i,i+1,
	// поэтому можно выделять память лишь под 3 текущие значения.
	// На этапе 4) происходит чтение по индексу i-1, и запись по индексу i+1, поэтому
	// память можно выделять только под 1 значение.
	// Макрос WW(i) имеет вид (i+D)%3, где D - константа.
	// D выбрано как 2ʷ, чтобы WW(2ʷ⁻¹)=[(2ʷ⁻¹(1+2))%3]=0.
	// Макрос WW переопределен перед этапом 4) так, чтобы WW(i)=0.
	word* pWW;
#define WW(i) (pWW + (((i) + (SIZE_1 << w))%3) * n)
	// произведения: (2y)² Wᵢ₋₁ Wᵢ₊₁, i=3,5..2ʷ⁻¹+1
	// этапы: 0), 1), 3)
	// память: 2ʷ⁻²
	// Значения формируются на этапах 0), 1), чтение - на этапе 3). Кэшировать нужно все значения.
	word* pWW2;
#define WWy2(i) (pWW2 + (((i)-3) >> 1) * n)
	// текущее произведение: (2y)⁴ Wᵢ₋₁ Wᵢ₊₁, i=3,5..(2ʷ⁻¹-1)
	// этапы: 0), 1)
	// память: 1
	// Запись на пред. шаге, чтение на текущем. Кэшировать можно только одно текущее значение.
	word* pWW4;
#define WWy4(i) (pWW4)

	// выходной буфер
	word* c;

	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(w > 0);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(ec->d * ec->f->n * (SIZE_1 << (w - 1))),
		a, O_OF_W(2 * ec->f->n)));

	// разметить стек
	stack_walloc(dy2, n);
	stack_walloc(tmp, n);
	stack_walloc(tmp2, n);
	stack_walloc(pW, n * ((SIZE_1 << w) - 1));
	stack_walloc(pW2[0], n * ((SIZE_1 << (w-1)) - 1));
	stack_walloc(pW2[1], n * ((SIZE_1 << (w-1)) - 1));
	stack_walloc(pWW, n * 3);
	stack_walloc(pWW2, n * (SIZE_1 << (w-2)));
	stack_walloc(pWW4, n);
	dy = dy2;

	// Этап 0)

	// [(2y)²]
	gfpDouble(dy, y, ec->f);
	qrSqr(dy2, dy, ec->f, stack);

	{
		// вспомогательные значения
		word* xx;
		word* bx;
		word* aa;

		xx = pWW;
		bx = xx + n;
		aa = bx + n;

		qrSqr(xx, x, ec->f, stack);			// x ²
		qrMul(bx, ec->B, x, ec->f, stack);	// b x
		qrSqr(aa, ec->A, ec->f, stack);		// a ²

		// [W₃]
		{
			qrAdd(tmp, xx, ec->A, ec->f);	// x² + a
			qrSqr(tmp, tmp, ec->f, stack);	// (x²+a) ²
			gfpDouble(tmp2, tmp, ec->f);	// 2 (x²+a)²
			qrAdd(W(3), tmp, tmp2, ec->f);	// 3 (x²+a)²

			gfpDouble(tmp, bx, ec->f);		// 2 bx
			qrAdd(tmp, tmp, bx, ec->f);		// 3 bx
			qrSub(tmp, aa, tmp, ec->f);		// a² − 3bx
			gfpDouble(tmp, tmp, ec->f);		// 2 (a²−3bx)
			gfpDouble(tmp, tmp, ec->f);		// 4 (a²−3bx)

			qrSub(W(3), W(3), tmp, ec->f);	// W₃ = 3(x²+a)² − 4(a²−3bx)
		}

		// [W₄]
		{
			word* u = W(4);
			gfpDouble(tmp, xx, ec->f);				// 2 x²
			gfpDouble(tmp, tmp, ec->f);				// 4 x²
			qrAdd(tmp, tmp, xx, ec->f);				// 5 x²
			qrSub(tmp, tmp, ec->A, ec->f);			// 5x² - a
			qrMul(tmp, bx, tmp, ec->f, stack);		// bx (5x²-a)
			gfpDouble(tmp, tmp, ec->f);				// 2 bx(5x²-a)
			gfpDouble(W(4), tmp, ec->f);			// 4 bx(5x²-a)

			qrMul(tmp, xx, x, ec->f, stack);		// x³
			qrSqr(tmp2, tmp, ec->f, stack);			// x⁶
			qrAdd(W(4), tmp2, W(4), ec->f);			// x⁶ + 4bx(5x²-a)

			qrMul(tmp2, ec->A, x, ec->f, stack);	// a x
			qrSub(tmp, tmp, tmp2, ec->f);			// x³ - ax
			qrMul(tmp, tmp, tmp2, ec->f, stack);	// ax (x³-ax)
			gfpDouble(tmp2, tmp, ec->f);			// 2 ax(x³-ax)
			gfpDouble(tmp2, tmp2, ec->f);			// 4 ax(x³-ax)
			qrAdd(tmp, tmp, tmp2, ec->f);			// 5 ax(x³-ax)
			qrAdd(W(4), W(4), tmp, ec->f);			// x⁶+4bx(5x²-a) + 5ax(x³-ax)

			qrSqr(tmp, ec->B, ec->f, stack);		// b ²
			gfpDouble(tmp, tmp, ec->f);				// 2 b²
			gfpDouble(tmp, tmp, ec->f);				// 4 b²
			gfpDouble(tmp, tmp, ec->f);				// 8 b²
			qrSub(W(4), W(4), tmp, ec->f);			// x⁶+4bx(5x²-a)+5ax(x³-ax) - 8b²

			qrMul(tmp2, aa, ec->A, ec->f, stack);	// a² a
			qrSub(u, W(4), tmp2, ec->f);			// W₄/2 = x⁶+4bx(5x²-a)+5ax(x³-ax)-8b² - a³

			gfpDouble(W(4), u, ec->f);				// W₄ = 2 (x⁶+4bx(5x²-a)+5ax(x³-ax)-8b²-a³)
		}
	}
	// [W₃²], [W₁W₃], [W₄²], [W₂W₄], [(2y)²W₂W₄], [(2y)⁴W₂W₄]
	qrSqr(W2(3), W(3), ec->f, stack);			// W₃²
	qrCopy(WW(2), W(3), ec->f);					// W₁W₃ = W₃
	qrSqr(W2(4), W(4), ec->f, stack);			// W₄²
	qrCopy(WW(3), W(4), ec->f);					// W₂W₄ = W₄
	qrMul(WWy2(3), dy2, WW(3), ec->f, stack);	// (2y)² W₂W₄
	qrMul(WWy4(3), dy2, WWy2(3), ec->f, stack);	// (2y)² (2y)²W₂W₄

	// [W₅], [W₅²]
	{
		qrMul(tmp, WW(2), W2(3), ec->f, stack);		// W₁W₃ W₃²
		qrSub(W(5), WWy4(3), tmp, ec->f);			// W₅ = (2y)⁴W₂W₄ − W₁W₃W₃²
		if (w > 2)
			qrSqr(W2(5), W(5), ec->f, stack);			// W₅ ²
	}

	// Этап 1)
	// для i=3,4..2ʷ⁻¹: [W₂ᵢ], [W₂ᵢ₊₁], [Wᵢ Wᵢ₊₂]
	for (i = 3; i <= SIZE_1 << (w - 1); ++i)
	{
		// [WᵢWᵢ₊₂] = ((Wᵢ + Wᵢ₊₂) ² - Wᵢ² - Wᵢ₊₂²) / 2
		gfpMul2(WW(i+1), W(i), W(i+2), W2(i), W2(i+2), ec->f, stack);

		// [W₂ᵢ]
		if (i == 3)
		{
			qrMul(tmp, WW(i-1), W2(i+1), ec->f, stack);		// (W₁W₃) W₄²
			qrSub(W(2*i), WW(i+1), tmp, ec->f);				// W₆ = W₃W₅ - W₁W₃W₄²
		}
		else
		{
			qrMul(tmp, WW(i-1), W2(i+1), ec->f, stack);		// (Wᵢ₋₂Wᵢ) Wᵢ₊₁²
			qrMul(W(2*i), WW(i+1), W2(i-1), ec->f, stack);	// (WᵢWᵢ₊₂) Wᵢ₋₁²
			qrSub(W(2*i), W(2*i), tmp, ec->f);				// W₂ᵢ = (WᵢWᵢ₊₂)Wᵢ₋₁² - (Wᵢ₋₂Wᵢ)Wᵢ₊₁²
		}

		// [W₂ᵢ²]
		qrSqr(W2(2*i), W(2*i), ec->f, stack);				// W₂ᵢ ²

		// [W₂ᵢ₊₁]
		if ((i & 1) == 1)
		{
			qrMul(tmp, WWy4(i), W2(i+1), ec->f, stack);		// (2y)⁴Wᵢ₋₁Wᵢ₊₁ Wᵢ₊₁²
			qrMul(W(2*i+1), WW(i+1), W2(i), ec->f, stack);	// WᵢWᵢ₊₂ Wᵢ²
			qrSub(W(2*i+1), W(2*i+1), tmp, ec->f);			// W₂ᵢ₊₁ = WᵢWᵢ₊₂Wᵢ² - (2y)⁴Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
 		}
		else
		{
			// [(2y)²WᵢWᵢ₊₂]
			qrMul(WWy2(i+1), dy2, WW(i+1), ec->f, stack);	// (2y)² WᵢWᵢ₊₂
			// [(2y)⁴WᵢWᵢ₊₂]
			qrMul(WWy4(i+1), dy2, WWy2(i+1), ec->f, stack);	// (2y)² (2y)²WᵢWᵢ₊₂
			qrMul(tmp, WW(i), W2(i+1), ec->f, stack);		// Wᵢ₋₁Wᵢ₊₁ Wᵢ₊₁²
			qrMul(W(2*i+1), WWy4(i+1), W2(i), ec->f, stack);	// (2y)⁴WᵢWᵢ₊₂ Wᵢ²
			qrSub(W(2*i+1), W(2*i+1), tmp, ec->f);			// W₂ᵢ₊₁ = (2y)⁴WᵢWᵢ₊₂Wᵢ² - Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
		}

		if (i != SIZE_1 << (w - 1))
		{
			// [W₂ᵢ₊₁²]
			qrSqr(W2(2 * i + 1), W(2 * i + 1), ec->f, stack);		// W₂ᵢ₊₁ ²
		}
	}

	// [1]P
	c = pre->pts;
	ecFromA(c, a, ec, stack);
	c += nj;

	// Этап 3)
	for (i = 3;;)
	{
		// i=3,5..2ʷ⁻¹+1: [Xᵢ] = x Wᵢ² − (2y)²Wᵢ₋₁Wᵢ₊₁
		qrMul(ecX(c), x, W2(i), ec->f, stack);
		qrSub(ecX(c), ecX(c), WWy2(i), ec->f);

		if (i == (SIZE_1 << (w - 1)) + 1) break;

		// i=3,5..2ʷ⁻¹-1: [Yᵢ] = y (Wᵢ₊₂ Wᵢ₋₁² - Wᵢ₋₂ Wᵢ₊₁²)
		if (i < 4)
			wwCopy(tmp, W(i+2), n);
		else
			qrMul(tmp, W(i+2), W2(i-1), ec->f, stack);
		if (i < 5)
			wwCopy(ecY(c, n), W2(i+1), n);
		else
			qrMul(ecY(c, n), W(i-2), W2(i+1), ec->f, stack);
		qrSub(ecY(c, n), tmp, ecY(c, n), ec->f);
		qrMul(ecY(c, n), y, ecY(c, n), ec->f, stack);
		// [Zᵢ] = Wᵢ
		wwCopy(ecZ(c, n), W(i), n);

		i += 2, c += nj;
	}
	// Этап 4)
#undef WW
#define WW(i) (pWW)
	for (; i <= (SIZE_1 << w) - 1;)
	{
		// i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1: [Yᵢ] = y (Wᵢ₊₂ Wᵢ₋₁² - Wᵢ₋₂ Wᵢ₊₁²)
		if (i < 4)
			wwCopy(tmp, W(i+2), n);
		else
			qrMul(tmp, W(i+2), W2(i-1), ec->f, stack);
		if (i < 5)
			wwCopy(ecY(c, n), W2(i+1), n);
		else
			qrMul(ecY(c, n), W(i-2), W2(i+1), ec->f, stack);

		qrSub(ecY(c, n), tmp, ecY(c, n), ec->f);
		qrMul(ecY(c, n), y, ecY(c, n), ec->f, stack);
		// [Zᵢ] = Wᵢ
		wwCopy(ecZ(c, n), W(i), n);

		if (i == (SIZE_1 << w) - 1) break;
		i += 2, c += nj;

		// i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1: [Xᵢ] = x Wᵢ² − (2y)² Wᵢ₋₁ Wᵢ₊₁
		gfpMul2(tmp, W(i-1), W(i+1), W2(i-1), W2(i+1), ec->f, stack);		// Wᵢ₋₁ Wᵢ₊₁
		qrMul(tmp, dy2, tmp, ec->f, stack);									// (2y)² Wᵢ₋₁Wᵢ₊₁
		qrMul(ecX(c), x, W2(i), ec->f, stack);								// x Wᵢ²
		qrSub(ecX(c), ecX(c), tmp, ec->f);									// x Wᵢ² − (2y)²Wᵢ₋₁Wᵢ₊₁
	}

	stack_wfree(pWW4);
	stack_wfree(pWW2);
	stack_wfree(pWW);
	stack_wfree(pW2[1]);
	stack_wfree(pW2[0]);
	stack_wfree(pW);
	stack_wfree(tmp2);
	stack_wfree(tmp);
	stack_wfree(dy2);

#undef W
#undef W2
#undef WW
#undef WWy2
#undef WWy4

	// заполнить остальные поля
	pre->type = ec_pre_snza;
	pre->w = w, pre->h = 0;
}

size_t ecpPreSNZ_deep(size_t n, size_t f_deep, size_t w)
{
	size_t const ww = SIZE_1 << w;
	size_t r = n * (0
		+ 1						// dy2
		+ 1						// tmp
		+ 1						// tmp2
		+ (ww - 1)				// pW
		+ (ww/2 - 1)			// pW2[0]
		+ (ww/2 - 1)			// pW2[1]
		+ 3						// pWW
		+ ww/4					// pWW2
		+ 1						// pWW4
		);
	return O_OF_W(r) + f_deep;
}

#undef stack_walloc
#undef stack_wfree
