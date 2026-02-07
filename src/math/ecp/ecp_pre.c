/*
*******************************************************************************
\file ecp_pre.c
\brief Elliptic curves over prime fields: precomputations
\project bee2 [cryptographic library]
\created 2021.07.18
\version 2026.02.07
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
- этап 1 -- шаги 1 -- 16 (расчет начальных выражений);
- этап 2 -- шаги 17, 18, 20 (расчет основных выражений);
- этап 3 -- шаги 19, 21 (формирование точек).

Для повышения читабельности используются макросы, которые покрывают следующие
выражения:
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
	* кэшируются 2 последовательных значения: текущее и предыдущее.
5. WWy4(i) -- произведения (2y)⁴WᵢWᵢ₊₂, i=3,5,...,2ʷ⁻¹-1:
	* память: 1;
	* вычисляются и используются на этапах 1 и 2;
	* кэшируется только текущее значение.
6. WWW(i) -- выражения Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁², i=3,4,...,2ʷ⁻¹:
	* память: 2ʷ⁻¹-2;
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

#define ecpPreSNZ_local(n, w)\
/* t */			O_OF_W(n),\
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
	word* t;				/* [n] */
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
	// [(2y)²W₂W₄] <- (2y)²(W₂W₄)
	qrMul(WWy2(2), dy2, WW(2), ec->f, stack);
	// [(2y)⁴W₂W₄] <- (2y)²((2y)²W₂W₄)
	qrMul(WWy4(2), dy2, WWy2(2), ec->f, stack);
	// [W₅] <- (2y)⁴W₂W₄−(W₁W₃)W₃²
	qrMul(t, WW(1), W2(3), ec->f, stack);
	qrSub(W(5), WWy4(2), t, ec->f);
	// [W₅²] <- W₅²
	qrSqr(W2(5), W(5), ec->f, stack);
	// [W₅W₂²−W₁W₄²] <- W₅-W₄²
	qrSub(WWW(3), W(5), W2(4), ec->f);
	// [W₆] <- W₃(W₅W₂²−W₁W₄²)
	qrMul(W(6), W(3), WWW(3), ec->f, stack);
	// [W₆W₃²−W₂W₅²] <- (W₆W₃)W₃-W₅²
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

	// (Xᵢ:Yᵢ:Zᵢ) для i=2ʷ⁻¹+1,...,2ʷ-1
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

/*
*******************************************************************************
Предвычисления: схема SNZA

Реализован алгоритм SmallMultA, предложенный в [APS22]. Алгоритм основан на
многочленах деления и требует примерно 25/2 M + 5 S операций на каждую
кратную точку и дополнительно операцию 1I для одновременнного обращения 
нескольких элементов поля.

Алгоритм выполняется в 4 этапа. Этапам соответствуют следующие шаги алгоритма:
- этап 1 -- шаги 1 -- 13 (расчет начальных выражений);
- этап 2 -- шаг 14, частично шаги 16 и 18 (расчет основных выражений);
- этап 3 -- шаг 15 (обращение элементов поля);
- этап 4 -- шаги 16 -- 20 (формирование точек).

В целом кэшируются те же выражения, что и в ecpPreSNZ(). Отличия:
- не кэшируется выражение Wᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂Wᵢ₊₁². Соответственно макрос 
  WWW не используется;
- кэшируется не 2, а 3 последовательных значения WᵢWᵢ₊₂. Это связано
  с тем, что на итерациях этапа 2 используются пары выражений 
  Wᵢ₋₁Wᵢ₊₁ и WᵢWᵢ₊₂, а на итерациях этапа 4 -- пары Wᵢ₋₂Wᵢ и WᵢWᵢ₊₂.

Дополнительный макрос:
7. W2I(i) -- выражения Wᵢ⁻², i=3,5,...,2ʷ-1:
	* память: 2ʷ⁻¹-1;
	* на этапе 2 кэшируются значения (∏ᵥ Wᵥ²: v = 3,5,...,i);
	* на этапе 3 вычисляются актуальные значения Wᵢ⁻², которые используются на
	  этапе 4.

Точки (xᵢ,yᵢ), i=3,5,..,2ʷ⁻¹-1, начинают формироваться на этапе 2 и завершают
на этапе 4, после обращения Wᵢ².
*******************************************************************************
*/

#if defined(W) || defined(W2) || defined(WW) || defined(WWy2) ||\
	defined(WWy4) || defined(W2I)
	#error "Conflicting preprocessor definitions"
#endif

#define ecpPreSNZA_local(n, w)\
/* t */			O_OF_W(n),\
/* dy2 */		O_OF_W(n),\
/* Ws */		O_OF_W((SIZE_BIT_POS(w) - 1) * n),\
/* W2s */		O_OF_W((SIZE_BIT_POS(w) - 2) * n),\
/* WWs */		O_OF_W(3 * n),\
/* WWy2s */		O_OF_W(2 * n),\
/* WWy4s */		O_OF_W(n),\
/* W2Is */		O_OF_W((SIZE_BIT_POS(w - 1) - 1) * n)

bool_t ecpPreSNZA(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack) 
{
	size_t n;
	word* t;				/* [n] */
	word* dy2;				/* [n] (2y)² */
	word* Ws;				/* [(2^w - 1) * n] Wᵢ */
	word* W2s;				/* [(2^w - 2) * n] Wᵢ² */
	word* WWs;				/* [3 * n] WᵢWᵢ₊₂ */
	word* WWy2s;			/* [2 * n] (2y)²WᵢWᵢ₊₂ */
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
		ecpPreSNZA_local(n, w), SIZE_0, SIZE_MAX,
		&t, &dy2, &Ws, &W2s, &WWs, &WWy2s, &WWy4s, &W2Is, &stack);
	// первая точка
	pt = pre->pts;
	wwCopy(pt, a, 2 * n);
	pt += 2 * n;

/*** SmallMultA: begin ***/
#define W(i) (Ws + ((i) - 3) * n)
#define W2(i) (W2s + ((i) - 3) * n)
#define WW(i) (WWs + ((i) % 3) * n)
#define WWy2(i) (WWy2s + ((i) % 2) * n)
#define WWy4(i) (WWy4s)
#define W2I(i) (W2Is + ((i) >> 1) * n)

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

	// [W₃⁻²] <- W₃
	wwCopy(W2I(3), W(3), n);
	// W₂ᵢ, W₂ᵢ₊₁, WᵢWᵢ₊₂ для i=3,4...,2ʷ⁻¹
	// Vᵢ и предварительные точки (xᵢ,yᵢ) для нечетных i
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
		// Vᵢ и предварительные (xᵢ,yᵢ) при нечетном i
		if (i & 1)
		{
			// [W₂ᵢ₊₁] <- (WᵢWᵢ₊₂)Wᵢ²-((2y)⁴Wᵢ₋₁Wᵢ₊₁)Wᵢ₊₁²
			qrMul(t, WWy4(i - 1), W2(i + 1), ec->f, stack);
			qrMul(W(2 * i + 1), WW(i), W2(i), ec->f, stack);
			qrSub(W(2 * i + 1), W(2 * i + 1), t, ec->f);
			// [xᵢ] <- (2y)²Wᵢ₋₁Wᵢ₊₁
			wwCopy(ecX(pt), WWy4(i - 1), n);
			// [yᵢ] <- yW₂ᵢ
			qrMul(ecY(pt, n), ecY(a, n), W2(2 * i), ec->f, stack);
			// [Wᵢ⁻²] <- [Wᵢ₋₂⁻²]Wᵢ²
			if (i >= 5)
				qrMul(W2I(i), W2I(i - 2), W2(i), ec->f, stack);
			// к следующей точке
			pt += 2 * n;
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
	// [xᵢ] <- (2y)²Wᵢ₋₁Wᵢ₊₁ для i = 2ʷ⁻¹ + 1
	ASSERT(i == SIZE_BIT_POS(w - 1) + 1);
	wwCopy(ecX(pt), WWy2(i - 1), n);

/* SmallMultA: этап 3 */

	// обращение
	i = SIZE_BIT_POS(w) - 1;
	// (∏ᵥ Wᵥ²: v = 3,5,...,2ʷ-1) == 0?
	if (qrIsZero(W2I(i), ec->f))
		return FALSE;
	{
		word* t1 = WWy4s;
		// t <- (∏ᵥ Wᵥ²: v <= 2ʷ-1)⁻¹
		qrInv(t, W2I(i), ec->f, stack);
		// Wᵢ⁻²
		for (; i > 3; i -= 2)
		{
			// t1 <- (∏ᵥ Wᵥ²: v < i)⁻¹
			qrMul(t1, t, W2I(i), ec->f, stack);
			// [Wᵢ⁻²] <- (∏ᵥ Wᵥ²: v <= i)⁻¹ (∏ᵥ Wᵥ²: v < i)
			qrMul(W2I(i), t, W2I(i - 2), ec->f, stack);
			// t <- t1
			wwCopy(t, t1, n);
		}
		// [W₃⁻²] <- (∏ᵥ Wᵥ²: v <= 3)⁻¹
		wwCopy(W2I(3), t, n);
	}

/* SmallMultA: этап 4 */

	// (xᵢ,yᵢ) для i=3,5,..,2ʷ⁻¹-1
	ASSERT(i == 3);
	for (pt = pre->pts + 2 * n; i < SIZE_BIT_POS(w - 1); i += 2, pt += 2 * n)
	{
		// [xᵢ] <- x-[xᵢ]Wᵢ⁻² = x-((2y)²Wᵢ₋₁Wᵢ₊₁)Wᵢ⁻²
		qrMul(ecX(pt), ecX(pt), W2I(i), ec->f, stack);
		qrSub(ecX(pt), ecX(a), ecX(pt), ec->f);
		// [yᵢ] <- [yᵢ](Wᵢ⁻²)² = (yW₂ᵢ)(Wᵢ⁻²)²
		qrSqr(t, W2I(i), ec->f, stack);
		qrMul(ecY(pt, n), ecY(pt, n), t, ec->f, stack);
	}
	// [xᵢ] <- x-[xᵢ]Wᵢ⁻² = x-((2y)²Wᵢ₋₁Wᵢ₊₁)Wᵢ⁻² для i=2ʷ⁻¹+1
	ASSERT(i == SIZE_BIT_POS(w - 1) + 1);
	qrMul(ecX(pt), ecX(pt), W2I(i), ec->f, stack);
	qrSub(ecX(pt), ecX(a), ecX(pt), ec->f);
	// (xᵢ,yᵢ) для i=2ʷ⁻¹+1,...,2ʷ-1
	while (1)
	{
		if (i == SIZE_BIT_POS(w) - 1)
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
	pre->type = ec_pre_snza;
	pre->w = w, pre->h = 0;
	return TRUE;
}

size_t ecpPreSNZA_deep(size_t n, size_t f_deep, size_t w)
{
	return memSliceSize(
		ecpPreSNZA_local(n, w),
		f_deep,
		SIZE_MAX);
}
