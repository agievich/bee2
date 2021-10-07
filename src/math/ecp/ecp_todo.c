/*
*******************************************************************************
\file ecp_todo.c
\brief Elliptic curves over prime fields: to merge with ecp_smult?
\project bee2 [cryptographic library]
\created 2012.06.26
\version 2021.07.29
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/ecp.h"
#include "bee2/math/gfp.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

#if 0
/*
*******************************************************************************

Вычисление малых кратных в афинных координатах с помощью полиномов деления.

Входная точка [2n]a в афинных коордитанах

w - ширина окна. Вообще говоря, зависит только от стойкости. (Сохранить значеие в кривой ec_o для предвычисленных малых кратных?)

sm_mults - выходной массив малых кратных X3,Y3,X5,Y5... в афинных координатах

\safe алгоритм регулярен

*******************************************************************************
*/
bool_t smMultsA_divPoly(word* sm_mults, const word a[], const word w, const ec_o* ec, void* stack)
{
	//todo проверки?
	const word ec_f_n = ec->f->n;
	const word aff_point_size = ec->f->n * 2;
	size_t i;
	size_t t;
	word* x = ecX(a);
	word* y = ecY(a, ec->f->n);
	word* xx;
	word* bx;
	word* aa;
	word* bb;
	word* ax;
	word* xxx;
	word* dblYSq;

	word* tmp;
	word* tmp2;

	word* W;				//полиномы деления начиная с третьего, W[0] = W_3
	word* WW;				//квадраты полиномов деления начиная c третьего
	word* WWd2;				//произведения W_{n}W_{n+2}, c n = 1
	word* WWd2_dblYSq;		//произведения (2y)^2 W_{n}W_{n+2}, начиная с n = 2
	word* WWd2_dblYPow4;	//значения (2y)^4 W_{n}W_{n+2}, начиная с n = 2
	word* WW_odd_inv;	    //обратные к нечетным квадратам полиномов деления: W_{n}^{-2}, n = 3, 5, ...

	const int W_idx_shift = -3;
	const int WW_idx_shift = -3;
	const int WWd2_idx_shift = -1;
	const int WWd2_dblYSq_idx_shift = -2;
	const int WWd2_dblYPow4_idx_shift = -2;


	//раскладка в stack
	xx = (word*)stack;
	bx = xx + ec->f->n;
	aa = bx + ec->f->n;
	bb = aa + ec->f->n;
	ax = bb + ec->f->n;
	xxx = ax + ec->f->n;
	dblYSq = xxx + ec->f->n;
	tmp = dblYSq + ec->f->n;
	tmp2 = tmp + ec->f->n;

	//todo посчитать количество элементов
	W = tmp2 + ec->f->n * ;
	WW = W + ec->f->n*;
	WWd2 = WW + ec->f->n* ;
	WWd2_dblYSq = WWd2 + ec->f->n* ;
	WWd2_dblYPow4 = WWd2_dblYSq + ec->f->n* ;
	WW_odd_inv = WWd2_dblYPow4 + ec->f->n*;
	stack = WW_odd_inv + ec->f->n*;

	//Вспомогательные значения
	qrSqr(xx, x, ec->f, stack);
	qrMul(bx, ec->B, x, ec->f, stack);
	qrSqr(aa, ec->A, ec->f, stack);
	qrSqr(bb, ec->B, ec->f, stack);
	qrMul(ax, ec->A, x, ec->f, stack);
	qrMul(xxx, xx, x, ec->f, stack);

	gfpDouble(dblYSq, y, ec->f);
	qrSqr(dblYSq, dblYSq, ec->f, stack);

	//Вычислить W_3 = 3 (x^2 + a)^2 − 4 (a^2 − 3 bx)
	qrAdd(tmp, xx, ec->A, ec->f);  // x^2 + a
	qrSqr(tmp, tmp, ec->f, stack);		  // (x^2 + a)^2
	gfpDouble(tmp2, tmp, ec->f);   // 2 (x^2 + a)^2
	qrAdd(W, tmp, tmp2, ec->f);    // 3 (x^2 + a)^2

	gfpDouble(tmp, bx, ec->f);	  //2 bx
	qrAdd(tmp, tmp, bx, ec->f);	  //3 bx
	qrSub(tmp, aa, tmp, ec->f);   //a^2 − 3 bx
	gfpDouble(tmp, tmp, ec->f);	  //2 (a^2 − 3 bx)
	gfpDouble(tmp, tmp, ec->f);	  //4 (a^2 − 3 bx)

	qrSub(W, W, tmp, ec->f);	  //W_3 = 3 (x^2 + a)^2 − 4 (a^2 − 3 bx)

	//Вычислить W_4
	qrSqr(W + ec_f_n, xxx, ec->f, stack);		//(x^3)^2

	gfpDouble(tmp, xx, ec->f);					//2 x^2
	gfpDouble(tmp, tmp, ec->f);					//4 x^2
	qrAdd(tmp, tmp, xx, ec->f);					//5 x^2
	qrSub(tmp, tmp, ec->A, ec->f);				//5 x^2 - a
	qrMul(tmp, bx, tmp, ec->f, stack);			//bx (5 x^2 - a)
	gfpDouble(tmp, tmp, ec->f);					//2 bx (5 x^2 - a)
	gfpDouble(tmp, tmp, ec->f);					//4 bx (5 x^2 - a)

	qrAdd(W + ec->f->n, W + ec_f_n, tmp, ec->f); //(x^3)^2 + 4 bx (5 x^2 - a)

	qrSub(tmp, xxx, ax, ec->f);					//x^3 - ax
	qrMul(tmp, tmp, ax, ec->f, stack);			//ax (x^3 - ax)
	gfpDouble(tmp2, tmp, ec->f);				//2 ax (x^3 - ax)
	gfpDouble(tmp2, tmp2, ec->f);				//4 ax (x^3 - ax)
	qrAdd(tmp, tmp, tmp2, ec->f);				//5 ax (x^3 - ax)

	qrAdd(W + ec_f_n, W + ec_f_n, tmp, ec->f); //(x^3)^2 + 4 bx (5 x^2 - a) + 5 ax (x^3 - ax)

	gfpDouble(tmp, bb, ec->f);					//2 b^2
	gfpDouble(tmp, tmp, ec->f);					//4 b^2
	gfpDouble(tmp, tmp, ec->f);					//8 b^2

	qrSub(W + ec_f_n, W + ec_f_n, tmp, ec->f); //(x^3)^2 + 4 bx (5 x^2 - a) + 5 ax (x^3 - ax) - 8 b^2

	qrMul(tmp, aa, a, ec->f, stack);				//a^3

	qrSub(W + ec_f_n, W + ec_f_n, tmp, ec->f); //(x^3)^2 + 4 bx (5 x^2 - a) + 5 ax (x^3 - ax) - 8 b^2 - a^3

	gfpDouble(W + ec_f_n, W + ec_f_n, ec->f);	//W_4 = 2 ((x^3)^2 + 4 bx (5 x^2 - a) + 5 ax (x^3 - ax) - 8 b^2 - a^3)


	//(2y)^2
	gfpDouble(dblYSq, y, ec->f);
	qrSqr(dblYSq, dblYSq, ec->f, stack);

	//(W_3)^2
	qrSqr(WW, W, ec->f, stack);

	//(W_4)^2
	qrSqr(WW + ec_f_n, W + ec_f_n, ec->f, stack);

	//W_{1}W_{3} = W{3}
	qrCopy(WWd2, W, ec->f);

	//W_{2}W_{4} = W{4}
	qrCopy(WWd2 + ec_f_n, w + ec_f_n, ec->f);

	//[(2y)2W2W4]
	qrMul(WWd2_dblYSq, WWd2 + ec_f_n, dblYSq, ec->f, stack);

	//[(2y)4W2W4]
	qrMul(WWd2_dblYPow4, WWd2_dblYSq, dblYSq, ec->f, stack);

	//[W5] ← [(2y)4W2W4] −[W1W3] ·[W_{3}^2]
	qrMul(tmp, WWd2, WW, ec->f, stack);
	qrSub(W + 2 * ec_f_n, WWd2_dblYPow4, tmp, ec->f, stack);

	//[W5 ^2] ←([W5])2
	qrSqr(WW + 2 * ec_f_n, W + 2 * ec_f_n, ec->f, stack);

	//i 3 = .. 2^{w-1}
	t = (SIZE_1 << (w - 1));
	for (i = 3; i <= t; ++i)
	{
		//[WnWn+2] ← (([Wn] + [Wn+2])^2 − [W2n] −[W2 n + 2]) / 2
		qrAdd(tmp, W + ec_f_n * (i + W_idx_shift), W + ec_f_n * (i + W_idx_shift + 2), ec->f, stack);
		qrSqr(tmp, tmp, ec->f, stack);
		qrSub(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift), ec->f);
		qrSub(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift + 2), ec->f);
		gfpHalf(WWd2 + ec_f_n * (i-1), tmp, ec->f);

		if (i == 3)
		{
			//[W2n] ← [WnWn+2] − [Wn−2Wn] · [W2 n + 1]: 1M + 1A
			qrMul(tmp, WWd2  + ec_f_n * (i + WWd2_idx_shift - 2), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
			qrSub(W + ec_f_n * (2 * i + W_idx_shift), WWd2 + ec_f_n * (i - 1), tmp, ec->f, stack);
		}
		else
		{
			//[W2n] ← [WnWn+2] · [W2 n−1] −[Wn−2Wn] ·[W2 n + 1]
			qrMul(tmp, WWd2 + ec_f_n * (i + WWd2_idx_shift - 2), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
			qrMul(tmp2, WWd2 + ec_f_n * (i + WWd2_idx_shift), WW + ec_f_n * (i + WW_idx_shift - 1), ec->f, stack);
			qrSub(W + ec_f_n * (2 * i + W_idx_shift), tmp2, tmp, ec->f, stack);
		}

		//i нечетное?
		if (i & 1 == 1)
		{
			//[W2n+1] ← [WnWn+2] · [W2 n] − [(2y)4Wn−1Wn + 1] ·[W2 n + 1]
			qrMul(tmp, WWd2 + ec_f_n * (i + WWd2_idx_shift), WW + ec_f_n * (i + WW_idx_shift), ec->f, stack);
			qrMul(tmp2, WWd2_dblYPow4 + ec_f_n * (i + WWd2_dblYPow4_idx_shift - 1), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
			qrSub(W + ec_f_n * (2*i + 1 + W_idx_shift), tmp, tmp2, ec->f);
 		}
		else
		{
			//(a) [(2y)2WnWn + 2] ←[(2y)2] ·[WnWn + 2]: 1M
			qrMul(WWd2_dblYSq + ec_f_n * (i + WWd2_dblYSq_idx_shift), dblYSq, WWd2 + ec_f_n * (i + WWd2_idx_shift), ec->f, stack);

			//(b)[(2y)4WnWn + 2] ←[(2y)2] ·[(2y)2WnWn + 2]: 1M
			qrMul(WWd2_dblYPow4 + ec_f_n * (i + WWd2_dblYPow4_idx_shift), dblYSq, WWd2_dblYSq + ec_f_n * (i + WWd2_dblYSq_idx_shift), ec->f, stack);

			//(c) [W2n+1] ← [(2y)4WnWn + 2] ·[W2n] −[Wn−1Wn + 1] ·[W2 n + 1]: 2M + 1A
			qrMul(tmp, WWd2_dblYPow4 + ec_f_n * (i + WWd2_dblYPow4_idx_shift), WW + ec_f_n * (i + WW_idx_shift), ec->f, stack);
			qrMul(tmp2, WWd2 + ec_f_n * (i - 1 + WWd2_idx_shift), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
			qrSub(W + ec_f_n * (2 * i + 1 + W_idx_shift), tmp, tmp2, ec->f);
		}

		if (i != t)
		{
			//[W2 2n + 1] ←([W2n + 1])2
			qrSqr(WW + ec_f_n * (2 * i + 1 + WW_idx_shift), W + ec_f_n * (2 * i + 1 + W_idx_shift), ec->f, stack);
		}
	}

	//обратить квадраты нечетных малых кратных
	for (i = 0; i < t; ++i)
	{
		//WW_odd_inv <- W_n^2, n = 3, 5, ... 2^w - 1
		qrCopy(WW_odd_inv + ec_f_n * i, WW + ec_f_n * (i * 2 + 3 + WW_idx_shift), ec->f);
	}
	//WW_odd_inv <- W_n^(-2), n = 3, 5, ... 2^w - 1
	qrMontInv(WW_odd_inv, WW_odd_inv, t - 1, ec->f, stack);

	for (int i = 3; i <= t + 1; i += 2)
	{
		//[X'n] ← x −[(2y)2 Wn−1Wn + 1] ·[W−2 n]
		qrMul(tmp, WWd2_dblYSq + ec_f_n * (i - 1 + WWd2_dblYSq_idx_shift), WW_odd_inv + ec_f_n * ((i - 3) / 2), ec->f, stack);
		qrSub(ecX(sm_mults + aff_point_size * ((i - 3) / 2)), x, tmp, ec->f);
	}

	for (int i = t + 3; i <= t * 2 - 1; i += 2)
	{
		//tmp ←(([Wn−1] + [Wn + 1])2 −[W2 n−1] −[W2n + 1]) / 2
		qrAdd(tmp, W + ec_f_n * (i - 1 + W_idx_shift), W + ec_f_n * (i + 1 + W_idx_shift), ec->f, stack);
		qrSqr(tmp, tmp, ec->f, stack);
		qrSub(tmp, tmp, WW + ec_f_n * (i - 1 + WW_idx_shift), ec->f);
		qrSub(tmp, tmp, WW + ec_f_n * (i + 1 + WW_idx_shift ), ec->f);
		gfpHalf(tmp, tmp, ec->f);

		//[X'n] ← x −[(2y)2] · tmp ·[W−2 n]
		qrMul(tmp, tmp, WW_odd_inv + ec_f_n * ((i - 3) / 2), ec->f, stack);
		qrMul(tmp, dblYSq, tmp, ec->f, stack);
		qrSub(ecX(sm_mults + aff_point_size * ((i - 3) / 2)), x, tmp, ec->f);
	}

	for (i = 3; i <= t - 1; i += 2)
	{
		//. [Y'n] ← y ·[W2n] ·([W−2 n])2
		qrSqr(tmp, WW_odd_inv + ec_f_n * ((i - 3) / 2), ec->f, stack);
		qrMul(tmp, tmp, W + ec_f_n * (2 * i + W_idx_shift), ec->f, stack);
		qrMul(ecY(sm_mults + aff_point_size * ((i - 3) / 2), ec_f_n), tmp, y, ec->f, stack);
	}

	for (i = t + 1; i <= t * 2 - 3; i += 2)
	{
		//[WnWn+2] ← (([Wn] + [Wn+2])^2 − [W2n] −[W2 n + 2]) / 2
		qrAdd(tmp, W + ec_f_n * (i + W_idx_shift), W + ec_f_n * (i + W_idx_shift + 2), ec->f, stack);
		qrSqr(tmp, tmp, ec->f, stack);
		qrSub(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift), ec->f);
		qrSub(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift + 2), ec->f);
		gfpHalf(WWd2 + ec_f_n * (i - 1), tmp, ec->f);

		//tmp2 ← [WnWn+2] · [W2 n−1] −[Wn−2Wn] ·[W2 n + 1]
		qrMul(tmp, WWd2 + ec_f_n * (i + WWd2_idx_shift - 2), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
		qrMul(tmp2, WWd2 + ec_f_n * (i + WWd2_idx_shift), WW + ec_f_n * (i + WW_idx_shift - 1), ec->f, stack);
		qrSub(tmp2, tmp2, tmp, ec->f, stack);

		//[Y'n] ← y · tmp2 ·([W−2 n])2
		qrSqr(tmp, WW_odd_inv + ec_f_n * ((i - 3) / 2), ec->f, stack);
		qrMul(tmp, tmp, tmp2, ec->f, stack);
		qrMul(ecY(sm_mults + aff_point_size * ((i - 3) / 2), ec_f_n), tmp, y, ec->f, stack);
	}

	i = t * 2 - 1;
	//[Y'2w−1] ← y·([W2w−1]·[W2w + 1]·[W2 2w−2]−[W2w−3W2w−1]·[W2 2w])·([W−2 2w−1])2

	//tmp <- [W2w−1]·[W2w + 1]·[W2 2w−2]
	qrMul(tmp, W + ec_f_n * (i + W_idx_shift), W + ec_f_n * (i + W_idx_shift + 2), ec->f, stack);
	qrMul(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift - 1), ec->f, stack);

	//tmp2 <-[W_2w−3 W_2w−1]·[W2 2w]
	qrMul(tmp2, WWd2 + ec_f_n * (i + WWd2_idx_shift - 2), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);

	//tmp <- ([W 2w−1]·[W 2w + 1]·[W2 2w−2]−[W 2w−3 W 2w−1]·[W2 2w]) = tmp - tmp2
	qrSub(tmp, tmp, tmp2, ec->f);

	//[Y'2w−1] ← y·tmp·tmp2
	qrMul(tmp, tmp, tmp2, ec->f, stack);
	qrMul(ecY(sm_mults + aff_point_size * ((i - 3) / 2), ec_f_n), tmp, y, ec->f, stack);

	//todo cleanup
}
#endif

#ifdef _DEBUG
#define stack_walloc(p, k)					\
	do {									\
		*(word*)(stack) = (word)(k);		\
		*((word*)(stack) + 1) = 0xfeedbeef;	\
		(p) = (word*)(stack) + 2;			\
		*((word*)(stack) + 2) = 0xbeeffeed;	\
		stack = (word*)(stack) + 3 + (k);	\
		*((word*)(stack) - 2) = 0xfeedbeef;	\
		*((word*)(stack) - 1) = 0xbeeffeed;	\
	} while(0)
#define stack_wfree(p)														\
	do {																	\
		ASSERT(*((word*)(p) - 1) == 0xfeedbeef);							\
		ASSERT(*((word*)(p)) != 0xbeeffeed);								\
		ASSERT(stack == ((word*)(p) + 1 + (size_t)*((word*)(p)-2)));		\
		ASSERT(*((word*)(p) + (size_t)*((word*)(p)-2) - 1) != 0xfeedbeef);	\
		ASSERT(*((word*)(p) + (size_t)*((word*)(p)-2)) == 0xbeeffeed);		\
		stack = (word*)(p) - 2;												\
	} while(0)
#else
#define stack_walloc(p, k)				\
	do {								\
		(p) = (word*)(stack);			\
		stack = (word*)(stack) + (k);	\
	} while(0)
#define stack_wfree(p)
#endif

void ecpSmallMultA(word* c, word da[], const word a[], const size_t w, const ec_o* ec, void* stack)
{
	// размер координаты
	const size_t n = ec->f->n;
	// размер аффинной точки
	const size_t na = n * 2;
	// координата x базовой точки
	const word* x = ecX(a);
	// координата y базовой точки
	const word* y = ecY(a, n);

	size_t i;

	// Основные этапы алгоритма:
	// 0) Wᵢ, i=3,4,5
	// 1) for i=3,4..2ʷ⁻¹
	// 2) Wᵢ⁻², i=3,5..2ʷ-1
	// 3) 2P
	// 4*) for i=3,5..2ʷ⁻¹-1
	// 4) for i=3,5..2ʷ⁻¹+1
	// 5) for i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1
	// 5*) for i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1
	//
	// Таблица. Подвыражения на этапах.
	// Подвыражение    | 0)       | 1)                | 2)   | 3)     | 4)         | 5)                 |
	// --------------------------------------------------------------------------------------------------
	// Wᵢ              | W[3,4,5] | R[i,i+2,2i+1]     |      | R[3,4] | R[*2i]     | R[*i-1,i,*i+1,i+2] |
	//                 |          | W[2i,2i+1]        |      |        |            |                    |
	// Wᵢ²             | W[3,4,5] | R[i-1,i,i+1,'i+2] | R[i] |        |            | R[i-1,'i,i+1,'i+2] |
	//                 |          | W[2i,2i+1]        |      |        |            |                    |
	// Wᵢ⁻²            |          |                   | W[i] |        | R[i]       | R[i]               |
	// Wᵢ₋₁ Wᵢ₊₁       | W[2,3]   | W[i+1]            |      |        |            | R[i-1], W[i+1]     |
	//                 |          | R[i-1,i(e),i+1]   |      |        |            |                    |
	// (2y)² Wᵢ₋₁ Wᵢ₊₁ | W[3]     | W[i(e)+1]         |      |        | R[i]       |                    |
	// (2y)⁴ Wᵢ₋₁ Wᵢ₊₁ | W[3]     | R[i(o)]           |      |        |            |                    |
	//                 |          | WR[i(e)+1]        |      |        |            |                    |
	//

	// Выделяемая память
	word* tmp;
	word* tmp2;
	// 2y
	word* dy;
	// (2y)⁻¹
	word* dyi;
	// (2y)²
	word* dy2;
	// полиномы деления: Wᵢ, i=3,4..(2ʷ+1)
	// этапы: 0), 1), 3), 4), 5)
	// память: 2ʷ-1
	// Значения расчитываются на этапе 1) по индексам 2i и 2i+1.
	// На этапе 1) значения считываются последовательно, по индексам i, i+2.
	// На этапе 4) значения считываются по чётным индексам 2i.
	// На этапе 5) значения считываются последовательно, по индексам i-1,i,i+1,i+2.
	// Упростить кэширование не получается - необходимо выделять память под все значения.
	word* pW;
#define W(i) (pW + ((i)-3) * n)
	// квадраты: Wᵢ², i=3,4..2ʷ
	// этапы: 2), 4), 5)
	// память: 2ʷ-2[+1]
	// Если на этапе 5) не используется gfpMul2 (вычисление произведения через квадраты),
	// то на этапе 5) используются только значения по чётным индексам, поэтому память
	// под квадраты по нечётным индексам можно переиспользовать под обратные (макрос W2i).
	// Квадраты с нечётными индексами сгруппированы вместе для упрощения их обращения.
	// Если требуется найти также двойную точки (da != NULL), то требуется также инвертировать
	// значение 2y. Оно добавляется к квадратам по нечётным индексам для обращения.
	// Квадраты по чётным индексам: W₂ᵢ², i=2,3..2ʷ⁻¹, - выделяются в pW2[0].
	// Квадраты по нечётным индексам: W₂ᵢ₋₁²[,2y], i=2,3..2ʷ⁻¹, - выделяются в pw2[1].
	word* pW2[2];
#define W2(i) (pW2[(i)&1] + (((i)-3)>>1) * n)
	// обратные нечётные квадраты: W₂ᵢ₋₁⁻², i=2,3..2ʷ⁻¹
	// этапы: 2), 4), 5)
	// память: 2ʷ⁻¹-1
	// Обратные нечётные квадраты формируются на этапе 2) и используются на этапах 4) и 5).
	word* pW2i;
#define W2i(i) (pW2i + (((i)-3)>>1) * n)
	// произведения: Wᵢ₋₁ Wᵢ₊₁, i=2,3..2ʷ⁻¹+1
	// этапы: 0), 1), 5)
	// память: 3
	// На этапе 1) значения формируются и используются последовательно с индексами i-1,i,i+1,
	// поэтому можно выделять память лишь под 3 текущие значения.
	// На этапе 5) происходит чтение по индексу i-1, и запись по индексу i+1, поэтому
	// память можно выделять только под 1 значение.
	// Макрос WW(i) имеет вид (i+D)%3, где D - константа.
	// D выбрано как 2ʷ, чтобы WW(2ʷ⁻¹)=[(2ʷ⁻¹(1+2))%3]=0.
	// Макрос WW переопределен перед этапом 5) так, чтобы WW(i)=0.
	word* pWW;
#define WW(i) (pWW + (((i) + (SIZE_1 << w))%3) * n)
	// произведения: (2y)² Wᵢ₋₁ Wᵢ₊₁, i=3,5..2ʷ⁻¹+1
	// этапы: 0), 1), 4)
	// память: 2ʷ⁻²
	// Значения формируются на этапах 0), 1), чтение - на этапе 4). Кэшировать нужно все значения.
	word* pWW2;
#define WWy2(i) (pWW2 + (((i)-3) >> 1) * n)
	// текущее произведение: (2y)⁴ Wᵢ₋₁ Wᵢ₊₁, i=3,5..(2ʷ⁻¹-1)
	// этапы: 0), 1)
	// память: 1
	// Запись на пред. шаге, чтение на текущем. Кэшировать можно только одно текущее значение.
	word* pWW4;
#define WWy4(i) (pWW4)

	ASSERT(w >= 2);

	stack_walloc(dy2, n);
	stack_walloc(tmp, n);
	stack_walloc(tmp2, n);
	stack_walloc(pW, n * ((SIZE_1 << w) - 1));
	stack_walloc(pW2[0], n * ((SIZE_1 << (w-1)) - 1));
	stack_walloc(pW2[1], n * ((SIZE_1 << (w-1)) - (da ? 0 : 1)));
	stack_walloc(pW2i, n * ((SIZE_1 << (w-1)) - (da ? 0 : 1)));
	stack_walloc(pWW, n * 3);
	stack_walloc(pWW2, n * (SIZE_1 << (w-2)));
	stack_walloc(pWW4, n);
	dy = da ? pW2[1] + n * ((SIZE_1 << (w-1)) - 1) : dy2;

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
			word* u = da ? ecY(da, n) : W(4);
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
			qrSqr(W2(5), W(5), ec->f, stack);		// W₅ ²
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
			// [W₂ᵢ₊₁²]
			qrSqr(W2(2 * i + 1), W(2 * i + 1), ec->f, stack);		// W₂ᵢ₊₁ ²
	}


	// [1]P
	wwCopy(c, a, na);
	c += na;

	// Этап 2)
	// [Wᵢ⁻²][,2y], i=3,5..2ʷ-1
	qrMontInv(W2i(3), W2(3), da ? i - 1 : i - 2, ec->f, stack);

	// Этап 3)
	// [2]P
	if(da)
	{
		dyi = pW2i + n * ((SIZE_1 << (w - 1)) - 1);
		// X₂ = x-W₁W₃/(2yW₂)² = x - W₃ / (2y)²
		qrSqr(tmp, dyi, ec->f, stack);						// (2y) ⁻²
		qrMul(ecX(da), W(3), tmp, ec->f, stack);			// W₃ / (2y)²
		qrSub(ecX(da), x, ecX(da), ec->f);					// x - W₃/(2y)²
		// Y₂ = (W₄W₁²-W₀W₃²)/2/(2yW₂)³ = W₄ / 2 / (2y)³
		qrMul(tmp, tmp, dyi, ec->f, stack);					// (2y) ⁻³
		qrMul(ecY(da, n), ecY(da, n), tmp, ec->f, stack);	// W₄/2 / (2y)³
	}

	// Этап 4)
	for (i = 3;;)
	{
		// i=3,5..2ʷ⁻¹+1: [Xᵢ] = x − (2y)²Wᵢ₋₁Wᵢ₊₁ Wᵢ⁻²
		qrMul(tmp, WWy2(i), W2i(i), ec->f, stack);
		qrSub(ecX(c), x, tmp, ec->f);

		if (i == (SIZE_1 << (w - 1)) + 1) break;

		// i=3,5..2ʷ⁻¹-1: [Yᵢ] = y W₂ᵢ Wᵢ⁻⁴
		qrSqr(tmp, W2i(i), ec->f, stack);
		qrMul(tmp, W(2*i), tmp, ec->f, stack);
		qrMul(ecY(c, n), y, tmp, ec->f, stack);

		i += 2, c += na;
	}
	// Этап 5)
#undef WW
#define WW(i) (pWW)
	for (; i <= (SIZE_1 << w) - 1;)
	{
		// i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1: [Yᵢ] = y (WᵢWᵢ₊₂ Wᵢ₋₁² - Wᵢ₋₂Wᵢ Wᵢ₊₁²) Wᵢ⁻⁴
		qrMul(tmp, WW(i-1), W2(i+1), ec->f, stack); 						// Wᵢ₋₂Wᵢ Wᵢ₊₁²
		// [WᵢWᵢ₊₂]
		if (i != (SIZE_1 << w) - 1)
			gfpMul2(WW(i+1), W(i), W(i+2), W2(i), W2(i+2), ec->f, stack);	// Wᵢ Wᵢ₊₂
		else
			// Wᵢ₊₂² undefined
			qrMul(WW(i+1), W(i), W(i+2), ec->f, stack);						// Wᵢ Wᵢ₊₂

		if (i < 4)
			//w == 2, W2^2 = 1
			wwCopy(tmp2, WW(i + 1), n);
		else
			qrMul(tmp2, WW(i+1), W2(i-1), ec->f, stack); 					// WᵢWᵢ₊₂ Wᵢ₋₁²

		qrSub(tmp2, tmp2, tmp, ec->f);										// WᵢWᵢ₊₂Wᵢ₋₁² - Wᵢ₋₂WᵢWᵢ₊₁²
		qrSqr(tmp, W2i(i), ec->f, stack);									// Wᵢ⁻² ²
		qrMul(tmp, tmp2, tmp, ec->f, stack);								// (WᵢWᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂WᵢWᵢ₊₁²) Wᵢ⁻⁴
		qrMul(ecY(c, n), y, tmp, ec->f, stack);								// y (WᵢWᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂WᵢWᵢ₊₁²)Wᵢ⁻⁴

		if (i == (SIZE_1 << w) - 1) break;
		i += 2, c += na;

		// i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1: [Xᵢ] = x − (2y)² Wᵢ₋₁ Wᵢ₊₁ Wᵢ⁻²
		gfpMul2(tmp, W(i-1), W(i+1), W2(i-1), W2(i+1), ec->f, stack);		// Wᵢ₋₁ Wᵢ₊₁
		qrMul(tmp, dy2, tmp, ec->f, stack);									// (2y)² Wᵢ₋₁Wᵢ₊₁
		qrMul(tmp, W2i(i), tmp, ec->f, stack);								// (2y)²Wᵢ₋₁Wᵢ₊₁ Wᵢ⁻²
		qrSub(ecX(c), x, tmp, ec->f);										// x − (2y)²Wᵢ₋₁Wᵢ₊₁Wᵢ⁻²
	}
#ifdef _DEBUG
	if (w == 2) {
		//чтобы stack_wfree не ломался для w == 2, так как значение по адресу pWW + 2 * n не записывается
		wwSetZero(pWW + 2 * n, n);
	}
#endif // _DEBUG


	stack_wfree(pWW4);
	stack_wfree(pWW2);
	stack_wfree(pWW);
	stack_wfree(pW2i);
	stack_wfree(pW2[1]);
	stack_wfree(pW2[0]);
	stack_wfree(pW);
	stack_wfree(tmp2);
	stack_wfree(tmp);
	stack_wfree(dy2);

#undef W
#undef W2
#undef W2i
#undef WW
#undef WWy2
#undef WWy4

}

size_t ecpSmallMultA_deep(bool_t da, const size_t w, size_t n, size_t f_deep)
{
	size_t const ww = SIZE_1 << w;
	size_t r = n * (0
		+ 1						// dy2
		+ 1						// tmp
		+ 1						// tmp2
		+ (ww - 1)				// pW
		+ (ww/2 - 1)			// pW2[0]
		+ (ww/2 - (da ? 0 : 1))	// pW2[1]
		+ (ww/2 - (da ? 0 : 1))	// pW2i
		+ 3						// pWW
		+ ww/4					// pWW2
		+ 1						// pWW4
		);
#ifdef _DEBUG
	r += 3 * 10;
#endif
	return O_OF_W(r) +
		utilMax(2,
			f_deep,
			qrMontInv_deep(n, da ? ww/2 : ww/2 - 1, f_deep));
;
}

void ecpSmallMultJ(word* c, word da[], const word a[], const size_t w, const ec_o* ec, void* stack)
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
	// 3) 2P
	// 4*) for i=3,5..2ʷ⁻¹-1
	// 4) for i=3,5..2ʷ⁻¹+1
	// 5) for i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1
	// 5*) for i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1
	//
	// Таблица. Подвыражения на этапах.
	// Подвыражение    | 0)       | 1)                | 3)     | 4)         | 5)                 |
	// -------------------------------------------------------------------------------------------
	// Wᵢ              | W[3,4,5] | R[i,i+2,2i+1]     | R[3,4] | R[*2i]     | R[*i-1,i,*i+1,i+2] |
	//                 |          | W[2i,2i+1]        |        |            |                    |
	// Wᵢ²             | W[3,4,5] | R[i-1,i,i+1,'i+2] |        |            | R[i-1,'i,i+1,'i+2] |
	//                 |          | W[2i,2i+1]        |        |            |                    |
	// Wᵢ₋₁ Wᵢ₊₁       | W[2,3]   | W[i+1]            |        |            | R[i-1], W[i+1]     |
	//                 |          | R[i-1,i(e),i+1]   |        |            |                    |
	// (2y)² Wᵢ₋₁ Wᵢ₊₁ | W[3]     | W[i(e)+1]         |        | R[i]       |                    |
	// (2y)⁴ Wᵢ₋₁ Wᵢ₊₁ | W[3]     | R[i(o)]           |        |            |                    |
	//                 |          | WR[i(e)+1]        |        |            |                    |
	//

	// Выделяемая память
	word* tmp;
	word* tmp2;
	// 2y
	word* dy;
	// (2y)²
	word* dy2;
	// полиномы деления: Wᵢ, i=3,4..(2ʷ+1)
	// этапы: 0), 1), 3), 4), 5)
	// память: 2ʷ-1
	// Значения расчитываются на этапе 1) по индексам 2i и 2i+1.
	// На этапе 1) значения считываются последовательно, по индексам i, i+2.
	// На этапе 4) значения считываются по чётным индексам 2i.
	// На этапе 5) значения считываются последовательно, по индексам i-1,i,i+1,i+2.
	// Упростить кэширование не получается - необходимо выделять память под все значения.
	word* pW;
#define W(i) (pW + ((i)-3) * n)
	// квадраты: Wᵢ², i=3,4..2ʷ
	// этапы: 2), 4), 5)
	// память: 2ʷ-2[+1]
	// Квадраты с нечётными индексами сгруппированы вместе для упрощения их обращения.
	// Если требуется найти также двойную точки (da != NULL), то требуется также инвертировать
	// значение 2y. Оно добавляется к квадратам по нечётным индексам для обращения.
	// Квадраты по чётным индексам: W₂ᵢ², i=2,3..2ʷ⁻¹, - выделяются в pW2[0].
	// Квадраты по нечётным индексам: W₂ᵢ₋₁²[,2y], i=2,3..2ʷ⁻¹, - выделяются в pw2[1].
	word* pW2[2];
#define W2(i) (pW2[(i)&1] + (((i)-3)>>1) * n)
	// произведения: Wᵢ₋₁ Wᵢ₊₁, i=2,3..2ʷ⁻¹+1
	// этапы: 0), 1), 5)
	// память: 3
	// На этапе 1) значения формируются и используются последовательно с индексами i-1,i,i+1,
	// поэтому можно выделять память лишь под 3 текущие значения.
	// На этапе 5) происходит чтение по индексу i-1, и запись по индексу i+1, поэтому
	// память можно выделять только под 1 значение.
	// Макрос WW(i) имеет вид (i+D)%3, где D - константа.
	// D выбрано как 2ʷ, чтобы WW(2ʷ⁻¹)=[(2ʷ⁻¹(1+2))%3]=0.
	// Макрос WW переопределен перед этапом 5) так, чтобы WW(i)=0.
	word* pWW;
#define WW(i) (pWW + (((i) + (SIZE_1 << w))%3) * n)
	// произведения: (2y)² Wᵢ₋₁ Wᵢ₊₁, i=3,5..2ʷ⁻¹+1
	// этапы: 0), 1), 4)
	// память: 2ʷ⁻²
	// Значения формируются на этапах 0), 1), чтение - на этапе 4). Кэшировать нужно все значения.
	word* pWW2;
#define WWy2(i) (pWW2 + (((i)-3) >> 1) * n)
	// текущее произведение: (2y)⁴ Wᵢ₋₁ Wᵢ₊₁, i=3,5..(2ʷ⁻¹-1)
	// этапы: 0), 1)
	// память: 1
	// Запись на пред. шаге, чтение на текущем. Кэшировать можно только одно текущее значение.
	word* pWW4;
#define WWy4(i) (pWW4)

	ASSERT(w >= 2);

	stack_walloc(dy2, n);
	stack_walloc(tmp, n);
	stack_walloc(tmp2, n);
	stack_walloc(pW, n * ((SIZE_1 << w) - 1));
	stack_walloc(pW2[0], n * ((SIZE_1 << (w-1)) - 1));
	stack_walloc(pW2[1], n * ((SIZE_1 << (w-1)) - (da ? 0 : 1)));
	stack_walloc(pWW, n * 3);
	stack_walloc(pWW2, n * (SIZE_1 << (w-2)));
	stack_walloc(pWW4, n);
	dy = da ? pW2[1] + n * ((SIZE_1 << (w-1)) - 1) : dy2;

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
			word* u = da ? ecY(da, n) : W(4);
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
	ecFromA(c, a, ec, stack);
	c += nj;

	// Этап 3)
	// [2]P
	if(da)
	{
		// X₂ = x(2y)²W₂²-W₁W₃ = (2y)²x - W₃
		qrMul(ecX(da), dy2, x, ec->f, stack);				// (2y)² x
		qrSub(ecX(da), ecX(da), W(3), ec->f);				// (2y)²x - W₃
		// Y₂ = (W₄W₁²-W₀W₃²)/2 = W₄/2
		// Z₂ = 2yW₂ = 2y
		gfpDouble(ecZ(da, n), y, ec->f);
	}

	// Этап 4)
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
	// Этап 5)
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

}

size_t ecpSmallMultJ_deep(bool_t da, const size_t w, size_t n, size_t f_deep)
{
	size_t const ww = SIZE_1 << w;
	size_t r = n * (0
		+ 1						// dy2
		+ 1						// tmp
		+ 1						// tmp2
		+ (ww - 1)				// pW
		+ (ww/2 - 1)			// pW2[0]
		+ (ww/2 - (da ? 0 : 1))	// pW2[1]
		+ 3						// pWW
		+ ww/4					// pWW2
		+ 1						// pWW4
		);
#ifdef _DEBUG
	r += 3 * 9;
#endif
	return O_OF_W(r) + f_deep;
}

#undef stack_walloc
#undef stack_wfree
