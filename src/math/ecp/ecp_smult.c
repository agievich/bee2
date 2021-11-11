/*
*******************************************************************************
\file ecp_smult.c
\brief Elliptic curves: scalar multiplication based on division polynomials
\project bee2 [cryptographic library]
\created 2021.07.18
\version 2021.10.28
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <stdarg.h>
#include "bee2/core/mem.h"
#include "bee2/core/stack.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ec.h"
#include "bee2/math/ecp.h"
#include "bee2/math/gfp.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "ecp_lcl.h"

static void ecNegPrecompA(word c[], const size_t w, const ec_o* ec)
{
	const size_t na = ec->f->n * 2;
	word* nci;
	word* ci;
	ci = nci = c + (na << (w - 1));

	for (; nci != c;)
	{
		nci -= na;
		ecNegA(nci, ci, ec);
		ci += na;
	}
}

size_t ecpMulAWidth(const size_t l) {
    return l <= 256 ? 4 : 5;
}

bool_t ecpMulA1(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, const word c[], word w, void* stack)
{
	const size_t n = ec->f->n * ec->d;
	const size_t na = ec->f->n * 2;
	const size_t order_len = W_OF_B(wwBitSize(ec->order, ec->f->n + 1));

	/* Текущая цифра кратности */
	register word t;
	/* Индекс малого кратного */
	register size_t v;
	/* Флаг нечётности */
	register word f;
	/* Флаг четности d */
	register word d_is_even;
	/* исправленная кратность dd = ((d & 1) ? d : -d) \mod ec->order */
	word* dd;
	/* Текущая кратная точка */
	word* q;

	size_t j, k;

	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(3 <= w && w + 1 < B_PER_W);
	ASSERT(m <= order_len);

	// раскладка stack
	q = (word*)stack;
	dd = q + n;
	stack = (void*)(dd + order_len);

	/* Переход к нечетной кратности dd = ((d & 1) ? d : -d) \mod ec->order */
	wwSetZero(dd, order_len);
	wwCopy(dd, d, m); //todo регулярно ли разрешать m переменной длины, или всегда должно быть m == order_len?
	d_is_even = WORD_1 - (d[0] & 1);
	zzSetSignMod(dd, dd, ec->order, order_len, d_is_even);

	/*
	Каноническое разложение a по степеням 2^w:
	a = a_0 + a_1 2^w + .. + a_i 2^{wi} + .. + a_k 2^{wk}
	0 <= a_i < 2^w
	B_PER_W * order_len <= wk
	*/

	k = B_PER_W * order_len;
	ASSERT(w < k);
	if (k % w != 0)
		j = k - (k % w);
	else
		j = k - w;

	/*
	Индекс, по которому находится необходимое малое кратное в списке предвычисленных малых кратных
	t - значение канонического разложения на текущем шаге
	f - флаг нечетности значения канонического разложения на предыдущей итерации
	*/
#define SMULT_IDX(t, f) ((t >> 1) | (f << (w - 1)))

	/*
	Старшая часть кратности: a_k
	1.1) a_k - нечётное:
		a = .. + a_{k-1} 2^{wk-w} + a_k 2^{wk}
		t := a_k
		f := 0
	1.2) a_k - чётное:
		a = .. + (a_{k-1} - 2^w) 2^{wk-w} + (a_k + 1) 2^{wk}
		t := a_k + 1
		f := -2^w
	*/
	t = wwGetBits(dd, j, k - j);
	v = SMULT_IDX(t, 1);
	ecFromA(q, c + v * na, ec, stack);
	f = t & 1;

	/* a_{k-1} .. a_1 */
	for (; (j -= w) != 0;) {
		/* Q <- 2^(w-1) * Q */
		for (k = w - 1; k--;)
			ecDbl(q, q, ec, stack);

		/*
		Внутренняя часть кратности: a_i
		f - флаг нечётности с предыдущего шага
		2.1) a_i - нечётное:
			a = .. + a_{i-1} 2^{wi-w} + (a_i + f) 2^{wi} + ..
			t := a_i + f
			f := 0
		2.2) a_i - чётное:
			a = .. + (a_{i-1} - 2^w) 2^{wi-w} + (a_i + 1 + f) 2^wi + ..
			t := a_i + 1 + f
			f := -2^w
		*/
		t = wwGetBits(dd, j, w);
		v = SMULT_IDX(t, f);
		ecpDblAddA(q, q, c + v * na, FALSE, ec, stack);
		f = t & 1;
	}

	/* Q <- 2^w * Q */
	for (k = w; k--;)
		ecDbl(q, q, ec, stack);

	t = wwGetBits(dd, 0, w);
	v = SMULT_IDX(t, f);
	ecpAddAJA_complete(b, q, c + v * na, ec, stack);

#undef SMULT_IDX

	//переход к исходной кратности
	ecpSetSignA(b, b, d_is_even, ec);
	//todo очистка остальных переменных
	t = v = f = d_is_even = j = k = 0;
	//предусмотреть d == 0
	return WORD_1 - wwIsZero(dd, order_len);
}

size_t ecpMulA1_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t m)
{
	return O_OF_W(n * ec_d + n + 1)
		+ utilMax(2,
			ec_deep,
			ecpAddAJA_complete_deep(n, f_deep)
		);
}

bool_t ecpMulA(word b[], const word a[], const ec_o* ec, const word d[], size_t m, void* stack)
{
	const size_t w = ecpMulAWidth(wwBitSize(ec->order, ec->f->n + 1));
	const size_t half_precomp_size = ec->f->n << w; //i.e. (ec->f->n * 2) << (w - 1)

	word* c;
	word* ci;

	c = (word*)stack;
	ci = c + half_precomp_size;
	stack = ci + half_precomp_size;

	ecpSmallMultA(ci, a, w, ec, stack);
	ecNegPrecompA(c, w, ec);
	return ecpMulA1(b, a, ec, d, m, c, w, stack);
}

size_t ecpMulA_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t ec_order_len)
{
	const size_t na = n * 2;
	const size_t w = ecpMulAWidth(B_OF_W(ec_order_len));

	return O_OF_W(na << w)
		+ utilMax(2,
			ecpSmallMultA_deep(w, n, f_deep),
			ecpMulA1_deep(n, f_deep, ec_d, ec_deep, ec_order_len)
		);
}

static void ecNegPrecompJ(word c[], const size_t w, const ec_o* ec, void* stack)
{
	const size_t nj = ec->f->n * 3;
	word* nci;
	word* ci;
	ci = nci = c + (nj << (w - 1));

	for (; nci != c;)
	{
		nci -= nj;
		ecNeg(nci, ci, ec, stack);
		ci += nj;
	}
}

size_t ecpMulJWidth(const size_t l) {
    return l <= 256 ? 5 : 6;
}

bool_t ecpMulAJ1(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, const word c[], word w, void* stack)
{
	const size_t n = ec->f->n * ec->d;
	const size_t order_len = W_OF_B(wwBitSize(ec->order, ec->f->n + 1));

	/* Текущая цифра кратности */
	register word t;
	/* Индекс малого кратного */
	register size_t v;
	/* Флаг нечётности */
	register word f;
	/* Флаг четности d */
	register word d_is_even;
	/* исправленная кратность dd = ((d & 1) ? d : -d) \mod ec->order */
	word* dd;
	/* Текущая кратная точка */
	word* q;

	size_t j, k;

	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(3 <= w && w + 1 < B_PER_W);
	ASSERT(m <= order_len);

	// раскладка stack
	q = (word*)stack;
	dd = q + n;
	stack = (void*)(dd + order_len);

	/* Переход к нечетной кратности dd = ((d & 1) ? d : -d) \mod ec->order */
	wwSetZero(dd, order_len);
	wwCopy(dd, d, m); //todo регулярно ли разрешать m переменной длины, или всегда должно быть m == order_len?
	d_is_even = WORD_1 - (d[0] & 1);
	zzSetSignMod(dd, dd, ec->order, order_len, d_is_even);

	/*
	Каноническое разложение a по степеням 2^w:
	a = a_0 + a_1 2^w + .. + a_i 2^{wi} + .. + a_k 2^{wk}
	0 <= a_i < 2^w
	B_PER_W * order_len <= wk
	*/

	k = B_PER_W * order_len;
	ASSERT(w < k);
	if (k % w != 0)
		j = k - (k % w);
	else
		j = k - w;


	/*
	Индекс, по которому находится необходимое малое кратное в списке предвычисленных малых кратных
	t - значение канонического разложения на текущем шаге
	f - флаг нечетности значения канонического разложения на предыдущей итерации
	*/
#define SMULT_IDX(t, f) ((t >> 1) | (f << (w - 1)))

	/*
	Старшая часть кратности: a_k
	1.1) a_k - нечётное:
		a = .. + a_{k-1} 2^{wk-w} + a_k 2^{wk}
		t := a_k
		f := 0
	1.2) a_k - чётное:
		a = .. + (a_{k-1} - 2^w) 2^{wk-w} + (a_k + 1) 2^wk
		t := a_k + 1
		f := -2^w
	*/
	t = wwGetBits(dd, j, k - j);
	v = SMULT_IDX(t, 1);
	wwCopy(q, c + v * n, n);
	f = t & 1;

	/* a_{k-1} .. a_1 */
	for (; (j -= w) != 0;) {
		/* Q <- 2^w * Q */
		for (k = w; k--;)
			ecDbl(q, q, ec, stack);

		/*
		Внутренняя часть кратности: a_i
		f - флаг нечётности с предыдущего шага
		2.1) a_i - нечётное:
			a = .. + a_{i-1} 2^{wi-w} + (a_i + f) 2^{wi} + ..
			t := a_i + f
			f := 0
		2.2) a_i - чётное:
			a = .. + (a_{i-1} - 2^w) 2^{wi-w} + (a_i + 1 + f) 2^wi + ..
			t := a_i + 1 + f
			f := -2^w
		*/
		t = wwGetBits(dd, j, w);
		v = SMULT_IDX(t, f);
		ecAdd(q, q, c + v * n, ec, stack);
		f = t & 1;
	}

	/* Q <- 2^w * Q */
	for (k = w; k--;)
		ecDbl(q, q, ec, stack);

	t = wwGetBits(dd, 0, w);
	v = SMULT_IDX(t, f);
	ecpAddAJJ_complete(b, q, c + v * n, ec, stack);

#undef SMULT_IDX

	//переход к исходной кратности
	ecpSetSignA(b, b, d_is_even, ec);
	//todo очистка остальных переменных
	t = v = f = d_is_even = j = k = 0;
	//предусмотреть d == 0
	return WORD_1 - wwIsZero(dd, order_len);
}

size_t ecpMulAJ1_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t m)
{
	return O_OF_W(n * ec_d + n + 1)
		+ utilMax(2,
			ec_deep,
			ecpAddAJJ_complete_deep(n, f_deep)
		);
}

bool_t ecpMulAJ(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, void* stack)
{
	const size_t w = ecpMulJWidth(wwBitSize(ec->order, ec->f->n + 1));
	const size_t half_precomp_size = (ec->f->n * ec->d) << (w - 1);
	word* c;
	word* ci;

	c = (word*)stack;
	ci = c + half_precomp_size;
	stack = ci + half_precomp_size;

	ecpSmallMultJ(ci, a, w, ec, stack);
	ecNegPrecompJ(c, w, ec, stack);
	return ecpMulAJ1(b, a, ec, d, m, c, w, stack);
}

size_t ecpMulAJ_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t ec_order_len)
{
	const size_t w = ecpMulJWidth(B_OF_W(ec_order_len));

	return  O_OF_W((n * ec_d) << w)
		+ utilMax(2,
			ecpSmallMultJ_deep(w, n, f_deep),
			ecpMulAJ1_deep(n, f_deep, ec_d, ec_deep, ec_order_len)
		);
}

#define stack_walloc(p, k)				\
	do {								\
		(p) = (word*)(stack);			\
		stack = (word*)(stack) + (k);	\
	} while(0)
#define stack_wfree(p)

void ecpSmallMultA(word* c, const word a[], const size_t w, const ec_o* ec, void* stack)
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
	// 3*) for i=3,5..2ʷ⁻¹-1
	// 3) for i=3,5..2ʷ⁻¹+1
	// 4) for i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1
	// 4*) for i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1
	//
	// Таблица. Подвыражения на этапах.
	// Подвыражение    | 0)       | 1)                | 2)   | 3)         | 4)                 |
	// -----------------------------------------------------------------------------------------
	// Wᵢ              | W[3,4,5] | R[i,i+2,2i+1]     |      | R[*2i]     | R[*i-1,i,*i+1,i+2] |
	//                 |          | W[2i,2i+1]        |      |            |                    |
	// Wᵢ²             | W[3,4,5] | R[i-1,i,i+1,'i+2] | R[i] |            | R[i-1,'i,i+1,'i+2] |
	//                 |          | W[2i,2i+1]        |      |            |                    |
	// Wᵢ⁻²            |          |                   | W[i] | R[i]       | R[i]               |
	// Wᵢ₋₁ Wᵢ₊₁       | W[2,3]   | W[i+1]            |      |            | R[i-1], W[i+1]     |
	//                 |          | R[i-1,i(e),i+1]   |      |            |                    |
	// (2y)² Wᵢ₋₁ Wᵢ₊₁ | W[3]     | W[i(e)+1]         |      | R[i]       |                    |
	// (2y)⁴ Wᵢ₋₁ Wᵢ₊₁ | W[3]     | R[i(o)]           |      |            |                    |
	//                 |          | WR[i(e)+1]        |      |            |                    |
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
	// Если на этапе 4) не используется gfpMul2 (вычисление произведения через квадраты),
	// то на этапе 4) используются только значения по чётным индексам, поэтому память
	// под квадраты по нечётным индексам можно переиспользовать под обратные (макрос W2i).
	// Квадраты с нечётными индексами сгруппированы вместе для упрощения их обращения.
	// Квадраты по чётным индексам: W₂ᵢ², i=2,3..2ʷ⁻¹, - выделяются в pW2[0].
	// Квадраты по нечётным индексам: W₂ᵢ₋₁², i=2,3..2ʷ⁻¹, - выделяются в pw2[1].
	word* pW2[2];
#define W2(i) (pW2[(i)&1] + (((i)-3)>>1) * n)
	// обратные нечётные квадраты: W₂ᵢ₋₁⁻², i=2,3..2ʷ⁻¹
	// этапы: 2), 3), 4)
	// память: 2ʷ⁻¹-1
	// Обратные нечётные квадраты формируются на этапе 2) и используются на этапах 3) и 4).
	word* pW2i;
#define W2i(i) (pW2i + (((i)-3)>>1) * n)
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

	ASSERT(w >= 2);

	stack_walloc(dy2, n);
	stack_walloc(tmp, n);
	stack_walloc(tmp2, n);
	stack_walloc(pW, n * ((SIZE_1 << w) - 1));
	stack_walloc(pW2[0], n * ((SIZE_1 << (w-1)) - 1));
	stack_walloc(pW2[1], n * ((SIZE_1 << (w-1)) - 1));
	stack_walloc(pW2i, n * ((SIZE_1 << (w-1)) - 1));
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
	qrMontInv(W2i(3), W2(3), i - 2, ec->f, stack);

	// Этап 3)
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
	// Этап 4)
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

size_t ecpSmallMultA_deep(const size_t w, size_t n, size_t f_deep)
{
	size_t const ww = SIZE_1 << w;
	size_t r = n * (0
		+ 1						// dy2
		+ 1						// tmp
		+ 1						// tmp2
		+ (ww - 1)				// pW
		+ (ww/2 - 1)			// pW2[0]
		+ (ww/2 - 1)			// pW2[1]
		+ (ww/2 - 1)			// pW2i
		+ 3						// pWW
		+ ww/4					// pWW2
		+ 1						// pWW4
		);
	return O_OF_W(r) +
		utilMax(2,
			f_deep,
			qrMontInv_deep(n, ww/2 - 1, f_deep));
}

void ecpSmallMultJ(word* c, const word a[], const size_t w, const ec_o* ec, void* stack)
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

	ASSERT(w >= 2);

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
}

size_t ecpSmallMultJ_deep(const size_t w, size_t n, size_t f_deep)
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
