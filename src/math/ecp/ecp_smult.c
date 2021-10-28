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

size_t ecSafeMulAWidth(const size_t l) {
	//todo calculate actual breakpoints
	if (l <= 256)
	{
		return 4;
	}
	return 5;
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
	const size_t w = ecSafeMulAWidth(wwBitSize(ec->order, ec->f->n + 1));
	const size_t half_precomp_size = ec->f->n << w; //i.e. (ec->f->n * 2) << (w - 1)

	word* c;
	word* ci;

	c = (word*)stack;
	ci = c + half_precomp_size;
	stack = ci + half_precomp_size;

	ecpSmallMultA(ci, NULL, a, w, ec, stack);
	ecNegPrecompA(c, w, ec);
	return ecpMulA1(b, a, ec, d, m, c, w, stack);
}

size_t ecpMulA_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t ec_order_len)
{
	const size_t na = n * 2;
	const size_t w = ecSafeMulAWidth(B_OF_W(ec_order_len));

	return O_OF_W(na << w)
		+ utilMax(2,
			ecpSmallMultA_deep(FALSE, w, n, f_deep),
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

size_t ecSafeMulJWidth(const size_t l) {
	//todo calculate actual breakpoints
	if (l <= 256)
	{
		return 5;
	}
	return 6;
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
	const size_t w = ecSafeMulJWidth(wwBitSize(ec->order, ec->f->n + 1));
	const size_t half_precomp_size = (ec->f->n * ec->d) << (w - 1);
	word* c;
	word* ci;

	c = (word*)stack;
	ci = c + half_precomp_size;
	stack = ci + half_precomp_size;

	ecpSmallMultJ(ci, NULL, a, w, ec, stack);
	ecNegPrecompJ(c, w, ec, stack);
	return ecpMulAJ1(b, a, ec, d, m, c, w, stack);
}

size_t ecpMulAJ_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t ec_order_len)
{
	const size_t w = ecSafeMulJWidth(B_OF_W(ec_order_len));

	return  O_OF_W((n * ec_d) << w)
		+ utilMax(2,
			ecpSmallMultJ_deep(FALSE, w, n, f_deep),
			ecpMulAJ1_deep(n, f_deep, ec_d, ec_deep, ec_order_len)
		);
}
