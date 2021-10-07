/*
*******************************************************************************
\file ecp_smult.c
\brief Elliptic curves: scalar multiplication based on division polynomials
\project bee2 [cryptographic library]
\created 2021.07.18
\version 2021.07.29
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

//дубликат из ec.c
static size_t ecNAFWidth(size_t l)
{
	if (l >= 336)
		return 6;
	else if (l >= 120)
		return 5;
	else if (l >= 40)
		return 4;
	return 3;
}

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

bool_t FAST(ecpMulAA1)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, const word precomp_a[], const word precomp_w, void* stack)
{
	const size_t n = ec->f->n;
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const word naf_hi = WORD_1 << (naf_width - 1);
	register size_t naf_size;
	register size_t i;
	register word w;
	// переменные в stack
	word* naf;			/* NAF */
	word* t;			/* вспомогательная точка */
	word* pre;			/* pre[i] = (2i + 1)a (naf_count элементов) */

	// pre
	ASSERT(ecIsOperable(ec));

	// раскладка stack
	naf = (word*)stack;

	// расчет NAF
	ASSERT(naf_width >= 3);
	naf_size = wwNAF(naf, d, m, naf_width);

	// d == O => b <- O
	if (naf_size == 0)
		return FALSE;

	t = naf + 2 * m + 1;
	stack = t + ec->d * n;

	pre = (word*)precomp_a + ((2 * n) << (precomp_w - 1));

	// t <- a[naf[l - 1]]
	w = wwGetBits(naf, 0, naf_width);
	ASSERT(w <= precomp_w);
	ASSERT((w & 1) == 1 && (w & naf_hi) == 0);
	ecFromA(t, pre + (w >> 1) * 2 * n, ec, stack);
	// цикл по символам NAF
	i = naf_width;
	while (--naf_size)
	{
		w = wwGetBits(naf, i, naf_width);
		if (w & 1)
		{
			// t <- 2 t
			ecDbl(t, t, ec, stack);
			// t <- t \pm pre[naf[w]]
			if (w & naf_hi)
				ecSubA(t, t, pre + ((w ^ naf_hi) >> 1) * 2 * n, ec, stack);
			else
				ecAddA(t, t, pre + (w >> 1) * 2 * n, ec, stack);
			// к следующему разряду naf
			i += naf_width;
		}
		else
			ecDbl(t, t, ec, stack), ++i;
	}
	// очистка
	w = 0;
	i = 0;
	// к аффинным координатам
	return ecToA(b, t, ec, stack);
}

size_t FAST(ecpMulAA1_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return O_OF_W(2 * m + 1) +
		O_OF_W(ec_d * n) +
		ec_deep;
}

bool_t FAST(ecpMulAA)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, void* stack)
{
	const size_t n = ec->f->n;
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t naf_count = SIZE_1 << (naf_width - 2);
	word* pre;

	pre = (word*)stack;
	stack = pre + naf_count * 2 * n;

	ecpSmallMultA(pre, NULL, a, naf_width - 1, ec, stack);

	return FAST(ecpMulAA1)(b, a, ec, d, m, pre, naf_width - 1, stack);
}

size_t FAST(ecpMulAA_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t naf_count = SIZE_1 << (naf_width - 2);
	const size_t f_deep = ec_deep; //f_deep < ec_deep todo - сделать f_deep аргументом функции?

	return O_OF_W(naf_count * 2 * n)
		+ utilMax(2,
			ecpSmallMultA_deep(FALSE, naf_width - 1, n, f_deep),
			FAST(ecpMulAA1_deep)(n, ec_d, ec_deep, m)
		);
}

//todo другое имя
bool_t SAFE(ecpMulAA1)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, const word precomp_a[], word precomp_w, void* stack)
{
	const size_t n = ec->f->n * ec->d;
	const size_t na = ec->f->n * 2;
	const size_t order_len = ec->f->n + 1;

	/*
	* todo если есть предвычисленные малые кратные для точки a,
	* то имеет смысл w = max(ecSafeMulAWidth(...), ec->precomp_w);
	*/
	const size_t w = ecSafeMulAWidth(wwBitSize(ec->order, order_len));

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

	/* Предвычисленные в следующем порядке малые кратные:
	[1-2^w]a, [3-2^w]a, .., [-1]a, [1]a, [3]a, .., [2^w-1]a, */
	const word* c;
	size_t j, k;
	word* check_stack;

	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(3 <= w && w + 1 < B_PER_W);
	ASSERT(m <= order_len); //todo добавить этот assert в описание
	ASSERT(w <= precomp_w);

	// раскладка stack
	q = (word*)stack;
	dd = q + n;
	check_stack = dd + order_len;
#ifdef _DEBUG
	* check_stack = 0xdeadbeef;
	stack = (void*)(check_stack + 1);
#else
	stack = (void*)check_stack;
#endif

	c = precomp_a + (na << (precomp_w - 1)) - (na << (w - 1));

	/* Переход к нечетной кратности dd = ((d & 1) ? d : -d) \mod ec->order */
	wwSetZero(dd, order_len);
	wwCopy(dd, d, m); //todo регулярно ли разрешать m переменной длины, или всегда должно быть m == order_len?
	d_is_even = WORD_1 - (d[0] & 1);
	zzSetSignMod(dd, dd, ec->order, order_len, d_is_even);

	/* Каноническое разложение a по степеням 2^w:
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

	/* Старшая часть кратности: a_k
	1.1) a_k - нечётное:
		a = .. + a_{k-1} 2^{wk-w} + a_k 2^{wk}
		t := a_k
		f := 0
	1.2) a_k - чётное:
		a = .. + (a_{k-1} - 2^w) 2^{wk-w} + (a_k + 1) 2^{wk}
		t := a_k + 1
		f := -2^w
	*/
	t = wwGetBits(d, j, k - j);
	v = SMULT_IDX(t, 1);
	ecFromA(q, c + v * na, ec, stack);
	f = t & 1;


	/* a_{k-1} .. a_1 */
	for (; (j -= w) != 0;) {
		/* Q <- 2^(w-1) * Q */
		for (k = w - 1; k--;)
			ecDbl(q, q, ec, stack);

		/* Внутренняя часть кратности: a_i
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

#ifdef _DEBUG
	ASSERT(*check_stack == 0xdeadbeef);
#endif

	//переход к исходной кратности
	ecpSetSignA(b, b, d_is_even, ec);
	//todo очистка остальных переменных
	t = v = f = d_is_even = j = k = 0;
	//предусмотреть d == 0
	return WORD_1 - wwIsZero(dd, order_len);
}

size_t SAFE(ecpMulAA1_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return O_OF_W(n * ec_d + n + 1)
		+ ec_deep
#ifdef _DEBUG
		+ O_OF_W(1)
#endif
		;
}

bool_t SAFE(ecpMulAA)(word b[], const word a[], const ec_o* ec, const word d[], size_t m, void* stack)
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

	return SAFE(ecpMulAA1(b, a, ec, d, m, c, w, stack));
}

size_t SAFE(ecpMulAA_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t ec_order_len)
{
	const size_t na = n * 2;
	const size_t w = ecSafeMulAWidth(B_OF_W(ec_order_len));
	const size_t f_deep = ec_deep; //f_deep < ec_deep todo - сделать f_deep аргументом функции?

	return O_OF_W(na << w)
		+ utilMax(2,
			ecpSmallMultA_deep(FALSE, w, n, f_deep),
			SAFE(ecpMulAA1_deep)(n, ec_d, ec_deep, ec_order_len)
		);
}

bool_t FAST(ecpMulAJ1)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, const word precomp_j[], word precomp_w, void* stack)
{
	const size_t n = ec->f->n;
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const word naf_hi = WORD_1 << (naf_width - 1);
	register size_t naf_size;
	register size_t i;
	register word w;
	// переменные в stack
	word* naf;			/* NAF */
	word* t;			/* вспомогательная точка */
	word* pre;			/* pre[i] = (2i + 1)a (naf_count элементов) */
	// pre
	ASSERT(ecIsOperable(ec));

	// раскладка stack
	naf = (word*)stack;

	// расчет NAF
	ASSERT(naf_width >= 3);
	naf_size = wwNAF(naf, d, m, naf_width);

	// d == O => b <- O
	if (naf_size == 0)
		return FALSE;

	t = naf + 2 * m + 1;
	stack = t + ec->d * n;

	pre = (word*)precomp_j + ((2 * n) << (precomp_w - 1));

	// t <- a[naf[l - 1]]
	w = wwGetBits(naf, 0, naf_width);
	ASSERT((w & 1) == 1 && (w & naf_hi) == 0);
	ASSERT(w <= precomp_w);

	wwCopy(t, pre + (w >> 1) * ec->d * n, ec->d * n);
	// цикл по символам NAF
	i = naf_width;
	while (--naf_size)
	{
		w = wwGetBits(naf, i, naf_width);
		if (w & 1)
		{
			// t <- 2 t
			ecDbl(t, t, ec, stack);
			// t <- t \pm pre[naf[w]]
			if (w & naf_hi)
				ecSub(t, t, pre + ((w ^ naf_hi) >> 1) * ec->d * n, ec, stack);
			else
				ecAdd(t, t, pre + (w >> 1) * ec->d * n, ec, stack);
			// к следующему разряду naf
			i += naf_width;
		}
		else
			ecDbl(t, t, ec, stack), ++i;
	}
	// очистка
	w = 0;
	i = 0;
	// к аффинным координатам
	return ecToA(b, t, ec, stack);
}

size_t FAST(ecpMulAJ1_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return O_OF_W(2 * m + 1) +
		O_OF_W(ec_d * n) +
		ec_deep;
}

bool_t FAST(ecpMulAJ)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, void* stack)
{
	const size_t n = ec->f->n;
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t naf_count = SIZE_1 << (naf_width - 2);

	// переменные в stack
	word* pre;			/* pre[i] = (2i + 1)a (naf_count элементов) */

	pre = (word*)stack;
	stack = pre + naf_count * ec->d * n;

	// precomputed point in affine coordinates
	//TODO: convert to jacobian coordinates
	//ASSERT(0);

	ecpSmallMultJ(pre, NULL, a, naf_width - 1, ec, stack);

	return FAST(ecpMulAJ1)(b, a, ec, d, m, pre, naf_width - 1, stack);
}

size_t FAST(ecpMulAJ_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t naf_count = SIZE_1 << (naf_width - 2);
	const size_t f_deep = ec_deep; //f_deep < ec_deep todo - сделать f_deep аргументом функции?

	return O_OF_W(naf_count * ec_d * n)
		+ utilMax(2,
			ecpSmallMultJ_deep(FALSE, naf_width - 1, n, f_deep),
			FAST(ecpMulAJ1_deep)(n, ec_d, ec_deep, m)
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

bool_t SAFE(ecpMulAJ1)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, const word precomp_j[], word precomp_w, void* stack)
{
	const size_t n = ec->f->n * ec->d;
	const size_t order_len = ec->f->n + 1;

	const size_t w = ecSafeMulJWidth(wwBitSize(ec->order, order_len));

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

	/* Предвычисленные в следующем порядке малые кратные:
	[1-2^w]a, [3-2^w]a, .., [-1]a, [1]a, [3]a, .., [2^w-1]a, */
	const word* c;
	size_t j, k;
	word* check_stack;

	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(3 <= w && w + 1 < B_PER_W);
	ASSERT(m <= order_len); //todo добавить этот assert в описание
	ASSERT(w <= precomp_w);

	// раскладка stack
	q = (word*)stack;
	dd = q + n;
	check_stack = dd + order_len;
#ifdef _DEBUG
	* check_stack = 0xdeadbeef;
	stack = (void*)(check_stack + 1);
#else
	stack = (void*)check_stack;
#endif

	c = precomp_j + (n << (precomp_w - 1)) - (n << (w - 1));

	/* Переход к нечетной кратности dd = ((d & 1) ? d : -d) \mod ec->order */
	wwSetZero(dd, order_len);
	wwCopy(dd, d, m); //todo регулярно ли разрешать m переменной длины, или всегда должно быть m == order_len?
	d_is_even = WORD_1 - (d[0] & 1);
	zzSetSignMod(dd, dd, ec->order, order_len, d_is_even);

	/* Каноническое разложение a по степеням 2^w:
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

	/* Старшая часть кратности: a_k
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

		/* Внутренняя часть кратности: a_i
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

#ifdef _DEBUG
	ASSERT(*check_stack == 0xdeadbeef);
#endif

	//переход к исходной кратности
	ecpSetSignA(b, b, d_is_even, ec);
	//todo очистка остальных переменных
	t = v = f = d_is_even = j = k = 0;
	//предусмотреть d == 0
	return WORD_1 - wwIsZero(dd, order_len);
}

size_t SAFE(ecpMulAJ1_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t order_len = n + 1;

	return O_OF_W(n * ec_d)
		+ O_OF_W(order_len)
		+ ec_deep
#ifdef _DEBUG
		+ O_OF_W(1)
#endif
		;
}

bool_t SAFE(ecpMulAJ)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, void* stack)
{
	const size_t n = ec->f->n * ec->d;
	const size_t order_len = ec->f->n + 1;
	const size_t w = ecSafeMulJWidth(wwBitSize(ec->order, order_len));
	const size_t half_precomp_size = n << (w - 1);
	word* c;
	word* ci;

	// precomputed point in affine coordinates
	//TODO: convert to jacobian coordinates
	//ASSERT(0);

	c = (word*)stack;
	ci = c + half_precomp_size;
	stack = ci + half_precomp_size;

	ecpSmallMultJ(ci, NULL, a, w, ec, stack);

	ecNegPrecompJ(c, w, ec, stack);

	return SAFE(ecpMulAJ1)(b, a, ec, d, m, c, w, stack);
}

size_t SAFE(ecpMulAJ_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t ec_order_len)
{
	//todo сделать ec_order_len отдельным параметром фукнции?
	const size_t w = ecSafeMulJWidth(B_OF_W(ec_order_len));
	const size_t f_deep = ec_deep; //f_deep < ec_deep todo - сделать f_deep аргументом функции?

	return  O_OF_W((n * ec_d) << w)
		+ utilMax(2,
			ecpSmallMultJ_deep(FALSE, w, n, f_deep),
			SAFE(ecpMulAJ1_deep)(n, ec_d, ec_deep, ec_order_len)
		);
}

/*
*******************************************************************************
Сумма кратных точек

Реализован алгоритм 3.51 [Hankerson D., Menezes A., Vanstone S. Guide to
Elliptic Curve Cryptography, Springer, 2004] (interleaving with NAF).

Для каждого d[i] строится naf[i] длиной l[i] с шириной окна w[i].

Сложность алгоритма:
	max l[i](P <- 2P) + \sum {i=1}^k
		[1(P <- 2A) + (2^{w[i]-2}-2)(P <- P + P) + l[i]/(w[i]+1)(P <- P + P)].
*******************************************************************************
*/

bool_t FAST(ecpAddMulAA)(word b[], const ec_o* ec, void* stack, size_t k, ...)
{
	const size_t n = ec->f->n;
	register word w;
	size_t i, naf_max_size = 0;
	va_list marker;
	// переменные в stack
	word* t;			/* проективная точка */
	size_t* m;			/* длины d[i] */
	size_t* naf_width;	/* размеры NAF-окон */
	size_t* naf_size;	/* длины NAF */
	size_t* naf_pos;	/* позиция в NAF-представлении */
	word** naf;			/* NAF */
	word** pre;			/* предвычисленные точки */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(k > 0);
	// раскладка stack
	t = (word*)stack;
	m = (size_t*)(t + ec->d * n);
	naf_width = m + k;
	naf_size = naf_width + k;
	naf_pos = naf_size + k;
	naf = (word**)(naf_pos + k);
	pre = naf + k;
	stack = pre + k;
	// обработать параметры (a[i], d[i], m[i])
	va_start(marker, k);
	for (i = 0; i < k; ++i)
	{
		const word* a;
		const word* d;
		size_t naf_count;
		// a <- a[i]
		a = va_arg(marker, const word*);
		// d <- d[i]
		d = va_arg(marker, const word*);
		// прочитать m[i]
		m[i] = va_arg(marker, size_t);
		// подправить m[i]
		m[i] = wwWordSize(d, m[i]);
		// расчет naf[i]
		naf_width[i] = ecNAFWidth(B_OF_W(m[i]));
		naf_count = SIZE_1 << (naf_width[i] - 2);
		ASSERT(naf_count > 1);
		naf[i] = (word*)stack;
		stack = naf[i] + 2 * m[i] + 1;
		naf_size[i] = wwNAF(naf[i], d, m[i], naf_width[i]);
		if (naf_size[i] > naf_max_size)
			naf_max_size = naf_size[i];
		naf_pos[i] = 0;
		// резервируем память для pre[i]
		pre[i] = (word*)stack;
		stack = pre[i] + ec->d * n * naf_count;
#if 1
		//if (a == ec->base && ec->precomp_Gs && naf_width[i] <= ec->precomp_w + 1)
		//{
			//todo передавать как параметр
			//pre[i] = (word*)ec->precomp_Gs + ((2 * n) << (ec->precomp_w - 1));
		//}
		//else
		//{
		ecpSmallMultA(pre[i], NULL, a, naf_width[i] - 1, ec, stack);
		//}
#else
		// pre[i][0] <- a[i]
		ecFromA(pre[i], a, ec, stack);
		// расчет pre[i][j]: t <- 2a[i], pre[i][j] <- t + pre[i][j - 1]
		ecDblA(t, pre[i], ec, stack);
		ecAddA(pre[i] + ec->d * n, t, pre[i], ec, stack);
		for (j = 2; j < naf_count; ++j)
			ecAdd(pre[i] + j * ec->d * n, t, pre[i] + (j - 1) * ec->d * n, ec,
				stack);
#endif
	}
	va_end(marker);
	// t <- O
	ecSetO(t, ec);
	// основной цикл
	for (; naf_max_size; --naf_max_size)
	{
		// t <- 2 t
		ecDbl(t, t, ec, stack);
		// цикл по (a[i], naf[i])
		for (i = 0; i < k; ++i)
		{
			word naf_hi;
			// символы naf[i] не начались?
			if (naf_size[i] < naf_max_size)
				continue;
			// прочитать очередной символ naf[i]
			w = wwGetBits(naf[i], naf_pos[i], naf_width[i]);
			// обработать символ
			naf_hi = WORD_1 << (naf_width[i] - 1);
			if (w & 1)
			{
				// t <- t \pm pre[i][naf[i][w]]
				if (w & naf_hi)
					ecSubA(t, t, pre[i] + ((w ^ naf_hi) >> 1) * 2 * n, ec, stack);
				else
					ecAddA(t, t, pre[i] + (w >> 1) * 2 * n, ec, stack);
				// к следующему символу naf[i]
				naf_pos[i] += naf_width[i];
			}
			else
				++naf_pos[i];
		}
	}
	// очистка
	w = 0;
	// к аффинным координатам
	return ecToA(b, t, ec, stack);
}

size_t FAST(ecpAddMulAA_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t k, ...)
{
	size_t i, ret;
	va_list marker;
	ret = O_OF_W(ec_d * n);
	ret += 4 * sizeof(size_t) * k;
	ret += 2 * sizeof(word**) * k;
	va_start(marker, k);
	for (i = 0; i < k; ++i)
	{
		size_t m = va_arg(marker, size_t);
		size_t naf_width = ecNAFWidth(B_OF_W(m));
		size_t naf_count = SIZE_1 << (naf_width - 2);
		ret += O_OF_W(2 * m + 1);
		ret += O_OF_W(ec_d * n * naf_count);
	}
	va_end(marker);
	ret += ec_deep + 40 * 1024;
	return ret;
}
