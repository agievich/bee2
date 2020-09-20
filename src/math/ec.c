/*
*******************************************************************************
\file ec.c
\brief Elliptic curves
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.03.04
\version 2015.11.09
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
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Управление описанием кривой
*******************************************************************************
*/

bool_t ecIsOperable2(const ec_o* ec)
{
	return objIsOperable2(ec) &&
		objKeep(ec) >= sizeof(ec_o) &&
		objPCount(ec) == 6 &&
		objOCount(ec) == 1 &&
		wwIsValid(ec->A, ec->f->n) &&
		wwIsValid(ec->B, ec->f->n) &&
		ec->d >= 3 &&
		ec->froma != 0 &&	
		ec->toa != 0 &&	
		ec->neg != 0 &&	
		ec->add != 0 &&	
		ec->adda != 0 &&	
		ec->sub != 0 &&	
		ec->suba != 0 &&	
		ec->dbl != 0 &&	
		ec->dbla != 0;
}

bool_t ecIsOperable(const ec_o* ec)
{
	return ecIsOperable2(ec) &&
		qrIsOperable(ec->f) &&
		ec->deep >= ec->f->deep;
}

bool_t ecCreateGroup(ec_o* ec, const octet xbase[], const octet ybase[], 
	const octet order[], size_t order_len, u32 cofactor, void* stack)
{
	ASSERT(ecIsOperable(ec));
	ASSERT(memIsValid(order, order_len));
	ASSERT(memIsNullOrValid(xbase, ec->f->no));
	ASSERT(memIsNullOrValid(ybase, ec->f->no));
	// корректное описание?
	order_len = memNonZeroSize(order, order_len);
	if (order_len == 0 || 
		W_OF_O(order_len) > ec->f->n + 1 ||
		cofactor == 0 || 
		(u32)(word)cofactor != cofactor)
		return FALSE;
	// установить базовую точку
	if (xbase == 0)
		qrSetZero(ecX(ec->base), ec->f);
	else if (!qrFrom(ecX(ec->base), xbase, ec->f, stack))
		return FALSE;
	if (ybase == 0)
		qrSetZero(ecY(ec->base, ec->f->n), ec->f);
	else if (!qrFrom(ecY(ec->base, ec->f->n), ybase, ec->f, stack))
		return FALSE;
	// установить порядок и кофактор
	wwFrom(ec->order, order, order_len);
	wwSetZero(ec->order + W_OF_O(order_len), 
		ec->f->n + 1 - W_OF_O(order_len));
	ec->cofactor = (word)cofactor;
	// все нормально
	return TRUE;
}

size_t ecCreateGroup_deep(size_t f_deep)
{
	return f_deep;
}

bool_t ecIsOperableGroup(const ec_o* ec)
{
	ASSERT(ecIsOperable(ec));
	return wwIsValid(ec->base, 2 * ec->f->n) &&
		wwIsValid(ec->order, ec->f->n + 1) &&
		!wwIsZero(ec->order, ec->f->n + 1) &&
		ec->cofactor != 0;
}

/*
*******************************************************************************
Кратная точка

Для определения b = da (d-кратное точки a) используется оконный NAF с
длиной окна w. В функции ecMulWNAF() реализован алгоритм 3.35 из 
[Hankerson D., Menezes A., Vanstone S. Guide to Elliptic Curve Cryptography, 
Springer, 2004].

Предварительно рассчитываются малые кратные a: сначала 2a, а затем
точки a[i] = a[i - 1] + 2a, i = 1,\ldots, 2^{w - 1} - 2, где a[0] = a.

При использовании проективных координат имеются три стратегии:
1)	w = 2 и малые кратные вообще не рассчитываются;
2)	w > 2 и малые кратные рассчитываются в аффинных координатах;
3)	w > 2 и малые кратные рассчитываются в проективных координатах.

Средняя общая сложность нахождения кратной точки (l = wwBitSize(d)):
1)	c1(l) = l/3(P <- P + A);
2)	c2(l, w) = 1(A <- 2A) + (2^{w-2} - 2)(A <- A + A) + l/(w + 1)(P <- P + A);
3)	c3(l, w) = 1(P <- 2A) + (2^{w-2} - 2)(P <- P + P) + l/(w + 1)(P <- P + P),
без учета общего во всех стратегиях слагаемого l(P <- 2P).

Здесь 
- (P <- P + A) -- время работы функций ec->adda / ec->suba;
- (A <- 2A) -- время работы каскада (ec->dbla, ec->toa)*;
- (A <- A + A) -- время работы каскада (ec->adda, ec->toa)*;
- (P <- 2A) -- время работы функции ec->dbla;
- (P <- P + P) -- время работы функции ec->add / ec->sub;
- (P <- 2P) -- время работы функции ec->dbl.
-----------------------------------------------------
* [или прямых вычислений в аффинных координатах]


В практических диапазонах размерностей при использовании наиболее эффективных
координат (якобиановых для кривых над GF(p) и Лопеса -- Дахаба для кривых 
над GF(2^m)) первые две стратегии являются проигрышными. Реализована только 
третья стратегия. 

Оптимальная длина окна выбирается как решение следующей оптимизационной 
задачи:
	(2^{w - 2} - 2) + l / (w + 1) -> min.

\todo Усилить вторую стратегию. Рассчитать малые кратные в проективных 
координатах, а затем быстро перейти к аффинным координатам с помощью 
трюка Монтгомери [Algorithm 11.15 Simultaneous inversion, CohenFrey, p. 209]:
	U_1 <- Z_1
	for t = 2,..., T: U_t <- U_{t-1} Z_t
	V <- U_T^{-1}
	for t = T,..., 2: 
		Z_t^{-1} <- V U_{t-1}
		V <- V Z_t
	Z_1^{-1} <- V
*******************************************************************************
*/

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

bool_t FAST(ecMulA)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, void* stack)
{
	const size_t n = ec->f->n;
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t naf_count = SIZE_1 << (naf_width - 2);
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
	t = naf + 2 * m + 1;
	pre = t + ec->d * n;
	stack = pre + naf_count * ec->d * n;
	// расчет NAF
	ASSERT(naf_width >= 3);
	naf_size = wwNAF(naf, d, m, naf_width);
	// d == O => b <- O
	if (naf_size == 0)
		return FALSE;
	// pre[0] <- a
	ecFromA(pre, a, ec, stack);
	// расчет pre[i]: t <- 2a, pre[i] <- t + pre[i - 1]
	ASSERT(naf_count > 1);
	ecDblA(t, pre, ec, stack);
	ecAddA(pre + ec->d * n, t, pre, ec, stack);
	for (i = 2; i < naf_count; ++i)
		ecAdd(pre + i * ec->d * n, t, pre + (i - 1) * ec->d * n, ec, stack);
	// t <- a[naf[l - 1]]
	w = wwGetBits(naf, 0, naf_width);
	ASSERT((w & 1) == 1 && (w & naf_hi) == 0);
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
			if (w == 1)
				ecAddA(t, t, pre, ec, stack);
			else if (w == (naf_hi ^ 1))
				ecSubA(t, t, pre, ec, stack);
			else if (w & naf_hi)
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

size_t FAST(ecMulA_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t naf_count = SIZE_1 << (naf_width - 2);
	return O_OF_W(2 * m + 1) + 
		O_OF_W(ec_d * n) + 
		O_OF_W(ec_d * n * naf_count) + 
		ec_deep;
}

bool_t SAFE(ecMulA)(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, void* stack)
{
	const size_t point_size = ec->f->n * ec->d;
		
	//window width of recording
	//todo resolve width by used sm_mult algorithm and l size
	const size_t window_width = ecNAFWidth(B_OF_W(m));
	
	//set size of small multiples |{+-1, +-3, ..., +-(2^w - 1)}| = 2^w  
	const size_t odd_recording_set_size = SIZE_1 << window_width;

	//2^w, required for positive/negative decoding of recording
	const word hi_bit = WORD_1 << window_width;
	
	//number of elements in actual odd recording of d
	const size_t odd_recording_size = wwOddRecording_size(m, window_width);
	
	register int i;
	register word w;
	register word sign;
	
	word delta = WORD_1;
	word b_flag;

	// переменные в stack
	word* odd_recording;			/* Odd Recording */
	word* t;			/* 2 вспомогательных точки */
	word* pre;			/* pre[i] =  (odd_recording_size элементов) */
	word* q;			/* вспомогательная точка */
	word* temp;			/* вспомогательное число */
	// pre
	ASSERT(ecIsOperable(ec));
	
	// раскладка stack
	odd_recording = (word*)stack;
	t = odd_recording + W_OF_B(odd_recording_size * (window_width + 1));
	pre = t + 2 * point_size;
	q = pre + odd_recording_set_size * point_size;
	temp = q + point_size;
	stack = temp + m;
	
	ASSERT(window_width >= 2);

	//t[0] <- 2a
	ecDblA(t, a, ec, stack);

	// расчет pre[i]: pre[2i] = pre[2i - 2] + 2a, pre[2i + 1] = -pre[2i], i > 0
	// pre[0] <- a, pre[1] <- -a
	sm_mult_add(pre, a, t, window_width, ec, stack);

	// переход к нечетной кратности
	delta += d[0] & WORD_1;	
	zzAddW(temp, d, m, delta);

	//1, 0, -1
	b_flag = wwCmp2(temp, m, ec->order, ec->f->n);
	//-1 -> 0
	b_flag = wordEq0M(b_flag, WORD_1);
	
	//recalculate temp
	zzSubW2(temp, m, (delta * 2) & b_flag);

	// save point, current sequence in stack: t[0] <- 2a, t[1] <- -2a, pre[0] = a, pre[1] = -a => t[0]=2a, t[1]=-2a, t[2]=a, t[3]=-a
	ecNeg(t + point_size, t, ec, stack);
	//if b_flag = 11111111_2 (binary) => need addition, add delta*a, else sub delta*a, delta = 1, 2;
	//t += (((delta – 2) & 2) - (~b_flag)) * point_size;
	b_flag = ~b_flag;
	delta -= 2;
	delta &= 2;
	delta -= b_flag;
	delta *= point_size;
	t += delta;
	
	// расчет Odd_Recording
	ASSERT(window_width >= 3);
	wwOddRecording(odd_recording, W_OF_B(odd_recording_size * (window_width + 1)),
					temp, m, odd_recording_size, window_width);
	
	// q <- odd_recording[k-1] * a
	w = wwGetBits(odd_recording, (odd_recording_size - 1) * (window_width + 1), window_width + 1);
		
	//calculate index
	ASSERT((w & 1) && (w & hi_bit) == 0);
	w ^= WORD_1;
	//save
	wwCopy(q, pre + w * point_size, point_size);
	
	for (i = odd_recording_size - 2; i >= 0; --i) {
		//Q <- 2^odd_recording_width * Q
		w = window_width;
		while (w) {
			ecDbl(q, q, ec, stack);
			--w;
		}

		w = wwGetBits(odd_recording, i * (window_width + 1), window_width + 1);
		// calculate index
		sign = w & hi_bit;
		w ^= sign;	
		ASSERT((w & 1) && (w & hi_bit) == 0);
		sign >>= window_width;
		sign = ~sign;
		sign &= WORD_1;
		w ^= sign;
		// add
		ecAdd(q, q, pre + w * point_size, ec, stack);
	}

	// correction
	ecAdd(q, q, t, ec, stack);
	
	// cleanup
	w = 0;
	i = 0;
	t = NULL;
	sign = 0;
	delta = 0;
	b_flag = 0; 
	
	// к аффинным координатам
	return ecToA(b, q, ec, stack);
}

size_t SAFE(ecMulA_deep)(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t point_size = n * ec_d;
	const size_t odd_recording_width = ecNAFWidth(B_OF_W(m));
	const size_t odd_recording_count = SIZE_1 << odd_recording_width;
	const size_t odd_recording_size = (m * B_PER_W + odd_recording_width - 1) / odd_recording_width;

	return O_OF_W(W_OF_B(odd_recording_size * (odd_recording_width + 1))) +
		O_OF_W(2 * point_size) +
		O_OF_W(odd_recording_count * point_size) +
		O_OF_W(point_size) +
		O_OF_W(m) +
		ec_deep;
}


/*
Вычисление малых кратных P, -P, 3P, -3P, ... , -(2^w - 1)P
Вычисление через сложение P + 2P, 3P + 2P, ...
На входе pre[0] = P
todo продумать общий интерфейс для вычисления малых кратных
[2n]p - в афинных координатах,
[3n]dblP - в проективных координатах

*/
bool_t sm_mult_add(word pre[], const word p[], const word dblP
	[], const word w, const ec_o* ec, void* stack) {
	const size_t point_size = ec->f->n * ec->d;

	//set size of small multiples |{+-1, +-3, ..., +-(2^w - 1)}| = 2^w  
	const size_t odd_recording_set_size = SIZE_1 << w;

	register int i;

	ecFromA(pre, p, ec, stack);
	ecNeg(pre + point_size, pre, ec, stack);


	for (i = 1; (unsigned)i <= odd_recording_set_size / 2 - 1; ++i) {
		ecAdd(pre + 2 * i * point_size, pre + (2 * i - 2) * point_size, dblP, ec, stack);
		ecNeg(pre + (2 * i + 1) * point_size, pre + 2 * i * point_size, ec, stack);
	}

}

/*
*******************************************************************************
Имеет порядок?
*******************************************************************************
*/

bool_t ecHasOrderA(const word a[], const ec_o* ec, const word q[], size_t m,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* b = (word*)stack;
	stack = b + ec->d * n;
	// q a == O?
	return !ecMulA(b, a, ec, q, m, stack);
}

size_t ecHasOrderA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return O_OF_W(ec_d * n) + ecMulA_deep(n, ec_d, ec_deep, m);
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

bool_t ecAddMulA(word b[], const ec_o* ec, void* stack, size_t k, ...)
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
		size_t naf_count, j;
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
		naf[i] = (word*)stack;
		stack = naf[i] + 2 * m[i] + 1;
		naf_size[i] = wwNAF(naf[i], d, m[i], naf_width[i]);
		if (naf_size[i] > naf_max_size)
			naf_max_size = naf_size[i];
		naf_pos[i] = 0;
		// резервируем память для pre[i]
		pre[i] = (word*)stack;
		stack = pre[i] + ec->d * n * naf_count;
		// pre[i][0] <- a[i]
		ecFromA(pre[i], a, ec, stack);
		// расчет pre[i][j]: t <- 2a[i], pre[i][j] <- t + pre[i][j - 1]
		ASSERT(naf_count > 1);
		ecDblA(t, pre[i], ec, stack);
		ecAddA(pre[i] + ec->d * n, t, pre[i], ec, stack);
		for (j = 2; j < naf_count; ++j)
			ecAdd(pre[i] + j * ec->d * n, t, pre[i] + (j - 1) * ec->d * n, ec,
				stack);
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
				if (w == 1)
					ecAddA(t, t, pre[i], ec, stack);
				else if (w == (naf_hi ^ 1))
					ecSubA(t, t, pre[i], ec, stack);
				else if (w & naf_hi)
					w ^= naf_hi,
					ecSub(t, t, pre[i] + (w >> 1) * ec->d * n, ec, stack);
				else
					ecAdd(t, t, pre[i] + (w >> 1) * ec->d * n, ec, stack);
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

size_t ecAddMulA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t k, ...)
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
	ret += ec_deep;
	return ret;
}
