/*
*******************************************************************************
\file ec.c
\brief Elliptic curves
\project bee2 [cryptographic library]
\created 2014.03.04
\version 2026.01.26
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdarg.h>
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ec.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Вспомогательные определения
*******************************************************************************
*/

#define ecPt(pts, pos, ec) ((pts) + (pos) * (ec)->d * (ec)->f->n)

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
		ec->d >= 3 &&
		ec->froma != 0 &&	
		ec->toa != 0 &&	
		ec->neg != 0 &&	
		ec->add != 0 &&	
		ec->adda != 0 &&	
		ec->dbl != 0 &&	
		ec->dbla != 0;
}

bool_t ecIsOperable(const ec_o* ec)
{
	return ecIsOperable2(ec) &&
		qrIsOperable(ec->f) &&
		wwIsValid(ec->A, ec->f->n) &&
		wwIsValid(ec->B, ec->f->n) &&
		ec->deep >= ec->f->deep;
}

bool_t ecGroupCreate(ec_o* ec, const octet xbase[], const octet ybase[], 
	const octet order[], size_t order_len, size_t cofactor, void* stack)
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
		(size_t)(word)cofactor != cofactor)
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

size_t ecGroupCreate_deep(size_t f_deep)
{
	return f_deep;
}

bool_t ecGroupIsOperable(const ec_o* ec)
{
	ASSERT(ecIsOperable(ec));
	return wwIsValid(ec->base, 2 * ec->f->n) &&
		wwIsValid(ec->order, ec->f->n + 1) &&
		!wwIsZero(ec->order, ec->f->n + 1) &&
		ec->cofactor != 0;
}

/*
*******************************************************************************
Предвычисления

Прямая реализация схемы SNZ:
	t <- 2a, pre[0] <- a, pre[i] <-  t + pre[i - 1], i = 1,..., 2^(w-1) - 1.

Сложение t + pre[0] выполняется по схеме P <- P + A. Остальные сложения -- по
схеме P <- P + P. Итоговая сложность:
	1(P <- 2A) + 1(P <- P + A) + (2^{w-1} - 2)(P <- P + P).

Здесь и далее
- (P <- 2A) -- время работы функции ec->dbla;
- (P <- P + A) -- время работы функций ec->adda;
- (P <- P + P) -- время работы функции ec->add.
*******************************************************************************
*/

#define ecSmul_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

static void ecSmul(word b[], const word a[], size_t w, const ec_o* ec,
	void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(w > 0);
	ASSERT(wwIsDisjoint2(b, ec->d * ec->f->n * (SIZE_1 << (w - 1)),
		a, 2 * ec->f->n) || a == b);
	// разметить стек
	memSlice(stack,
		ecSmul_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	// вычислить малые кратные
	if (w > 1)
	{
		size_t i;
		// t <- 2 a
		ecDblA(t, a, ec, stack);
		// b[1] <- t + a
		ecAddA(b + ec->d * ec->f->n, t, a, ec, stack);
		// b[i] <- t + b[i - 1]
		for (i = 2; i < SIZE_1 << (w - 1); ++i)
			ecAdd(b + i * ec->d * ec->f->n, t, b + (i - 1) * ec->d * ec->f->n,
				ec, stack);
	}
	// b[0] <- a
	ecFromA(b, a, ec, stack);
}

static size_t ecSmul_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecSmul_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Сложение с настройкой знака

Прямые нерегулярные реализации интерфейсов ec_finadd_i и ec_finadda_i.
*******************************************************************************
*/

#define ecFinAdd_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

static bool_t ecFinAdd(word c[], const word a[], const word b[],
	register word neg, const ec_o* ec, void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	ASSERT(ecIsOperable(ec));
	memSlice(stack,
		ecFinAdd_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	ecAdd(t, a, b, ec, stack);
	if (neg)
		ecNeg(t, t, ec, stack);
	return ecToA(c, t, ec, stack);
}

static size_t ecFinAdd_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecFinAdd_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

#define ecFinAddA_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

static bool_t ecFinAddA(word c[], const word a[], const word b[],
	register word neg, const ec_o* ec, void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	ASSERT(ecIsOperable(ec));
	memSlice(stack,
		ecFinAddA_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	ecAddA(t, a, b, ec, stack);
	if (neg)
		ecNeg(t, t, ec, stack);
	return ecToA(c, t, ec, stack);
}

static size_t ecFinAddA_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecFinAddA_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Кратная точка: NAF (Non-Adjacent Form)

В функции ecMulA() для определения b = da (d-кратного точки a) применяется
оконный NAF с длиной окна w > 2. Реализован алгоритм 3.36 из [HMV04].

Используются малые нечетные кратные a:
	b[i] = (2i + 1)a,  i = 0, 1, ..., 2^{w-2} - 1.

Имеются три стратегии:
1)	w = 2 и малые кратные вообще не рассчитываются;
2)	w > 2 и малые кратные рассчитываются в аффинных координатах;
3)	w > 2 и малые кратные рассчитываются в проективных координатах.

Если малые кратные рассчитываются по схеме "последовательно складывать
с удвоенной исходной точкой", то средняя общая сложность нахождения
кратной точки (l = wwBitSize(d)):
1)	c1(l) = l/3(P <- P + A);
2)	c2(l, w) = 1(A <- 2A) + 1(P <- P + A) +
		(2^{w-2} - 2)(A <- A + A) + l/(w + 1)(P <- P + A);
3)	c3(l, w) = 1(P <- 2A) + 1(P <- P + A) +
		(2^{w-2} - 2)(P <- P + P) + l/(w + 1)(P <- P + P),
без учета общего во всех стратегиях слагаемого l(P <- 2P).

Здесь
- (A <- 2A) -- время работы каскада (ec->dbla, ec->toa)*;
- (A <- A + A) -- время работы каскада (ec->adda, ec->toa)*;
- (P <- 2P) -- время работы функции ec->dbl.
-----------------------------------------------------
* [или прямых вычислений в аффинных координатах]

Реализована третья стратегия. Она является выигрышной для кривых над GF(p)
в практических диапазонах размерностей при использовании наиболее эффективных
(якобиевых) координат.

Длина окна w выбирается как решение следующей оптимизационной задачи:
	(2^{w - 2} - 2) + l / (w + 1) -> min.

Предвычисления выполняются с помощью функции ecSmul().

\todo Усилить вторую стратегию. Рассчитать малые кратные в проективных
координатах, а затем быстро перейти к аффинным координатам с помощью
трюка Монтгомери [Doc05; algorithm 11.15 -- simultaneous inversion, p. 209]:
	U_1 <- Z_1
	for t = 2,..., T: U_t <- U_{t-1} Z_t
	V <- U_T^{-1}
	for t = T,..., 2:
		Z_t^{-1} <- V U_{t-1}
		V <- V Z_t
	Z_1^{-1} <- V

[Doc05] Doche C. Finite Field Arithmetic. In: Handbook of Elliptic and
        Hyperelliptic Curve Cryptography. Chapman & Hall/CRC, 2005.
[HMV04] Hankerson D., Menezes A., Vanstone S. Guide to Elliptic Curve
        Cryptography, Springer, 2004.
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

#define ecMulA_local(n, ec_d, m, pre_count)\
/* naf */	O_OF_W(2 * m + 1),\
/* t */		O_OF_W(ec_d * n),\
/* pre */	O_OF_W(pre_count * ec_d * n)

bool_t ecMulA(word b[], const word a[], const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const word naf_hi = WORD_BIT_POS(naf_width - 1);
	const size_t pre_count = SIZE_1 << (naf_width - 1);
	register size_t naf_size;
	register size_t i;
	register word digit;
	word* naf;			/* [2 * m + 1] NAF */
	word* t;			/* [ec->d * ec->f->n] */
	word* pre;			/* [pre_count * ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	// разметить стек
	memSlice(stack,
		ecMulA_local(ec->f->n, ec->d, m, pre_count), SIZE_0, SIZE_MAX,
		&naf, &t, &pre, &stack);
	// расчет NAF
	ASSERT(naf_width >= 3);
	naf_size = wwNAF(naf, d, m, naf_width);
	// d == O => b <- O
	if (naf_size == 0)
		return FALSE;
	// малые кратные: a, 3a, ..., (2^w - 1)a
	ecSmul(pre, a, naf_width - 1, ec, stack);
	// отрицательные малые кратные: -a, -3a, ..., -(2^w - 1)a
	for (i = 0; i < pre_count / 2; ++i)
		ecNeg(ecPt(pre, pre_count / 2 + i, ec), ecPt(pre, i, ec), ec, stack);
	// старшая цифра NAF
	digit = wwGetBits(naf, 0, naf_width);
	ASSERT((digit & 1) == 1 && (digit & naf_hi) == 0);
	// t <- pre[digit / 2]
	wwCopy(t, ecPt(pre, digit >> 1, ec), ec->d * ec->f->n);
	// цикл по цифрам NAF
	i = naf_width;
	while (--naf_size)
	{
		digit = wwGetBits(naf, i, naf_width);
		// t <- 2t + pre[digit / 2]
		if (digit == 1 || digit == (naf_hi ^ 1))
			ecDblAddA(t, t, ecPt(pre, digit >> 1, ec), ec, stack);
		else
		{
			// t <- 2t
			ecDbl(t, t, ec, stack);
			if (digit & 1)
				// t <- t + pre[digit / 2]
				ecAdd(t, t, ecPt(pre, digit >> 1, ec), ec, stack);
		}
		// к следующей цифре
		i += (digit & 1) ? naf_width : 1;
	}
	// очистка
	CLEAN2(digit, i);
	// к аффинным координатам
	return ecToA(b, t, ec, stack);
}

size_t ecMulA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t pre_count = SIZE_1 << (naf_width - 1);
	return memSliceSize(
		ecMulA_local(n, ec_d, m, pre_count),
		ecSmul_deep(n, ec_d, ec_deep),
		SIZE_MAX);
}

/*
*******************************************************************************
Кратная точка: SNZ (Signed Non-Zero)

В функции ecMulA2() для определения кратной точки b = da при нечетной 
кратности d используется ее представление в форме
	d_0 + d_1 (2^w) + ... + d_{k-1} (2^w)^{k-1}.
Здесь d_i \in {\pm 1, \pm 3, ..., \pm (2^w - 1)} -- ненулевые (нечетные) цифры
со знаком (signed non-zero). Предполагается, что точка a лежит в группе
нечетного порядка order, (2^w)^{k-1} < order < (2^w)^k. Представление SNZ
предложено в [OkeTak03].

Если кратность d четная, то она предварительно меняется на order - d.
Для этого используется функция zzSubIf().

Реализован следующий алгоритм (см. [BCL+14; p. 9-11, algorithm 1], 
а также [APS22]):
1. Для i = 0, 1, ..., (2^{w-1} - 1):
	1) pre[i] <- (2i - 1)a;				// ecSmul
	2) pre[-i] <- -pre[i].				// ec_neg_i
2. t <- pre[d_{k-1} / 2]
3. Для i = k - 2, ..., 1:
	1) t <- 2^w t;						// ec_dbl_i
	1) t <- t + pre[d_i / 2].			// ec_add_i
4. t <- 2^w t.
5. t <- t + pre[d_0].					// ec_finadd_i
6. Возвратить t.

\remark сложение t + pre[d_0] вынесено за рамки основного цикла на шаге 3,
потому что при этом (и только при этом) сложении может произойти исключительная
ситуация -- совпадение операндов t и pre[d_0] с переключением от сложения
к удвоению. Предполагается, что функция ec_finadd_i регулярна, и тогда сложение
и удвоение будут выполняться по одним и тем же формулам.

[OkeTak03] Okeya K., Takagi T. The width-w NAF method provides small memory and
           fast elliptic scalar multiplications secure against side channel
		   attacks. In Cryptographers’ Track at the RSA Conference, 2003,
		   pp. 328-343. Springer Berlin Heidelberg.
[BCL+14]   Bos J.W., Costello C., Longa P., Naehrig M. Selecting Elliptic
		   Curves for Cryptography: An Efficiency and Security Analysis, 2014,
		   https://eprint.iacr.org/2014/130.pdf.
[APS22]    Agievich S., Poruchnik S., Semenov V. Small scalar multiplication
		   on Weierstrass curves using division polynomials. Mat. Vopr.
		   Kriptogr., 13:2, 2022, https://doi.org/10.4213/mvk406.
*******************************************************************************
*/

static size_t ecSNZWidth(size_t l)
{
	if (l <= 256)
		return 5;
	return 6;
}

#define ecMulA2_local(n, ec_d, m, pre_count)\
/* dd */	O_OF_W(m),\
/* t */		O_OF_W(ec_d * n),\
/* pre */	O_OF_W(pre_count * ec_d * n)

bool_t ecMulA2(word b[], const word a[], const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	register word neg;
	register word digit;
	register word hi;
	register bool_t ret;
	size_t mb;
	size_t snz_width;
	size_t pre_count;
	size_t k;
	size_t i;
	word* dd;			/* [m] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pre;			/* [pre_count * ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(wwWordSize(ec->order, ec->f->n + 1) == m);
	ASSERT(zzIsOdd(ec->order, m) && m > 1);
	ASSERT(wwCmp(d, ec->order, m) < 0);
	// размерности
	mb = wwBitSize(ec->order, m);
	snz_width = ecSNZWidth(mb);
	ASSERT(3 <= snz_width && snz_width < B_PER_W);
	pre_count = SIZE_1 << snz_width;
	// разметить стек
	memSlice(stack,
		ecMulA2_local(ec->f->n, ec->d, m, pre_count), SIZE_0, SIZE_MAX,
		&dd, &t, &pre, &stack);
	// dd <- (d & 1) ? d : ec->order - d
	neg = WORD_1 - (d[0] & 1);
	zzSubIf(dd, ec->order, d, m, neg);
	ASSERT(zzIsOdd(dd, m));
	// малые кратные: a, 3a, ..., (2^w - 1)a
	ecSmul(pre, a, snz_width, ec, stack);
	// отрицательные малые кратные: -(2^w - 1)a, ..., -3a, -a
	for (i = 0; i < pre_count / 2; ++i)
		ecNeg(ecPt(pre, pre_count - 1 - i, ec), ecPt(pre, i, ec), ec, stack);
	// число цифр SNZ
	k = (mb + snz_width - 1) / snz_width;
	ASSERT(k > 1);
	// старшая цифра
	--k;
	digit = wwGetBits(dd, k * snz_width, mb - k * snz_width);
	wwCopy(t, ecPt(pre, digit >> 1, ec), ec->d * ec->f->n);
	hi = WORD_1 - (digit & 1), hi <<= snz_width - 1;
	// обработать остальные цифры
	while (--k)
	{
		for (i = snz_width; i--;)
			ecDbl(t, t, ec, stack);
		digit = wwGetBits(dd, k * snz_width, snz_width);
		ecAdd(t, t, ecPt(pre, hi | (digit >> 1), ec), ec, stack);
		hi = WORD_1 - (digit & 1), hi <<= snz_width - 1;
	}
	// завершающие удвоения и финишное сложение
	for (i = snz_width; i--;)
		ecDbl(t, t, ec, stack);
	digit = wwGetBits(dd, 0, snz_width);
	ASSERT(digit & 1);
	ret = (ec->finadd) ?
		ec->finadd(b, t, ecPt(pre, hi | (digit >> 1), ec), neg, ec, stack) :
		ecFinAdd(b, t, ecPt(pre, hi | (digit >> 1), ec), neg, ec, stack);
	// очистка и возврат
	CLEAN3(neg, digit, hi);
	return ret;
}

size_t ecMulA2_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t snz_width = ecSNZWidth(B_OF_W(m));
	const size_t pre_count = SIZE_1 << snz_width;
	return memSliceSize(
		ecMulA2_local(n, ec_d, m, pre_count),
		utilMax(2,
			ecSmul_deep(n, ec_d, ec_deep),
			ecFinAdd_deep(n, ec_d, ec_deep)),
		SIZE_MAX);
}

/*
*******************************************************************************
Имеет порядок?
*******************************************************************************
*/

#define ecHasOrderA_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

bool_t ecHasOrderA(const word a[], const ec_o* ec, const word q[], size_t m,
	void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	// разметить стек
	memSlice(stack,
		ecHasOrderA_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	// q a == O?
	return !ecMulA(t, a, ec, q, m, stack);
}

size_t ecHasOrderA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecHasOrderA_local(n, ec_d), 
		ecMulA_deep(n, ec_d, ec_deep, m),
		SIZE_MAX);
}

/*
*******************************************************************************
Сумма кратных точек

Реализован алгоритм 3.51 (interleaving with NAF) из [HMV04].

Для каждого d[i] строится naf[i] длиной l[i] с шириной окна w[i].

Сложность алгоритма:
	max l[i](P <- 2P) + \sum {i=1}^k
		[1(P <- 2A) + (2^{w[i]-2}-2)(P <- P + P) + l[i]/(w[i]+1)(P <- P + P)].
*******************************************************************************
*/

#define ecAddMulA_local(n, ec_d, k)\
/* t */			O_OF_W(ec_d * n),\
/* m */			O_PER_S * k,\
/* naf_width */	O_PER_S * k,\
/* naf_size */	O_PER_S * k,\
/* naf_pos */	O_PER_S * k,\
/* naf */		sizeof(word*) * k,\
/* pre */		sizeof(word*) * k

bool_t ecAddMulA(word b[], const ec_o* ec, void* stack, size_t k, ...)
{
	register size_t naf_max_size;
	register word digit;
	size_t i;
	va_list args;
	word* t;			/* [ec->d * ec->f->n] проективная точка */
	size_t* m;			/* [k] длины d[i] */
	size_t* naf_width;	/* [k] размеры NAF-окон */
	size_t* naf_size;	/* [k] длины NAF */
	size_t* naf_pos;	/* [k] позиция в NAF-представлении */
	word** naf;			/* [k] NAF */
	word** pre;			/* [k] предвычисленные точки */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(k > 0);
	// разметить стек
	memSlice(stack,
		ecAddMulA_local(ec->f->n, ec->d, k), SIZE_0, SIZE_MAX,
		&t, &m, &naf_width, &naf_size, &naf_pos, &naf, &pre, &stack);
	// обработать параметры (a[i], d[i], m[i])
	va_start(args, k);
	naf_max_size = 0;
	for (i = 0; i < k; ++i)
	{
		const word* a;
		const word* d;
		size_t pre_count;
		size_t j;
		// a <- a[i]
		a = va_arg(args, const word*);
		// d <- d[i]
		d = va_arg(args, const word*);
		// прочитать m[i]
		m[i] = va_arg(args, size_t);
		// подправить m[i]
		m[i] = wwWordSize(d, m[i]);
		// зарезервировать память для naf[i] и pre[i]
		naf_width[i] = ecNAFWidth(B_OF_W(m[i]));
		pre_count = SIZE_1 << (naf_width[i] - 1);
		memSlice(stack,
			O_OF_W(2 * m[i] + 1), O_OF_W(ec->d * ec->f->n * pre_count), SIZE_0,
			SIZE_MAX,
			naf + i, pre + i, &stack);
		// расчет naf[i]
		naf_size[i] = wwNAF(naf[i], d, m[i], naf_width[i]);
		if (naf_size[i] > naf_max_size)
			naf_max_size = naf_size[i];
		naf_pos[i] = 0;
		// малые кратные
		ecSmul(pre[i], a, naf_width[i] - 1, ec, stack);
		// отрицательные малые кратные
		for (j = 0; j < pre_count / 2; ++j)
			ec->neg(pre[i] + (pre_count / 2 + j) * ec->d * ec->f->n,
				pre[i] + j * ec->d * ec->f->n, ec, stack);
	}
	va_end(args);
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
			// цифры naf[i] не начались?
			if (naf_size[i] < naf_max_size)
				continue;
			// прочитать очередную цифру naf[i]
			digit = wwGetBits(naf[i], naf_pos[i], naf_width[i]);
			// обработать цифру
			naf_hi = WORD_BIT_POS(naf_width[i] - 1);
			if (digit & 1)
			{
				// t <- t + pre[i][digit / 2]
				if (digit == 1 || digit == (naf_hi ^ 1))
					ecAddA(t, t, pre[i] + (digit / 2) * ec->d * ec->f->n, ec,
						stack);
				else
					ecAdd(t, t, pre[i] + (digit / 2) * ec->d * ec->f->n, ec,
						stack);
				// к следующей цифре naf[i]
				naf_pos[i] += naf_width[i];
			}
			else
				// к следующей цифре
				++naf_pos[i];
		}
	}
	// очистка
	CLEAN2(naf_max_size, digit);
	// к аффинным координатам
	return ecToA(b, t, ec, stack);
}

size_t ecAddMulA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t k, ...)
{
	size_t i, ret;
	va_list args;
	ret = memSliceSize(
		ecAddMulA_local(n, ec_d, k),
		ecSmul_deep(n, ec_d, ec_deep),
		SIZE_MAX);
	va_start(args, k);
	for (i = 0; i < k; ++i)
	{
		size_t m = va_arg(args, size_t);
		size_t naf_width = ecNAFWidth(B_OF_W(m));
		size_t pre_count = SIZE_1 << (naf_width - 1);
		ret += memSliceSize(
			O_OF_W(2 * m + 1),
			O_OF_W(ec_d * n * pre_count),
			SIZE_0,	SIZE_MAX);
	}
	va_end(args);
	return ret;
}
