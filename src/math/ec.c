/*
*******************************************************************************
\file ec.c
\brief Elliptic curves
\project bee2 [cryptographic library]
\created 2014.03.04
\version 2026.02.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdarg.h>
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ec.h"
#include "bee2/math/qr.h"
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
		ec->d >= 3 &&
		ec->froma != 0 &&	
		ec->toa != 0 &&	
		ec->neg != 0 &&	
		ec->nega != 0 &&	
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

В функции ecPreSNZ() реализованы предвычисления по схеме SNZ. Используется 
следуюший алгоритм:
- t <- 2a;													// P <- 2A
- pt[0] <- a;
- pt[1] <- t + pt[0];										// P <- P + A
- pt[i] <- t + pt[i - 1], i = 2, 3, ..., 2^{w-1} - 1.		// P <- P + P

Итоговая сложность:
	1(P <- 2A) + 1(P <- P + A) + (2^{w-1} - 2)(P <- P + P).

В функции ecPreSNZA() реализованы предвычисления по схеме SNZA. Используется 
тот же алгоритм, только операция P <- 2A в нем меняется на A <- 2A, а операции
P <- P + A и P <- P + P меняются на A <- A + A.

Итоговая сложность:
	1(P <- 2A) + (2^{w-1} - 1)(A <- A + A).

Перечень операций (здесь и далее):
- (P <- 2A) -- время работы функции ec->dbla;
- (P <- P + A) -- время работы функций ec->adda;
- (P <- P + P) -- время работы функции ec->add.
- (A <- 2A) -- время работы каскада (ec->dbla, ec->toa)*;
- (A <- A + A) -- время работы каскада (ec->adda, ec->toa)*;
- (P <- 2P) -- время работы функции ec->dbl.
-----------------------------------------------------
* [или прямых вычислений в аффинных координатах]
*******************************************************************************
*/

bool_t ecPreIsOperable(const ec_pre_t* pre)
{
	return memIsValid(pre, sizeof(pre)) &&
		(pre->type == ec_pre_snz || pre->type == ec_pre_snza ||
			pre->type == ec_pre_snzh || pre->type == ec_pre_hpb) &&
		pre->w > 0 && pre->w < B_PER_W &&
		((pre->type != ec_pre_snzh && pre->type != ec_pre_hpb) ^ (pre->h > 0));
}

#define ecPreSNZ_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

void ecPreSNZ(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	size_t i;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(w > 0);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(SIZE_BIT_POS(w - 1) * ec->d * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecPreSNZ_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	// pt[0] <- a
	ecFromA(ecPrePt(pre, 0, ec), a, ec, stack);
	// вычислить малые кратные
	if (w > 1)
	{
		// t <- 2 a
		ecDblA(t, a, ec, stack);
		// pt[1] <- t + a
		ecAddA(ecPrePt(pre, 1, ec), t, a, ec, stack);
		// pt[i] <- t + pt[i - 1]
		for (i = 2; i < SIZE_BIT_POS(w - 1); ++i)
			ecAdd(ecPrePt(pre, i, ec), t, ecPrePt(pre, i - 1, ec), ec, stack);
	}
	// заполнить служебные поля
	pre->type = ec_pre_snz;
	pre->w = w, pre->h = 0;
}

size_t ecPreSNZ_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecPreSNZ_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

#define ecPreSNZA_local(n, ec_d)\
/* t1 */	O_OF_W(ec_d * n),\
/* t2 */	O_OF_W(ec_d * n)

bool_t ecPreSNZA(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack)
{
	word* t1;			/* [ec->d * ec->f->n] */
	word* t2;			/* [ec->d * ec->f->n] */
	size_t i;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(w > 0);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(SIZE_BIT_POS(w - 1) * 2 * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecPreSNZA_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t1, &t2, &stack);
	// pt[0] <- a
	wwCopy(ecPrePtA(pre, 0, ec), a, 2 * ec->f->n);
	// вычислить малые кратные
	if (w > 1)
	{
		// t1 <- 2 a
		ecDblA(t1, a, ec, stack);
		// pt[i] <- t1 + pt[i - 1]
		for (i = 1; i < SIZE_BIT_POS(w - 1); ++i)
		{
			ecAddA(t2, t1, ecPrePtA(pre, i - 1, ec), ec, stack);
			if (!ecToA(ecPrePtA(pre, i, ec), t2, ec, stack))
				return FALSE;
		}
	}
	// заполнить служебные поля
	pre->type = ec_pre_snza;
	pre->w = w, pre->h = 0;
	return TRUE;
}

size_t ecPreSNZA_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecPreSNZA_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

#define ecPreSNZH_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

bool_t ecPreSNZH(ec_pre_t* pre, const word a[], size_t w, size_t h,
	const ec_o* ec, void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	size_t i;
	word* prev;
	word* cur;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(w > 0 && h > 0);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(SIZE_BIT_POS(w - 1) * h * 2 * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecPreSNZH_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	// первая строка
	if (!ecPreSNZA(pre, a, w, ec, stack))
		return FALSE;
	// остальные строки
	prev = pre->pts, cur = prev + SIZE_BIT_POS(w - 1) * 2 * ec->f->n;
	for (i = 0; i < h; ++i)
	{
		word* pt;
		for (pt = cur; prev != cur; pt += 2 * ec->f->n, prev += 2 * ec->f->n)
		{
			size_t j = SIZE_BIT_POS(w);
			ecDblA(t, prev, ec, stack);
			while (--j)
				ecDbl(t, t, ec, stack);
			if (!ecToA(pt, t, ec, stack))
				return FALSE;
		}
		cur = pt;
	}
	// заполнить служебные поля
	pre->type = ec_pre_snzh;
	pre->w = w, pre->h = h;
	return TRUE;
}

size_t ecPreSNZH_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecPreSNZH_local(n, ec_d),
		ecPreSNZA_deep(n, ec_d, ec_deep),
		SIZE_MAX);
}

/*
*******************************************************************************
Кратная точка: метод NAF (Non-Adjacent Form)

В функции ecMulPreNAF() для определения b = da (d-кратного точки a) применяется
оконный NAF с длиной окна w >= 2. Реализован алгоритм 3.36 из [HMV04].

Используются малые нечетные кратные a вида
	\pm (2i + 1)a,  i = 0, 1, ..., 2^{w-2} - 1.

Имеются три стратегии:
1)	w = 2 и малые кратные вообще не рассчитываются;
2)	w > 2 и малые кратные рассчитываются в аффинных координатах (схема SNZA);
3)	w > 2 и малые кратные рассчитываются в проективных координатах (схема SNZ).

Если малые кратные рассчитываются по схеме "последовательно складывать
с удвоенной исходной точкой", то средняя общая сложность нахождения
кратной точки (l = wwBitSize(d)):
1)	c1(l) = l/3(P <- P + A);
2)	c2(l, w) = 1(A <- 2A) + (2^{w-2} - 1)(A <- A + A) + 
		l/(w + 1)(P <- P + A);
3)	c3(l, w) = 1(P <- 2A) + 1(P <- P + A) +	(2^{w-2} - 2)(P <- P + P) + 
		l/(w + 1)(P <- P + P),
без учета общего во всех стратегиях слагаемого l(P <- 2P).

Реализована третья стратегия. Она является выигрышной для кривых над GF(p)
в практических диапазонах размерностей при использовании наиболее эффективных
(якобиевых) координат.

Длина окна w выбирается как решение следующей оптимизационной задачи:
	(2^{w - 2} - 2) + l / (w + 1) -> min.

В функции ecMulA() реализована композиция функций ecPreSNZ() (предвычисления)
и ecMulPreNAF().

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

#define ecMulPreNAF_local(n, ec_d, m)\
/* naf */	O_OF_W(2 * m + 1),\
/* t */		O_OF_W(ec_d * n)

static bool_t ecMulPreNAF(word b[], const ec_pre_t* pre, const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	register size_t naf_width;
	register size_t naf_size;
	register size_t i;
	register word digit;
	word* naf;			/* [2 * m + 1] NAF */
	word* t;			/* [ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_snz);
	// разметить стек
	memSlice(stack,
		ecMulPreNAF_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&naf, &t, &stack);
	// расчет NAF
	naf_width = pre->w + 1;
	naf_size = wwNAF(naf, d, m, naf_width);
	// d == O => b <- O
	if (naf_size == 0)
		return FALSE;
	// старшая цифра NAF
	digit = wwGetBits(naf, 0, naf_width);
	ASSERT((digit & 1) == 1 && (digit >> (naf_width - 1)) == 0);
	// t <- pt[digit / 2]
	wwCopy(t, ecPrePt(pre, digit >> 1, ec), ec->d * ec->f->n);
	// цикл по цифрам NAF
	i = naf_width;
	while (--naf_size)
	{
		// t <- 2t
		ecDbl(t, t, ec, stack);
		// обработать цифру
		digit = wwGetBits(naf, i, naf_width);
		if (digit & 1)
		{
			// t <- t + pt[digit / 2]
			ecAdd(t, t, ecPrePt(pre, digit >> 1, ec), ec, stack);
			// к следующей цифре
			i += naf_width - 1;
		}
		++i;
	}
	// очистка
	CLEAN3(naf_width, digit, i);
	// к аффинным координатам
	return ecToA(b, t, ec, stack);
}

size_t ecMulPreNAF_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreNAF_local(n, ec_d, m),
		ec_deep,
		SIZE_MAX);
}

#define ecMulA_local(n, ec_d, pre_count)\
/* pre */	sizeof(ec_pre_t) + O_OF_W(pre_count * ec_d * n)

bool_t ecMulA(word b[], const word a[], const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	size_t naf_width;
	size_t pre_count;
	ec_pre_t* pre;			/* [pre_count проективных точек] */
	size_t i;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(wwIsValid(d, m));
	// размерности
	m = wwWordSize(d, m);
	if (m == 0)
		return FALSE;
	naf_width = ecNAFWidth(B_OF_W(m));
	pre_count = SIZE_BIT_POS(naf_width - 1);
	// разметить стек
	memSlice(stack,
		ecMulA_local(ec->f->n, ec->d, pre_count), SIZE_0, SIZE_MAX,
		&pre, &stack);
	// предвычисления: pre[i] <- (2i + 1)a
	ecPreSNZ(pre, a, naf_width - 1, ec, stack);
	// предвычисления: pre[pre_count - 1 - i] <- -pre[i]
	for (i = 0; i < pre_count / 2; ++i)
		ecNeg(ecPrePt(pre, pre_count - 1 - i, ec), 
			ecPrePt(pre, i, ec), ec, stack);
	// кратная точка по методу NAF
	return ecMulPreNAF(b, pre, ec, d, m, stack);
}

size_t ecMulA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t pre_count = SIZE_BIT_POS(naf_width - 1);
	return memSliceSize(
		ecMulA_local(n, ec_d, pre_count),
		utilMax(2,
			ecPreSNZ_deep(m, ec_d, ec_deep),
			ecMulPreNAF_deep(n, ec_d, ec_deep, m)),
		SIZE_MAX);
}

/*
*******************************************************************************
Кратная точка: метод SNZ

В функции ecMulPreSNZ() для определения кратной точки b = da при нечетной 
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
	1) pt[i] <- (2i + 1)a.						// предвычисления: SNZ
2. t <- pt[d_{k-1} / 2].
3. Для i = k - 2, ..., 1:
	1) t <- 2^w t;								// P <- 2P
	1) t <- t + sgn(d_i) pt[|d_i| / 2].			// P <- P + P
4. t <- 2^w t.
5. t <- t + sgn(d_0) pt[|d_0| / 2].				// A <- P + P
6. Возвратить t.

\remark Сложение t + sgn(d_0) pt[|d_0| / 2] вынесено за рамки основного цикла
на шаге 3, потому что при этом (и только при этом) сложении может произойти
исключительная ситуация -- совпадение операндов t и sgn(d_0) pt[|d_0| / 2]
с переключением от сложения к удвоению. Завершающее сложение выполняется
с помощью функции интерфейса ec_finadd_i, если таковая указана в описании
кривой. Предполагается, что функция ec_finadd_i регулярна, и тогда сложение
и удвоение будут выполняться по одним и тем же формулам.

\remark Расчет цифр d_i (см. [APS22]):
1. Записать
     d = d_0 + d_1 (2^w) + ... + d_{k-1} (2^w)^{k-1},
   где d_i \in {0, 1, ..., 2^w - 1}.
2. (d_{k-1}, borrow) <- (d_{k-1} + (d_{k-1} % 2), d_{k-1} % 2).
3. Для i = k - 2, ...., 0:
   1) (d_i, borrow) <- (d_i - borrow * 2^w + (d_i % 2), d_i % 2).

\remark Выражение
   borrow ? d_i : d_i - 2^w,
по которому определяется индекс в таблице pt, вычисляется следующим образом:
   mask <- 2^w - 2, d_i <- d_i ^ ((0 - borrow) & mask).
Поскольку младший разряд mask нулевой, сохраняется четность цифры d_i и эту
четность можно использовать для пересчета borrow:
  borrow <- d_i % 2.

В функции ecMulPreSNZA() предварительно рассчитанные точки являются аффинными,
а не проективными. Это позволяет заменить регулярные сложения P <- P + P
на P <- P + A и финишное сложение A <- P + P на A <- P + A.

[BCL+14]   Bos J.W., Costello C., Longa P., Naehrig M. Selecting Elliptic
		   Curves for Cryptography: An Efficiency and Security Analysis, 2014,
		   https://eprint.iacr.org/2014/130.pdf.
[APS22]    Agievich S., Poruchnik S., Semenov V. Small scalar multiplication
		   on Weierstrass curves using division polynomials. Mat. Vopr.
		   Kriptogr., 13:2, 2022, https://doi.org/10.4213/mvk406.
*******************************************************************************
*/

#define ecMulPreSNZ_local(n, ec_d, m)\
/* dd */	O_OF_W(m),\
/* t */		O_OF_W(ec_d * n),\
/* pt */	O_OF_W(ec_d * n)

bool_t ecMulPreSNZ(word b[], const ec_pre_t* pre, const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	register word neg;
	register word digit;
	register word borrow;
	register bool_t ret;
	size_t mb;
	size_t pre_count;
	size_t pt_size;
	size_t mask;
	size_t pos;
	size_t i;
	word* dd;			/* [m] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pt;			/* [ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_snz);
	ASSERT(wwWordSize(ec->order, ec->f->n + 1) == m);
	ASSERT(zzIsOdd(ec->order, m) && m > 1);
	ASSERT(wwCmp(d, ec->order, m) < 0);
	// размерности
	mb = wwBitSize(ec->order, m);
	ASSERT(mb >= 2 * pre->w);
	pre_count = SIZE_BIT_POS(pre->w - 1);
	pt_size = ec->d * ec->f->n;
	mask = WORD_BIT_POS(pre->w) - 2;
	// разметить стек
	memSlice(stack,
		ecMulPreSNZ_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&dd, &t, &pt, &stack);
	// dd <- (d % 2) ? d : ec->order - d
	neg = WORD_1 - (d[0] & 1);
	zzSubIf(dd, ec->order, d, m, neg);
	ASSERT(zzIsOdd(dd, m));
	// обработать старшую цифру
	pos = (mb - 1) / pre->w, pos *= pre->w;
	digit = wwGetBits(dd, pos, mb - pos);
	wwSel(t, pre->pts, pre_count, pt_size, digit >> 1);
	borrow = WORD_1 - (digit & 1);
	// обработать остальные цифры
	while (pos -= pre->w)
	{
		for (i = pre->w; i--;)
			ecDbl(t, t, ec, stack);
		digit = wwGetBits(dd, pos, pre->w);
		digit ^= (WORD_0 - borrow) & mask;
		wwSel(pt, pre->pts, pre_count, pt_size, digit >> 1);
		ecSgn(pt, borrow, ec, stack);
		ecAdd(t, t, pt, ec, stack);
		borrow = WORD_1 - (digit & 1);
	}
	// завершающие удвоения
	for (i = pre->w; i--;)
		ecDbl(t, t, ec, stack);
	// финишное сложение
	digit = wwGetBits(dd, 0, pre->w);
	ASSERT(digit & 1);
	digit ^= (WORD_0 - borrow) & mask;
	wwSel(pt, pre->pts, pre_count, pt_size, digit >> 1);
	ecSgn(pt, borrow, ec, stack);
	ret = (ec->finadd) ?
		ec->finadd(b, t, pt, ec, stack) :
		(ecAdd(t, t, pt, ec, stack), ecToA(b, t, ec, stack));
	// настройка знака
	ecSgnA(b, neg, ec, stack);
	// очистка и возврат
	CLEAN3(neg, digit, borrow);
	return ret;
}

size_t ecMulPreSNZ_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreSNZ_local(n, ec_d, m),
		ec_deep,
		SIZE_MAX);
}

#define ecMulPreSNZA_local(n, ec_d, m)\
/* dd */	O_OF_W(m),\
/* t */		O_OF_W(ec_d * n),\
/* pt */	O_OF_W(2 * n)

bool_t ecMulPreSNZA(word b[], const ec_pre_t* pre, const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	register word neg;
	register word digit;
	register word borrow;
	register bool_t ret;
	size_t mb;
	size_t pre_count;
	size_t pt_size;
	size_t mask;
	size_t pos;
	size_t i;
	word* dd;			/* [m] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pt;			/* [2 * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_snza);
	ASSERT(wwWordSize(ec->order, ec->f->n + 1) == m);
	ASSERT(zzIsOdd(ec->order, m) && m > 1);
	ASSERT(wwCmp(d, ec->order, m) < 0);
	// размерности
	mb = wwBitSize(ec->order, m);
	ASSERT(mb >= 2 * pre->w);
	pre_count = SIZE_BIT_POS(pre->w - 1);
	pt_size = 2 * ec->f->n;
	mask = WORD_BIT_POS(pre->w) - 2;
	// разметить стек
	memSlice(stack,
		ecMulPreSNZA_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&dd, &t, &pt, &stack);
	// dd <- (d % 2) ? d : ec->order - d
	neg = WORD_1 - (d[0] & 1);
	zzSubIf(dd, ec->order, d, m, neg);
	ASSERT(zzIsOdd(dd, m));
	// обработать старшую цифру
	pos = (mb - 1) / pre->w, pos *= pre->w;
	digit = wwGetBits(dd, pos, mb - pos);
	wwSel(pt, pre->pts, pre_count, pt_size, digit >> 1);
	ecFromA(t, pt, ec, stack);
	borrow = WORD_1 - (digit & 1);
	// обработать остальные цифры
	while (pos -= pre->w)
	{
		for (i = pre->w; --i;)
			ecDbl(t, t, ec, stack);
		digit = wwGetBits(dd, pos, pre->w);
		digit ^= (WORD_0 - borrow) & mask;
		wwSel(pt, pre->pts, pre_count, pt_size, digit >> 1);
		ecSgnA(pt, borrow, ec, stack);
		ecDblAddA(t, t, pt, ec, stack);
		borrow = WORD_1 - (digit & 1);
	}
	// завершающие удвоения
	for (i = pre->w; i--;)
		ecDbl(t, t, ec, stack);
	// финишное сложение
	digit = wwGetBits(dd, 0, pre->w);
	ASSERT(digit & 1);
	digit ^= (WORD_0 - borrow) & mask;
	wwSel(pt, pre->pts, pre_count, pt_size, digit >> 1);
	ecSgnA(pt, borrow, ec, stack);
	ret = (ec->finadda) ?
		ec->finadda(b, t, pt, ec, stack) :
		(ecAddA(t, t, pt, ec, stack), ecToA(b, t, ec, stack));
	// настройка знака
	ecSgnA(b, neg, ec, stack);
	// очистка и возврат
	CLEAN3(neg, digit, borrow);
	return ret;
}

size_t ecMulPreSNZA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreSNZA_local(n, ec_d, m),
		ec_deep,
		SIZE_MAX);
}

#define ecMulPreSNZH_local(n, ec_d, m)\
/* dd */	O_OF_W(m),\
/* t */		O_OF_W(ec_d * n),\
/* pt */	O_OF_W(2 * n)

bool_t ecMulPreSNZH(word b[], const ec_pre_t* pre, const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	register word neg;
	register word digit;
	register word borrow;
	register bool_t ret;
	size_t mb;
	size_t row_count;
	size_t pt_size;
	size_t mask;
	size_t pos;
	const word* row;
	word* dd;			/* [m] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pt;			/* [2 * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_snzh);
	ASSERT(wwWordSize(ec->order, ec->f->n + 1) == m);
	ASSERT(zzIsOdd(ec->order, m) && m > 1);
	ASSERT(wwCmp(d, ec->order, m) < 0);
	// размерности
	mb = wwBitSize(ec->order, m);
	ASSERT(2 * pre->w <= mb && mb <= pre->w * pre->h);
	row_count = SIZE_BIT_POS(pre->w - 1);
	pt_size = 2 * ec->f->n;
	mask = WORD_BIT_POS(pre->w) - 2;
	// разметить стек
	memSlice(stack,
		ecMulPreSNZH_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&dd, &t, &pt, &stack);
	// dd <- (d % 2) ? d : ec->order - d
	neg = WORD_1 - (d[0] & 1);
	zzSubIf(dd, ec->order, d, m, neg);
	ASSERT(zzIsOdd(dd, m));
	// позиция старшей цифры, старшая строка pre
	pos = (mb - 1) / pre->w;
	row = pre->pts + pos * pt_size;
	pos *= pre->w;
	// обработать старшую цифру
	digit = wwGetBits(dd, pos, mb - pos);
	wwSel(pt, row, row_count, pt_size, digit >> 1);
	ecFromA(t, pt, ec, stack);
	borrow = WORD_1 - (digit & 1);
	// обработать остальные цифры
	while (pos -= pre->w)
	{
		row -= row_count * pt_size;
		digit = wwGetBits(dd, pos, pre->w);
		digit ^= (WORD_0 - borrow) & mask;
		wwSel(pt, row, row_count, pt_size, digit >> 1);
		ecSgnA(pt, borrow, ec, stack);
		ecDblAddA(t, t, pt, ec, stack);
		borrow = WORD_1 - (digit & 1);
	}
	// финишное сложение
	row -= row_count * pt_size;
	digit = wwGetBits(dd, 0, pre->w);
	ASSERT(digit & 1);
	digit ^= (WORD_0 - borrow) & mask;
	wwSel(pt, pre->pts, row_count, pt_size, digit >> 1);
	ecSgnA(pt, borrow, ec, stack);
	ret = (ec->finadda) ?
		ec->finadda(b, t, pt, ec, stack) :
		(ecAddA(t, t, pt, ec, stack), ecToA(b, t, ec, stack));
	// настройка знака
	ecSgnA(b, neg, ec, stack);
	// очистка и возврат
	CLEAN3(neg, digit, borrow);
	return ret;
}

size_t ecMulPreSNZH_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreSNZH_local(n, ec_d, m),
		ec_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Кратная точка: метод Comb

[LimLee94] Lim, C.H., Lee, P.J. More Flexible Exponentiation with
           Precomputation. In: Advances in Cryptology -- CRYPTO ’94. 1994.
           Lecture Notes in Computer Science, vol 839. Springer, Berlin,
		   Heidelberg. https://doi.org/10.1007/3-540-48658-5_11.
*******************************************************************************
*/

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
/* pre */		sizeof(ec_pre_t*) * k

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
	ec_pre_t** pre;		/* [k] предвычисленные точки */
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
		pre_count = SIZE_BIT_POS(naf_width[i] - 1);
		memSlice(stack,
			O_OF_W(2 * m[i] + 1),
			sizeof(ec_pre_t) + O_OF_W(pre_count * ec->d * ec->f->n),
			SIZE_0,
			SIZE_MAX,
			naf + i, pre + i, &stack);
		// расчет naf[i]
		naf_size[i] = wwNAF(naf[i], d, m[i], naf_width[i]);
		if (naf_size[i] > naf_max_size)
			naf_max_size = naf_size[i];
		naf_pos[i] = 0;
		// предвычисления
		ecPreSNZ(pre[i], a, naf_width[i] - 1, ec, stack);
		for (j = 0; j < pre_count / 2; ++j)
			ecNeg(ecPrePt(pre[i], pre_count - 1 - j, ec), 
				ecPrePt(pre[i], j, ec), ec, stack);
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
			// цифры naf[i] не начались?
			if (naf_size[i] < naf_max_size)
				continue;
			// прочитать очередную цифру naf[i]
			digit = wwGetBits(naf[i], naf_pos[i], naf_width[i]);
			// обработать цифру
			if (digit & 1)
			{
				// t <- t + pre[i].pt[digit / 2]
				ecAdd(t, t, ecPrePt(pre[i], digit / 2, ec), ec, stack);
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
		ecPreSNZ_deep(n, ec_d, ec_deep),
		SIZE_MAX);
	va_start(args, k);
	for (i = 0; i < k; ++i)
	{
		size_t m = va_arg(args, size_t);
		size_t naf_width = ecNAFWidth(B_OF_W(m));
		size_t pre_count = SIZE_BIT_POS(naf_width - 1);
		ret += memSliceSize(
			O_OF_W(2 * m + 1),
			sizeof(ec_pre_t) + O_OF_W(ec_d * n * pre_count),
			SIZE_0,	SIZE_MAX);
	}
	va_end(args);
	return ret;
}
