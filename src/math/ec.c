/*
*******************************************************************************
\file ec.c
\brief Elliptic curves
\project bee2 [cryptographic library]
\created 2014.03.04
\version 2026.03.03
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
	wwSetZero(ec->order + W_OF_O(order_len), ec->f->n + 1 - W_OF_O(order_len));
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

В функции ecPreSO() реализован следуюший алгоритм:
1. t <- 2a.								// P <- 2A
2. pre[0] <- a.
3. pre[1] <- t + pre[0].				// P <- P + A
4. Для i = 2, 3, ..., 2^{w-1} - 1:
   1) pre[i] <- t + pre[i - 1].			// P <- P + P

Итоговая сложность:
	1(P <- 2A) + 1(P <- P + A) + (2^{w-1} - 2)(P <- P + P).

В функции ecPreSOA() реализован тот тот же алгоритм, только операция P <- 2A
в нем меняется на A <- 2A, а операции P <- P + A и P <- P + P меняются
на A <- A + A.

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

В функции ecPreSI() вычисляются точки
	[v_{w-1}, v_{w-2}, ..., v_0]a = \sum_{j=0}^{w-1}(1-2v_i)(2^h)^j a,
где v_i in {0, 1}, v_{w-1} == 1. Точка [v_{w-1},...,v_0]a
размещается в массиве предвычисленных точек по индексу v_{w-1}...v_0.

Слова v_{w-1}...v_1 v_0 просматриваются как слова кода Грея: соседние
слова отличаются только в одном бите. Если это бит номер j, то новая точка
получается из [v_{w-1}...v_1 v_0]a:
- добавлением точки (2(2^h)^j)a при v_j = 1; 
- вычитанием точки (2(2^h)^j)a при v_j = 0.

Определение следующего за v = v_{w-1}...v_1 v_0 слова выполняется
следующим образом (см. [War03; глава 13], нумерация битов справа налево от 0):
1. Если v содержит четное число единиц, то j <- 0. Иначе
   j <- (позиция первой справа единицы) + 1.
2. Инвертировать бит code номер j.

[War03] Уоррен Генри Мл. Алгоритмические трюки для программистов,
		М.: Издательский дом "Вильямс", 2003.
*******************************************************************************
*/

bool_t ecPreIsOperable(const ec_pre_t* pre)
{
	return memIsValid(pre, sizeof(pre)) &&
		(pre->type == ec_pre_so || pre->type == ec_pre_soa ||
			pre->type == ec_pre_sh || pre->type == ec_pre_od ||
			pre->type == ec_pre_si) &&
		0 < pre->w && pre->w < MIN2(B_PER_W, B_PER_S) &&
		((pre->type != ec_pre_od && pre->type != ec_pre_si) ^ (pre->h > 0));
}

#define ecPreSO_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

void ecPreSO(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(0 < w && w < MIN2(B_PER_W, B_PER_S));
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + 
			O_OF_W(SIZE_BIT_POS(w - 1) * ec->d * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecPreSO_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	// pre[0] <- a
	ecFromA(ecPrePt(pre, 0, ec), a, ec, stack);
	// вычислить малые кратные
	if (w > 1)
	{
		size_t i;
		// t <- 2 a
		ecDblA(t, a, ec, stack);
		// pre[1] <- t + a
		ecAddA(ecPrePt(pre, 1, ec), t, a, ec, stack);
		// pre[i] <- t + pre[i - 1]
		for (i = 2; i < SIZE_BIT_POS(w - 1); ++i)
			ecAdd(ecPrePt(pre, i, ec), t, ecPrePt(pre, i - 1, ec), ec, stack);
	}
	// заполнить служебные поля
	pre->type = ec_pre_so;
	pre->w = w, pre->h = 0;
}

size_t ecPreSO_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecPreSO_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

#define ecPreSOA_local(n, ec_d)\
/* t1 */	O_OF_W(ec_d * n),\
/* t2 */	O_OF_W(ec_d * n)

bool_t ecPreSOA(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec,
	void* stack)
{
	word* t1;			/* [ec->d * ec->f->n] */
	word* t2;			/* [ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(0 < w && w < MIN2(B_PER_W, B_PER_S));
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + 
			O_OF_W(SIZE_BIT_POS(w - 1) * 2 * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecPreSOA_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t1, &t2, &stack);
	// pre[0] <- a
	wwCopy(ecPrePtA(pre, 0, ec), a, 2 * ec->f->n);
	// вычислить малые кратные
	if (w > 1)
	{
		size_t i;
		// t1 <- 2 a
		ecDblA(t1, a, ec, stack);
		// pre[i] <- t1 + pre[i - 1]
		for (i = 1; i < SIZE_BIT_POS(w - 1); ++i)
		{
			ecAddA(t2, t1, ecPrePtA(pre, i - 1, ec), ec, stack);
			if (!ecToA(ecPrePtA(pre, i, ec), t2, ec, stack))
				return FALSE;
		}
	}
	// заполнить служебные поля
	pre->type = ec_pre_soa;
	pre->w = w, pre->h = 0;
	return TRUE;
}

size_t ecPreSOA_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecPreSOA_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

void ecPreSH(ec_pre_t* pre, const word a[], size_t w, const ec_o* ec, 
	void* stack)
{
	const size_t pre_count = SIZE_BIT_POS(w - 1) + 3;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(0 < w && w < MIN2(B_PER_W, B_PER_S));
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + O_OF_W(pre_count * ec->d * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// pre[-2, -1] <- (a, 2a)
	ecFromA(ecPrePt(pre, pre_count - 2, ec), a, ec, stack);
	ecDblA(ecPrePt(pre, pre_count - 1, ec), a, ec, stack);
	// вычислить малые кратные
	if (w > 1)
	{
		size_t i;
		// pre[0] <- 2^{w-1}a
		wwCopy(ecPrePt(pre, 0, ec), ecPrePt(pre, pre_count - 1, ec), 
			ec->d * ec->f->n);
		for (i = 2; i < w; ++i)
			ecDbl(ecPrePt(pre, 0, ec), ecPrePt(pre, 0, ec), ec, stack);
		// pre[i] <- pre[i - 1] + a
		for (i = 1; i < pre_count - 3; ++i)
			ecAddA(ecPrePt(pre, i, ec), ecPrePt(pre, i - 1, ec), a, ec, stack);
		// pre[-3] <- 2 pre[0]
		ecDbl(ecPrePt(pre, pre_count - 3, ec), ecPrePt(pre, 0, ec), ec, stack);
	}
	else
		// pre[0, 1] <- pre[-1, -2]
		wwCopy(ecPrePt(pre, 0, ec), ecPrePt(pre, pre_count - 2, ec), 
			2 * ec->d * ec->f->n);
	// заполнить служебные поля
	pre->type = ec_pre_sh;
	pre->w = w, pre->h = 0;
}

size_t ecPreSH_deep(size_t ec_deep)
{
	return memSliceSize(
		ec_deep,
		SIZE_MAX);
}

#define ecPreOD_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

bool_t ecPreOD(ec_pre_t* pre, const word a[], size_t w, size_t h,
	const ec_o* ec, void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	size_t i;
	word* prev;
	word* cur;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(0 < w && w < MIN2(B_PER_W, B_PER_S) && h > 0);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + 
			O_OF_W(SIZE_BIT_POS(w - 1) * h * 2 * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecPreOD_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	// первая строка
	if (!ecPreSOA(pre, a, w, ec, stack))
		return FALSE;
	// остальные строки
	prev = pre->pts, cur = prev + SIZE_BIT_POS(w - 1) * 2 * ec->f->n;
	for (i = 1; i < h; ++i)
	{
		word* pt;
		for (pt = cur; prev != cur; pt += 2 * ec->f->n, prev += 2 * ec->f->n)
		{
			size_t j;
			ecDblA(t, prev, ec, stack);
			for (j = 1; j < w; ++j)
				ecDbl(t, t, ec, stack);
			if (!ecToA(pt, t, ec, stack))
				return FALSE;
		}
		cur = pt;
	}
	// заполнить служебные поля
	pre->type = ec_pre_od;
	pre->h = h;
	return TRUE;
}

size_t ecPreOD_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecPreOD_local(n, ec_d),
		utilMax(2,
			ec_deep,
			ecPreSOA_deep(n, ec_d, ec_deep)),
		SIZE_MAX);
}

#define ecPreSI_local(n, ec_d, h)\
/* t1 */		O_OF_W(ec_d * n),\
/* t2 */		O_OF_W(ec_d * n),\
/* dbls */		O_OF_W(h * ec_d * n)

bool_t ecPreSI(ec_pre_t* pre, const word a[], size_t w, size_t h,
	const ec_o* ec, void* stack)
{
	word* t1;			/* [ec->d * ec->f->n] */
	word* t2;			/* [ec->d * ec->f->n] */
	word* dbls;			/* [h * ec->d * ec->f->n] */
	size_t i;
	word code;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(0 < w && w < MIN2(B_PER_W, B_PER_S) && h > 0);
	ASSERT(memIsDisjoint2(
		pre, sizeof(ec_pre_t) + 
			O_OF_W(SIZE_BIT_POS(w - 1) * 2 * ec->f->n),
		a, O_OF_W(2 * ec->f->n)));
	// разметить стек
	memSlice(stack,
		ecPreSI_local(ec->f->n, ec->d, h), SIZE_0, SIZE_MAX,
		&t1, &t2, &dbls, &stack);
	// dbls[i] <- 2(2^h)^i a, t2 <- \sum_{i=0}^{w-1} (2^h)^i a
	ecFromA(t1, a, ec, stack);
	wwCopy(t2, t1, ec->d * ec->f->n);
	for (i = 0; i < w; ++i)
	{
		ecDbl(t1, t1, ec, stack);
		wwCopy(ecPt(dbls, i, ec), t1, ec->d * ec->f->n);
		if (i != w - 1)
		{
			size_t j;
			for (j = 1; j < h; ++j)
				ecDbl(t1, t1, ec, stack);
			ecAdd(t2, t2, t1, ec, stack);
		}
	}
	// pre[0] <- \sum_{i=0}^{w-1} dbls[i]
	if (!ecToA(ecPrePtA(pre, 0, ec), t2, ec, stack))
		return FALSE;
	// pre[next] <- pre[cur] \pm dbls[diff(next, cur)]
	for (i = 1, code = 0; i < (size_t)WORD_BIT_POS(w - 1); ++i)
	{
		size_t pos;
		pos = wordParity(code) ? wordCTZ(code) + 1 : 0;
		wwCopy(t1, ecPt(dbls, pos, ec), ec->d * ec->f->n);
		ecSgn(t1, (~code >> pos) & WORD_1, ec, stack);
		code ^= WORD_BIT_POS(pos);
		ecAdd(t2, t2, t1, ec, stack);
		if (!ecToA(ecPrePtA(pre, (size_t)code, ec), t2, ec, stack))
			return FALSE;
	}
	// заполнить служебные поля
	pre->type = ec_pre_si;
	pre->w = w, pre->h = h;
	return TRUE;
}

size_t ecPreSI_deep(size_t n, size_t ec_d, size_t ec_deep, size_t h)
{
	return memSliceSize(
		ecPreSI_local(n, ec_d, h),
		ec_deep,
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
2)	w > 2 и малые кратные рассчитываются в аффинных координатах (схема SOA);
3)	w > 2 и малые кратные рассчитываются в проективных координатах (схема SO).

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

В функции ecMulA() реализована композиция функций ecPreSO() (предвычисления)
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
	ASSERT(pre->type == ec_pre_so);
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
	// t <- pre[digit / 2]
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
			// t <- t + pre[digit / 2]
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
	ecPreSO(pre, a, naf_width - 1, ec, stack);
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
			ecPreSO_deep(m, ec_d, ec_deep),
			ecMulPreNAF_deep(n, ec_d, ec_deep, m)),
		SIZE_MAX);
}

/*
*******************************************************************************
Кратная точка: метод SO и его модификации

В функции ecMulPreSO() для определения кратной точки b = da при нечетной 
кратности d используется ее представление в форме
	e_{h-1} (2^w)^{h-1} + ... + e_1 (2^w) + e_0.
Здесь e_i \in {\pm 1, \pm 3, ..., \pm (2^w-1)} -- ненулевые нечетные цифры
со знаком. Предполагается, что точка a лежит в группе нечетного порядка order,
(2^w)^{h-1} < order < (2^w)^h. Представление SO предложено использовать 
в [OkeTak03].

Если кратность d четная, то она предварительно меняется на order-d. Для этого
используется функция zzSubIf().

Реализован следующий алгоритм (см. [BCL+14; p. 9-11, algorithm 1], [APS22]):
1. Для i = 0, 1, ..., 2^{w-1}-1:
	1) pre[i] <- (2i + 1)a.						// предвычисления: SO
2. t <- pre[e_{h-1} / 2].
3. Для i = h-2, ..., 2, 1:
	1) t <- 2^w t;								// P <- 2P
	2) t <- t + sgn(e_i) pre[|e_i|/2].			// P <- P + P
4. t <- 2^w t.
5. t <- t + sgn(e_0) pre[|e_0|/2].				// A <- P + P
6. Возвратить t.

\remark Сложение t + sgn(e_0) pre[|e_0|/2] вынесено за рамки основного цикла
на шаге 3, потому что при этом (и только при этом) сложении может произойти
исключительная ситуация -- совпадение операндов t и sgn(e_0) pre[|e_0|/2]
с переключением от сложения к удвоению. Завершающее сложение выполняется
с помощью функции интерфейса ec_finadd_i, если таковая указана в описании
кривой. Предполагается, что функция ec_finadd_i регулярна, и тогда сложение
и удвоение будут выполняться по одним и тем же формулам.

\remark Расчет цифр e_i (см. [APS22]):
1. Записать
     d = d_{h-1} (2^w)^{h-1} + d_1 (2^w) + d_0,
   где d_i \in {0, 1, ..., 2^w-1}.
2. (e_{h-1}, borrow) <- (d_{h-1} + (d_{h-1} % 2), d_{h-1} % 2).
3. Для i = h-2, ...., 1, 0:
   1) (e_i, borrow) <- (d_i - borrow * 2^w + (d_i % 2), d_i % 2).

\remark Выражение
   e_i = borrow ? d_i : d_i - 2^w,
по которому определяется индекс в таблице pt, вычисляется следующим образом:
   mask <- 2^w - 2, e_i <- d_i ^ ((0 - borrow) & mask).
Поскольку младший разряд mask нулевой, в e_i переносится четность d_i, и эту
четность можно использовать для пересчета borrow:
  borrow <- e_i % 2.

В функции ecMulPreSOA() предварительно рассчитанные точки являются аффинными,
а не проективными. Это позволяет заменить регулярные сложения P <- P + P
на P <- P + A и финишное сложение A <- P + P на A <- P + A.

В функции ecMulPreOD() предполагается, что аффинные точки предварительно
рассчитаны для каждой цифры обрабатываемого скаляра d. Это позволяет
избавиться от удвоений:
1. Для i = 0, 1, ..., h-1 и j = 0, 1, ..., 2^{w-1}-1:
	1) pre[i][j] <- (2^w)^i(2j + 1)a.			// предвычисления: OD
2. t <- pre[h-1][e_{h-1}/2].
3. Для i = h-2, ..., 2, 1:
	1) t <- t + sgn(e_i) pre[i]t[|e_i|/2].		// P <- P + P
4. t <- t + sgn(e_0) pre[0][|e_0|/2].			// A <- P + P
5. Возвратить t.

[OkeTak03] Okeya K., Takagi T. The width-w NAF method provides small memory
		   and fast elliptic scalar multiplications secure against side
		   channel attacks. In Cryptographers’ Track at the RSA Conference,
		   2003, pp. 328-343. Springer, Berlin Heidelberg.
[BCL+14]   Bos J.W., Costello C., Longa P., Naehrig M. Selecting Elliptic
		   Curves for Cryptography: An Efficiency and Security Analysis, 2014,
		   https://eprint.iacr.org/2014/130.pdf.
[APS22]    Agievich S., Poruchnik S., Semenov V. Small scalar multiplication
		   on Weierstrass curves using division polynomials. Mat. Vopr.
		   Kriptogr., 13:2, 2022, https://doi.org/10.4213/mvk406.
*******************************************************************************
*/

#define ecMulPreSO_local(n, ec_d, m)\
/* e */		O_OF_W(m),\
/* t */		O_OF_W(ec_d * n),\
/* pt */	O_OF_W(ec_d * n)

bool_t ecMulPreSO(word b[], const ec_pre_t* pre, const ec_o* ec,
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
	word* e;			/* [m] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pt;			/* [ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_so);
	ASSERT(wwWordSize(ec->order, ec->f->n + 1) == m);
	ASSERT(zzIsOdd(ec->order, m));
	ASSERT(wwCmp(d, ec->order, m) < 0);
	// размерности
	mb = wwBitSize(ec->order, m);
	ASSERT(mb > pre->w);
	pre_count = SIZE_BIT_POS(pre->w - 1);
	pt_size = ec->d * ec->f->n;
	mask = WORD_BIT_POS(pre->w) - 2;
	// разметить стек
	memSlice(stack,
		ecMulPreSO_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&e, &t, &pt, &stack);
	// e <- (d % 2) ? d : ec->order - d
	neg = WORD_1 - (d[0] & 1);
	zzSubIf(e, ec->order, d, m, neg);
	ASSERT(zzIsOdd(e, m));
	// обработать старшую цифру
	pos = (mb - 1) / pre->w, pos *= pre->w;
	digit = wwGetBits(e, pos, mb - pos);
	wwSel(t, pre->pts, pre_count, pt_size, digit >> 1);
	borrow = WORD_1 - (digit & 1);
	// t <- 2^w t
	for (i = 0; i < pre->w; ++i)
		ecDbl(t, t, ec, stack);
	// обработать остальные цифры
	while (pos -= pre->w)
	{
		// сложить
		digit = wwGetBits(e, pos, pre->w);
		digit ^= (WORD_0 - borrow) & mask;
		wwSel(pt, pre->pts, pre_count, pt_size, digit >> 1);
		ecSgn(pt, borrow, ec, stack);
		ecAdd(t, t, pt, ec, stack);
		borrow = WORD_1 - (digit & 1);
		// удвоить
		for (i = 0; i < pre->w; ++i)
			ecDbl(t, t, ec, stack);
	}
	// финишное сложение
	digit = wwGetBits(e, 0, pre->w);
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

size_t ecMulPreSO_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreSO_local(n, ec_d, m),
		ec_deep,
		SIZE_MAX);
}

#define ecMulPreSOA_local(n, ec_d, m)\
/* e */		O_OF_W(m),\
/* t */		O_OF_W(ec_d * n),\
/* pt */	O_OF_W(2 * n)

bool_t ecMulPreSOA(word b[], const ec_pre_t* pre, const ec_o* ec,
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
	word* e;			/* [m] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pt;			/* [2 * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_soa);
	ASSERT(wwWordSize(ec->order, ec->f->n + 1) == m);
	ASSERT(zzIsOdd(ec->order, m));
	ASSERT(wwCmp(d, ec->order, m) < 0);
	// размерности
	mb = wwBitSize(ec->order, m);
	ASSERT(mb > pre->w);
	pre_count = SIZE_BIT_POS(pre->w - 1);
	pt_size = 2 * ec->f->n;
	mask = WORD_BIT_POS(pre->w) - 2;
	// разметить стек
	memSlice(stack,
		ecMulPreSOA_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&e, &t, &pt, &stack);
	// e <- (d % 2) ? d : ec->order - d
	neg = WORD_1 - (d[0] & 1);
	zzSubIf(e, ec->order, d, m, neg);
	ASSERT(zzIsOdd(e, m));
	// обработать старшую цифру
	pos = (mb - 1) / pre->w, pos *= pre->w;
	digit = wwGetBits(e, pos, mb - pos);
	wwSel(pt, pre->pts, pre_count, pt_size, digit >> 1);
	borrow = WORD_1 - (digit & 1);
	// t <- 2^{w-1} pt
	if (pre->w > 1)
		ecDblA(t, pt, ec, stack);
	else
		ecFromA(t, pt, ec, stack);
	for (i = 2; i < pre->w; ++i)
		ecDbl(t, t, ec, stack);
	// обработать остальные цифры
	while (pos -= pre->w)
	{
		// удвоить со сложением
		digit = wwGetBits(e, pos, pre->w);
		digit ^= (WORD_0 - borrow) & mask;
		wwSel(pt, pre->pts, pre_count, pt_size, digit >> 1);
		ecSgnA(pt, borrow, ec, stack);
		ecDblAddA(t, t, pt, ec, stack);
		borrow = WORD_1 - (digit & 1);
		// t <- 2^{w-1} t
		for (i = 1; i < pre->w; ++i)
			ecDbl(t, t, ec, stack);
	}
	// t <- 2t
	ecDbl(t, t, ec, stack);
	// финишное сложение
	digit = wwGetBits(e, 0, pre->w);
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

size_t ecMulPreSOA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreSOA_local(n, ec_d, m),
		ec_deep,
		SIZE_MAX);
}

#define ecMulPreOD_local(n, ec_d, m)\
/* e */		O_OF_W(m),\
/* t */		O_OF_W(ec_d * n),\
/* pt */	O_OF_W(2 * n)

bool_t ecMulPreOD(word b[], const ec_pre_t* pre, const ec_o* ec,
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
	word* e;			/* [m] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pt;			/* [2 * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_od);
	ASSERT(wwWordSize(ec->order, ec->f->n + 1) == m);
	ASSERT(zzIsOdd(ec->order, m));
	ASSERT(wwCmp(d, ec->order, m) < 0);
	// размерности
	mb = wwBitSize(ec->order, m);
	ASSERT(pre->w < mb && mb <= pre->w * pre->h);
	row_count = SIZE_BIT_POS(pre->w - 1);
	pt_size = 2 * ec->f->n;
	mask = WORD_BIT_POS(pre->w) - 2;
	// разметить стек
	memSlice(stack,
		ecMulPreOD_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&e, &t, &pt, &stack);
	// e <- (d % 2) ? d : ec->order - d
	neg = WORD_1 - (d[0] & 1);
	zzSubIf(e, ec->order, d, m, neg);
	ASSERT(zzIsOdd(e, m));
	// позиция старшей цифры, старшая строка pre
	pos = (mb - 1) / pre->w;
	row = pre->pts + pos * row_count * pt_size;
	pos *= pre->w;
	// обработать старшую цифру
	digit = wwGetBits(e, pos, mb - pos);
	wwSel(pt, row, row_count, pt_size, digit >> 1);
	ecFromA(t, pt, ec, stack);
	borrow = WORD_1 - (digit & 1);
	// обработать остальные цифры
	while (pos -= pre->w)
	{
		digit = wwGetBits(e, pos, pre->w);
		digit ^= (WORD_0 - borrow) & mask;
		row -= row_count * pt_size;
		wwSel(pt, row, row_count, pt_size, digit >> 1);
		ecSgnA(pt, borrow, ec, stack);
		ecAddA(t, t, pt, ec, stack);
		borrow = WORD_1 - (digit & 1);
	}
	// финишное сложение
	digit = wwGetBits(e, 0, pre->w);
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

size_t ecMulPreOD_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreOD_local(n, ec_d, m),
		ec_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Кратная точка: метод SI

В функции ecMulPreSI() вычисление кратной точки выполняется по методу,
предложенному в [HPB05]. Это модификация метода Comb, введенного в [LimLee94]
(см. также [HMV04; algorithm 3.44]).

Для определения кратной точки b = da при нечетной кратности d используется
ее представление в виде
	e_{hw-1} 2^{hw-1} + e_{hw-2} 2^{hw-2} + ... + e_1 2^1 + e_0,
где e_i \in {\pm 1}. 

Как обычно, если кратность d четная, то она предварительно меняется на
order-d.

Обозначения:
* если e = (e_{hw-1},e_{hw-2},...,e_0), то 
    e_{h,i} = (e_{(w-1)h+i},e_{(w-2)h+i},...,e_i), i = 0,1,...,h-1;
* если v = (v_{w-1},v_{w-2},...,v_0) -- двоичный вектор, то 
    sgn(v) = 1-2*v_{w-1}, |v| = sgn(v) > 0 ? v : ~v.

Реализован следующий алгоритм:
1. Для v_{w-1} = 0 и v_{w-2},..., v_0 \in {0,1}:
	1) pre[v_{w-1},v_{w-2},...,v_0] = \sum_{j=0}^{w-1}(1-2v_j)(2^h)^j a.
2. t <- pre[e_{h,h-1}].
3. t <- 2 t.
4. Для i = h-2, h-3, ..., 1:
	1) t <- t + sgn(e_{h,i})pt[|e_{h,i}|].
	2) t <- 2 t.
5. t <- t + sgn(e_{h,0})pt[|e_{h,0}|].
6. Возвратить t.

Переход от двоичного представления
	d = \sum_{i=0}^{hw-1} d_i 2^i,		d_i \in {0,1}, d_0 = 1,
к \pm 1 представлению
	d = \sum_{i=0}^{hw-1}(1-2 e_i) 2^i,	e_i \in {0,1},
реализуется следующим образом:
	(e_{hw-1}, ..., e_1, e_0) <- (0, d_{hw-1} ^ 1, ..., d_1 ^ 1).

\remark Обоснование:
	\sum_{i=0}^{hw-1}(1-2 e_i) 2^i =
	  2^{hw-1} + \sum_{i=0}^{hw-2}(2 d_{i+1}-1)2^i = 
	  2^{hw-1} - \sum_{i=0}^{hw-2}2^i + \sum_{i=1}^{hw-1}d_i 2^i =
	  1 + \sum_{i=1}^{hw-1}d_i 2^i = d.

[HPB05]    Hedabou M., Pinel P., Beneteau L. Countermeasures for preventing
           comb method against SCA attacks. In: International Conference
           on Information Security Practice and Experience, 2005, pp. 85-96,
           Springer, Berlin Heidelberg.
[LimLee94] Lim, C.H., Lee, P.J. More Flexible Exponentiation with
           Precomputation. In: Advances in Cryptology -- CRYPTO ’94. 1994.
           Lecture Notes in Computer Science, vol 839. Springer, Berlin,
		   Heidelberg. https://doi.org/10.1007/3-540-48658-5_11.
*******************************************************************************
*/

#define ecMulPreSI_local(n, ec_d, m)\
/* e */		O_OF_W(m + 1),\
/* t */		O_OF_W(ec_d * n),\
/* pt */	O_OF_W(2 * n)

bool_t ecMulPreSI(word b[], const ec_pre_t* pre, const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	register word neg;
	register word digit;
	register word hi;
	register bool_t ret;
	size_t mb;
	size_t pre_count;
	size_t pt_size;
	size_t mask;
	size_t pos;
	size_t i;
	word* e;			/* [W_OF_B(pre->h * pre->w)] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pt;			/* [2 * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_si);
	ASSERT(wwWordSize(ec->order, ec->f->n + 1) == m);
	ASSERT(zzIsOdd(ec->order, m));
	ASSERT(wwCmp(d, ec->order, m) < 0);
	// размерности
	mb = pre->w * pre->h;
	ASSERT(pre->w < wwBitSize(ec->order, m));
	ASSERT(wwBitSize(ec->order, m) <= mb);
	pre_count = SIZE_BIT_POS(pre->w - 1);
	pt_size = 2 * ec->f->n;
	mask = WORD_BIT_POS(pre->w - 1) - 1;
	// разметить стек
	memSlice(stack,
		ecMulPreSI_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&e, &t, &pt, &stack);
	// e <- (d % 2) ? d : ec->order - d
	neg = WORD_1 - (d[0] & 1);
	e[m] = 0;
	zzSubIf(e, ec->order, d, m, neg);
	ASSERT(zzIsOdd(e, m));
	// перекодировать e
	m = W_OF_B(mb);
	wwNeg(e, m);
	if (i = mb % B_PER_W)
		e[m - 1] <<= (B_PER_W - i), e[m - 1] >>= (B_PER_W - i);
	wwShLo(e, m, 1);
	// сформировать старшую цифру
	digit = 0;
	for (i = 1; i < pre->w; ++i)
		digit <<= 1, digit ^= (word)wwTestBit(e, mb - i * pre->h - 1);
	ASSERT((digit & mask) == digit);
	// обработать старшую цифру
	wwSel(pt, pre->pts, pre_count, pt_size, digit);
	ecFromA(t, pt, ec, stack);
	// обработать остальные цифры
	for (pos = 2; pos < pre->h; ++pos)
	{
		// сформировать цифру
		hi = (word)wwTestBit(e, mb - pos);
		for (digit = 0, i = 1; i < pre->w; ++i)
			digit <<= 1, digit ^= (word)wwTestBit(e, mb - i * pre->h - pos);
		digit ^= (WORD_0 - hi) & mask;
		// удвоить и сложить
		wwSel(pt, pre->pts, pre_count, pt_size, digit);
		ecSgnA(pt, hi, ec, stack);
		ecDblAddA(t, t, pt, ec, stack);
	}
	// удвоить
	ecDbl(t, t, ec, stack);
	// сформировать последнюю цифру
	hi = (word)wwTestBit(e, mb - pos);
	for (digit = 0, i = 1; i < pre->w; ++i)
		digit <<= 1, digit ^= (word)wwTestBit(e, mb - i * pre->h - pos);
	digit ^= (WORD_0 - hi) & mask;
	// финишное сложение
	wwSel(pt, pre->pts, pre_count, pt_size, digit);
	ecSgnA(pt, hi, ec, stack);
	ret = (ec->finadda) ?
		ec->finadda(b, t, pt, ec, stack) :
		(ecAddA(t, t, pt, ec, stack), ecToA(b, t, ec, stack));
	// настройка знака
	ecSgnA(b, neg, ec, stack);
	// очистка и возврат
	CLEAN3(neg, digit, hi);
	return ret;
}

size_t ecMulPreSI_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreSI_local(n, ec_d, m),
		ec_deep,
		SIZE_MAX);
}

/*
*******************************************************************************
Кратная точка: метод SH

В функции ecMulPreSH() определяется кратная точка b = (2^l + d)a. Используется 
окно ширины w. Предполагается, что d < 2^l, l < bitlen(order) и w | l. Пусть
h = l/w + 1.

Скаляр 2^l+d записывается в виде
	e_{h-1} (2^w)^{h-1} + ... + e_1 (2^w) + e_0.
Здесь  e_i \in {2^{w-1}, \pm (2^{w-1}+1),...,\pm 2^w}, i = 0, 1,..., h-2, -- 
ненулевые цифры с установленным старшим разрядом и e_{h-1} \in {1, 2}.

Реализован следующий алгоритм:
1. Для i = 0, 1, ..., 2^{w-1}:
	1) pre[i] <- (2^{w-1} + i)a;				// предвычисления: SH
	2) pre[2^{w-1} + 1] <- a;
	3) pre[2^{w-1} + 2] <- 2a.
2. t <- pre[2^{w-1}+e_{h-1}].
3. Для i = h-2, ..., 1, 0:
	1) t <- 2^w t;								// P <- 2P
	2) t <- t + sgn(e_i) pre[|e_i|-2^{w-1}].	// P <- P + P
4. Возвратить t.

\remark Расчет цифр e_i:
1. Записать
     2^l + d = d_{h-1} (2^w)^{h-1} + d_1 (2^w) + d_0,
   где d_i \in {0, 1, ..., 2^w-1}, d_{h-1} = 1.
2. e_0 <- d_0.
3. Для i = 0, 1, ...., h-1:
   1) (e_i, e_{i+1}) <- e_i < 2^{w-1} ? (e_i-2^w, d_{i+1}+1) : (e_i, d_{i+1}).

\remark Цифра e_i хранится в виде (w+1)-разрядного слова:
* старший бит -- признак отрицательности;
* младшие w+1 битов -- |e_i|-2^{w-1}.
*******************************************************************************
*/

#define ecMulPreSH_local(n, ec_d, m)\
/* e */		O_OF_W(2 * m),\
/* t */		O_OF_W(ec_d * n),\
/* pt */	O_OF_W(ec_d * n)

bool_t ecMulPreSH(word b[], const ec_pre_t* pre, const ec_o* ec,
	const word d[], size_t m, void* stack)
{
	register word digit;
	register word carry;
	size_t mb;
	size_t pre_count;
	size_t pt_size;
	word mask;
	word hi;
	size_t i;
	word* e;			/* [2 * m] */
	word* t;			/* [ec->d * ec->f->n] */
	word* pt;			/* [ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecGroupIsOperable(ec));
	ASSERT(ecPreIsOperable(pre));
	ASSERT(pre->type == ec_pre_sh);
	// размерности
	mb = wwBitSize(d, m);
	ASSERT(0 < mb && (mb - 1) % pre->w == 0);
	pre_count = SIZE_BIT_POS(pre->w - 1) + 3;
	pt_size = ec->d * ec->f->n;
	mask = ~WORD_BIT_POS(pre->w);
	hi = WORD_BIT_POS(pre->w - 1);
	// разметить стек
	memSlice(stack,
		ecMulPreSH_local(ec->f->n, ec->d, m), SIZE_0, SIZE_MAX,
		&e, &t, &pt, &stack);
	// перекодирование
	for (i = 0, carry  = 0; i < (mb - 1) / pre->w; ++i)
	{
		// digit <- d_i + carry
		digit = wwGetBits(d, i * pre->w, pre->w);
		digit += carry;
		// carry <- (digit < 2^{w-1})
		carry = wordLess01(digit, hi);
		// digit <- carry ? digit - 2^w : digit
		digit ^= SIZE_0 - carry;
		digit += carry;
		// \post w-й бит digit: признак отрицательности
		// \post младшие w-1 битов digit: |digit - 2^w|
		// сохранить digit в виде (признак, |digit - 2^w| - 2^{w-1})
		wwSetBits(e, i * (pre->w + 1), pre->w + 1, digit - hi);
	}
	// обработать старшую цифру
	ASSERT(wwTestBit(d, i * pre->w));
	wwSel(t, ecPrePt(pre, pre_count - 2, ec), 2, pt_size, carry);
	// обработать остальные цифры
	while (i--)
	{
		size_t j;
		// t <- 2^w t
		for (j = 0; j < pre->w; ++j)
			ecDbl(t, t, ec, stack);
		// сложить
		digit = wwGetBits(e, i * (pre->w + 1), pre->w + 1);
		wwSel(pt, pre->pts, pre_count - 2, pt_size, digit & mask);
		ecSgn(pt, digit >> pre->w, ec, stack);
		ecAdd(t, t, pt, ec, stack);
	}
	// очистка и возврат
	CLEAN2(digit, carry);
	return ecToA(b, t, ec, stack);
}

size_t ecMulPreSH_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return memSliceSize(
		ecMulPreSH_local(n, ec_d, m),
		ec_deep,
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

Для каждого d[i] строится naf[i] длиной l[i] и окном шириной w[i].

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
		ecPreSO(pre[i], a, naf_width[i] - 1, ec, stack);
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
		ecPreSO_deep(n, ec_d, ec_deep),
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
