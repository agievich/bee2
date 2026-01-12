/*
*******************************************************************************
\file ec.c
\brief Elliptic curves
\project bee2 [cryptographic library]
\created 2014.03.04
\version 2026.01.12
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
	ec->w = 1;
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
	return ec->w >= 1 &&
		wwIsValid(ec->base, 2 * (SIZE_1 << (ec->w - 1)) * ec->f->n) &&
		wwIsValid(ec->order, ec->f->n + 1) &&
		!wwIsZero(ec->order, ec->f->n + 1) &&
		ec->cofactor != 0;
}

/*
*******************************************************************************
Малые нечетные кратные

Простейшая реализация интерфейса ec_smul_i:
	t <- 2a, b[0] <- a, b[i] <-  t + b[i - 1], i = 1,..., 2^(w-1) - 1.

Сложение t + b[0] выполняется по схеме P <- P + A. Остальные сложения -- по
схеме P <- P + P.
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
Кратная точка: NAF

Для определения b = da (d-кратное точки a) используется оконный NAF с
длиной окна w > 2. В функции ecMul0() реализован алгоритм 3.36 из [1].

Используются малые нечетные кратные a:
	b[i] = (2i + 1)a,  i = 0, 1, ..., 2^{w-2} - 1.
Они вычисляются с помощью функции интерфейса ec_smul_i, указанной в описании
кривой. Если искомая функция не задана в описании, то используется функция
по умолчанию ecSmul().

Пусть l = wwBitSize(d). Если расчет малых кратных выполняется с помощью
функции ecSmul(), то средняя сложность нахождения кратной точки:
	c(l, w) = 1(P <- 2A) + 1(P <- P + A) + (2^{w-2} - 2)(P <- P + P) +
	          l/(w + 1)(P <- P + P) + l(P <- 2P).

Здесь 
- (P <- 2A) -- время работы функции ec->dbla;
- (P <- P + A) -- время работы функций ec->adda / ec->suba;
- (P <- P + P) -- время работы функции ec->add / ec->sub;
- (P <- 2P) -- время работы функции ec->dbl.

Длина окна w выбирается как решение следующей оптимизационной задачи:
	(2^{w - 2} - 2) + l / (w + 1) -> min.

[1] Hankerson D., Menezes A., Vanstone S. Guide to Elliptic Curve Cryptography,
Springer, 2004.
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

#define ecMulNAF_local(n, ec_d, m, pre_count)\
/* naf */	O_OF_W(2 * m + 1),\
/* t */		O_OF_W(ec_d * n),\
/* pre */	O_OF_W(pre_count * ec_d * n)

bool_t ecMul0(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, void* stack)
{
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const word naf_hi = WORD_BIT_POS(naf_width - 1);
	const size_t pre_count = SIZE_1 << (naf_width - 1);
	register size_t naf_size;
	register size_t i;
	register word w;
	word* naf;			/* [2 * m + 1] NAF */
	word* t;			/* [ec->d * ec->f->n] вспомогательная точка */
	word* pre;			/* [naf_count * ec->d * ec->f->n] */
	// pre
	ASSERT(ecIsOperable(ec));
	// разметить стек
	memSlice(stack,
		ecMulNAF_local(ec->f->n, ec->d, m, pre_count), SIZE_0, SIZE_MAX,
		&naf, &t, &pre, &stack);
	// расчет NAF
	ASSERT(naf_width >= 3);
	naf_size = wwNAF(naf, d, m, naf_width);
	// d == O => b <- O
	if (naf_size == 0)
		return FALSE;
	// малые кратные
	if (ec->smul)
		ec->smul(pre, a, naf_width - 1, ec, stack);
	else
		ecSmul(pre, a, naf_width - 1, ec, stack);
	// отрицательные малые кратные
	for (i = 0; i < pre_count / 2; ++i)
		ec->neg(pre + (pre_count / 2 + i) * ec->d * ec->f->n,
			pre + i * ec->d * ec->f->n, ec, stack);
	// t <- a[naf[l - 1]]
	w = wwGetBits(naf, 0, naf_width);
	ASSERT((w & 1) == 1 && (w & naf_hi) == 0);
	wwCopy(t, pre + (w >> 1) * ec->d * ec->f->n, ec->d * ec->f->n);
	// цикл по символам NAF
	i = naf_width;
	while (--naf_size)
	{
		// t <- 2 t
		ecDbl(t, t, ec, stack);
		// обработать цифру naf
		w = wwGetBits(naf, i, naf_width);
		if (w & 1)
		{
			// t <- t + pre[w / 2]
			if (w == 1 || w == (naf_hi ^ 1))
				ecAddA(t, t, pre + (w >> 1) * ec->d * ec->f->n, ec, stack);
			else
				ecAdd(t, t, pre + (w >> 1) * ec->d * ec->f->n, ec, stack);
			// к следующей цифре
			i += naf_width;
		}
		else
			// к следующей цифре
			++i;
	}
	// очистка
	CLEAN2(w, i);
	// к аффинным координатам
	return ecToA(b, t, ec, stack);
}

size_t ecMul0_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	const size_t naf_width = ecNAFWidth(B_OF_W(m));
	const size_t pre_count = SIZE_1 << (naf_width - 1);
	return memSliceSize(
		ecMulNAF_local(n, ec_d, m, pre_count),
		ecSmul_deep(n, ec_d, ec_deep),
		SIZE_MAX);
}

/*
*******************************************************************************
Имеет порядок?
*******************************************************************************
*/

#define ecHasOrderA_local(n, ec_d)\
/* b */		O_OF_W(ec_d * n)

bool_t ecHasOrderA(const word a[], const ec_o* ec, const word q[], size_t m,
	void* stack)
{
	word* b;			/* [ec->d * ec->f->n] */
	// разметить стек
	memSlice(stack,
		ecHasOrderA_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&b, &stack);
	// q a == O?
	return !ecMulA(b, a, ec, q, m, stack);
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

Реализован алгоритм 3.51 (interleaving with NAF) из [1].

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
	register word w;
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
		if (ec->smul)
			ec->smul(pre[i], a, naf_width[i] - 1, ec, stack);
		else
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
			w = wwGetBits(naf[i], naf_pos[i], naf_width[i]);
			// обработать цифру
			naf_hi = WORD_BIT_POS(naf_width[i] - 1);
			if (w & 1)
			{
				// t <- t + pre[i][w / 2]
				if (w == 1 || w == (naf_hi ^ 1))
					ecAddA(t, t, pre[i] + (w >> 1) * ec->d * ec->f->n, ec,
						stack);
				else
					ecAdd(t, t, pre[i] + (w >> 1) * ec->d * ec->f->n, ec,
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
	CLEAN2(naf_max_size, w);
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
