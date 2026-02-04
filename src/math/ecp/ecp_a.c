/*
*******************************************************************************
\file ecp_a.c
\brief Elliptic curves over prime fields: affine coordinates
\project bee2 [cryptographic library]
\created 2012.06.26
\version 2026.02.04
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/util.h"
#include "bee2/math/ecp.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "ecp_lcl.h"

/*
*******************************************************************************
Арифметика аффинных точек

Сложение A <- A + A:
	1D + 1S + 1M + 6add \approx 102M

Удвоение A <- 2A:
	1D + 2S + 1M + 5add + 1*3 + 1*2 \approx 103M
*******************************************************************************
*/

#define ecpIsOnA_local(n)\
/* t1 */	O_OF_W(n),\
/* t2 */	O_OF_W(n)

bool_t ecpIsOnA(const word a[], const ec_o* ec, void* stack)
{
	size_t n;
	word* t1;			/* [n] */
	word* t2;			/* [n] */
	// pre
	ASSERT(ecIsOperable(ec));
	// разметить стек
	n = ec->f->n;
	memSlice(stack,
		ecpIsOnA_local(n), SIZE_0, SIZE_MAX,
		&t1, &t2, &stack);
	// xa, ya \in ec->f?
	if (!zmIsIn(ecX(a), ec->f) || !zmIsIn(ecY(a, n), ec->f))
		return FALSE;
	// t1 <- (xa^2 + A)xa + B
	qrSqr(t1, ecX(a), ec->f, stack);
	zmAdd(t1, t1, ec->A, ec->f);
	qrMul(t1, t1, ecX(a), ec->f, stack);
	zmAdd(t1, t1, ec->B, ec->f);
	// t2 <- ya^2
	qrSqr(t2, ecY(a, n), ec->f, stack);
	// t1 == t2?
	return qrCmp(t1, t2, ec->f) == 0;
}

size_t ecpIsOnA_deep(size_t n, size_t f_deep)
{
	return memSliceSize(
		ecpIsOnA_local(n),
		f_deep,
		SIZE_MAX);
}

void ecpNegA(word b[], const word a[], const ec_o* ec)
{
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 2 * ec->f->n));
	// (xb, yb) <- (xa, -ya)
	qrCopy(ecX(b), ecX(a), ec->f);
	zmNeg(ecY(b, ec->f->n), ecY(a, ec->f->n), ec->f);
}

#define ecpAddAA_local(n)\
/* t1 */	O_OF_W(n),\
/* t2 */	O_OF_W(n),\
/* t3 */	O_OF_W(n)

bool_t ecpAddAA(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	size_t n;
	word* t1;			/* [n] */
	word* t2;			/* [n] */
	word* t3;			/* [n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
	// разметить стек
	n = ec->f->n;
	memSlice(stack,
		ecpAddAA_local(n), SIZE_0, SIZE_MAX,
		&t1, &t2, &t3, &stack);
	// xa != xb?
	if (qrCmp(ecX(a), ecX(b), ec->f) != 0)
	{
		// t1 <- xa - xb
		zmSub(t1, ecX(a), ecX(b), ec->f);
		// t2 <- ya - yb
		zmSub(t2, ecY(a, n), ecY(b, n), ec->f);
	}
	else
	{
		// ya != yb или yb == 0 => a == -b => a + b == O
		if (qrCmp(ecY(a, n), ecY(b, n), ec->f) != 0 || 
			qrIsZero(ecY(b, n), ec->f))
			return FALSE;
		// t2 <- 3 xa^2 + A
		qrSqr(t1, ecX(a), ec->f, stack);
		gfpDouble(t2, t1, ec->f);
		zmAdd(t2, t2, t1, ec->f);
		zmAdd(t2, t2, ec->A, ec->f);
		// t1 <- 2 ya
		gfpDouble(t1, ecY(a, n), ec->f);
	}
	// t2 <- t2 / t1 = \lambda
	qrDiv(t2, t2, t1, ec->f, stack);
	// t1 <- \lambda^2 - xa - xb = xc
	qrSqr(t1, t2, ec->f, stack);
	zmSub(t1, t1, ecX(a), ec->f);
	zmSub(t1, t1, ecX(b), ec->f);
	// t3 <- xa - xc
	zmSub(t3, ecX(a), t1, ec->f);
	// t2 <- \lambda(xa - xc) - ya
	qrMul(t2, t2, t3, ec->f, stack);
	zmSub(t2, t2, ecY(a, n), ec->f);
	// выгрузить результат
	qrCopy(ecX(c), t1, ec->f);
	qrCopy(ecY(c, n), t2, ec->f);
	return TRUE;
}

size_t ecpAddAA_deep(size_t n, size_t f_deep)
{
	return memSliceSize(
		ecpAddAA_local(n),
		f_deep,
		SIZE_MAX);
}

#define ecpSubAA_local(n)\
/* t1 */	O_OF_W(n),\
/* t2 */	O_OF_W(n),\
/* t3 */	O_OF_W(n)

bool_t ecpSubAA(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	size_t n;
	word* t1;			/* [n] */
	word* t2;			/* [n] */
	word* t3;			/* [n] */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
	// разметить стек
	n = ec->f->n;
	memSlice(stack,
		ecpSubAA_local(n), SIZE_0, SIZE_MAX,
		&t1, &t2, &t3, &stack);
	// xa != xb?
	if (qrCmp(ecX(a), ecX(b), ec->f) != 0)
	{
		// t1 <- xa - xb
		zmSub(t1, ecX(a), ecX(b), ec->f);
		// t2 <- ya + yb
		zmAdd(t2, ecY(a, n), ecY(b, n), ec->f);
	}
	else
	{
		// ya == yb => a == b => a - b == O
		if (qrCmp(ecY(a, n), ecY(b, n), ec->f) == 0)
			return FALSE;
		// здесь должно быть a == -b => a - b = 2a
		// t2 <- 3 xa^2 + A
		qrSqr(t1, ecX(a), ec->f, stack);
		gfpDouble(t2, t1, ec->f);
		zmAdd(t2, t2, t1, ec->f);
		zmAdd(t2, t2, ec->A, ec->f);
		// t1 <- 2 ya
		gfpDouble(t1, ecY(a, n), ec->f);
	}
	// t2 <- t2 / t1 = \lambda
	qrDiv(t2, t2, t1, ec->f, stack);
	// t1 <- \lambda^2 - xa - xb = xc
	qrSqr(t1, t2, ec->f, stack);
	zmSub(t1, t1, ecX(a), ec->f);
	zmSub(t1, t1, ecX(b), ec->f);
	// t3 <- xa - xc
	zmSub(t3, ecX(a), t1, ec->f);
	// t2 <- \lambda(xa - xc) - ya
	qrMul(t2, t2, t3, ec->f, stack);
	zmSub(t2, t2, ecY(a, n), ec->f);
	// выгрузить результат
	qrCopy(ecX(c), t1, ec->f);
	qrCopy(ecY(c, n), t2, ec->f);
	return TRUE;
}

size_t ecpSubAA_deep(size_t n, size_t f_deep)
{
	return memSliceSize(
		ecpSubAA_local(n),
		f_deep,
		SIZE_MAX);
}

