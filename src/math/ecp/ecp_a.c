/*
*******************************************************************************
\file ecp_a.c
\brief Elliptic curves over prime fields: affine coordinates
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
#include "bee2/math/ww.h"
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

bool_t ecpIsOnA(const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// pre
	ASSERT(ecIsOperable(ec));
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
	return O_OF_W(2 * n) + f_deep;
}

void ecpNegA(word b[], const word a[], const ec_o* ec)
{
	const size_t n = ec->f->n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 2 * n));
	// (xb, yb) <- (xa, -ya)
	qrCopy(ecX(b), ecX(a), ec->f);
	zmNeg(ecY(b, n), ecY(a, n), ec->f);
}

bool_t ecpAddAA(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	stack = t3 + n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
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
	return O_OF_W(3 * n) + f_deep;
}

bool_t ecpSubAA(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	stack = t3 + n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
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
	return O_OF_W(3 * n) + f_deep;
}
