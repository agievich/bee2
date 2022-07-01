/*
*******************************************************************************
\file ecp_misc.c
\brief Elliptic curves over prime fields: : miscellaneous functions
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
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "ecp_lcl.h"

/*
*******************************************************************************
Свойства кривой
*******************************************************************************
*/

bool_t ecpIsValid(const ec_o* ec, void* stack)
{
	size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	stack = t3 + n;
	// кривая работоспособна?
	// поле ec->f корректно?
	// f->mod > 3?
	// ec->deep >= ec->f->deep?
	// A, B \in ec->f?
	if (!ecIsOperable2(ec) ||
		!gfpIsValid(ec->f, stack) ||
		wwCmpW(ec->f->mod, ec->f->n, 3) <= 0 ||
		ec->deep < ec->f->deep ||
		!zmIsIn(ec->A, ec->f) ||
		!zmIsIn(ec->B, ec->f))
		return FALSE;
	// t1 <- 4 A^3
	qrSqr(t1, ec->A, ec->f, stack);
	qrMul(t1, t1, ec->A, ec->f, stack);
	gfpDouble(t1, t1, ec->f);
	gfpDouble(t1, t1, ec->f);
	// t3 <- 3 B^2
	qrSqr(t2, ec->B, ec->f, stack);
	gfpDouble(t3, t2, ec->f);
	zmAdd(t3, t3, t2, ec->f);
	// t2 <- 3 t3 [27 B^2]
	gfpDouble(t2, t3, ec->f);
	zmAdd(t2, t3, t2, ec->f);
	// t1 <- t1 + t2 [4 A^3 + 27 B^2 -- дискриминант]
	zmAdd(t1, t1, t2, ec->f);
	// t1 == 0 => сингулярная кривая
	return !qrIsZero(t1, ec->f);
}

size_t ecpIsValid_deep(size_t n, size_t f_deep)
{
	return O_OF_W(3 * n) +
		utilMax(2,
			f_deep,
			gfpIsValid_deep(n));
}

bool_t ecpSeemsValidGroup(const ec_o* ec, void* stack)
{
	size_t n = ec->f->n;
	int cmp;
	word w;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n + 1;
	word* t3 = t2 + n + 2;
	stack = t3 + 2 * n;
	// pre
	ASSERT(ecIsOperable(ec));
	// ecIsOperableGroup(ec) == TRUE? base \in ec?
	if (!ecIsOperableGroup(ec) ||
		!ecpIsOnA(ec->base, ec, stack))
		return FALSE;
	// [n + 2]t1 <- order * cofactor
	t1[n + 1] = zzMulW(t1, ec->order, n + 1, ec->cofactor);
	// t1 <- |t1 - (p + 1)|
	if (zzSubW2(t1, n + 2, 1))
		return FALSE;
	if (wwCmp2(t1, n + 2, ec->f->mod, n) >= 0)
		zzSubW2(t1 + n, 2, zzSub2(t1, ec->f->mod, n));
	else
		zzSub(t1, ec->f->mod, t1, n);
	// n <- длина t1
	n = wwWordSize(t1, n + 2);
	// n > ec->f->n => t1^2 > 4 p
	if (n > ec->f->n)
		return FALSE;
	// [2n]t2 <- ([n]t1)^2
	zzSqr(t2, t1, n, stack);
	// условие Хассе: t2 <= 4 p?
	w = wwGetBits(t2, 0, 2);
	wwShLo(t2, 2 * n, 2);
	cmp = wwCmp2(t2, 2 * n, ec->f->mod, ec->f->n);
	if (cmp > 0 || cmp == 0 && w != 0)
		return FALSE;
	// все нормально
	return TRUE;
}

size_t ecpSeemsValidGroup_deep(size_t n, size_t f_deep)
{
	return O_OF_W(4 * n + 3) +
		utilMax(2,
			ecpIsOnA_deep(n, f_deep),
			zzSqr_deep(n));
}

bool_t ecpIsSafeGroup(const ec_o* ec, size_t mov_threshold, void* stack)
{
	size_t n1 = ec->f->n + 1;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n1;
	stack = t2 + n1;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecIsOperableGroup(ec));
	// order -- простое?
	n1 = wwWordSize(ec->order, n1);
	if (!priIsPrime(ec->order, n1, stack))
		return FALSE;
	// order == p?
	if (wwCmp2(ec->f->mod, ec->f->n, ec->order, n1) == 0)
		return FALSE;
	// проверка MOV
	if (mov_threshold)
	{
		zzMod(t1, ec->f->mod, ec->f->n, ec->order, n1, stack);
		wwCopy(t2, t1, n1);
		if (wwCmpW(t2, n1, 1) == 0)
			return FALSE;
		while (--mov_threshold)
		{
			zzMulMod(t2, t2, t1, ec->order, n1, stack);
			if (wwCmpW(t2, n1, 1) == 0)
				return FALSE;
		}
	}
	// все нормально
	return TRUE;
}

size_t ecpIsSafeGroup_deep(size_t n)
{
	const size_t n1 = n + 1;
	return O_OF_W(2 * n1) +
		utilMax(3,
			priIsPrime_deep(n1),
			zzMod_deep(n, n1),
			zzMulMod_deep(n1));
}

/*
*******************************************************************************
Алгоритм SWU

\todo Регуляризировать (qrIsUnitySafe).
*******************************************************************************
*/

void ecpSWU(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	register size_t mask;
	// переменные в stack [x2 после x1, s после y!]
	word* t = (word*)stack;
	word* x1 = t + n;
	word* x2 = x1 + n;
	word* y = x2 + n;
	word* s = y + n;
	stack = s + n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(zmIsIn(a, ec->f));
	ASSERT(wwGetBits(ec->f->mod, 0, 2) == 3);
	ASSERT(!qrIsZero(ec->A, ec->f) && !qrIsZero(ec->B, ec->f));
	// t <- -a^2
	qrSqr(t, a, ec->f, stack);
	zmNeg(t, t, ec->f);
	// s <- p - 2
	wwCopy(s, ec->f->mod, n);
	zzSubW2(s, n, 2);
	// x1 <- -B(1 + t + t^2)(A(t + t^2))^{p - 2}
	qrSqr(x2, t, ec->f, stack);
	qrAdd(x2, x2, t, ec->f);
	qrMul(x1, x2, ec->A, ec->f, stack);
	qrPower(x1, x1, s, n, ec->f, stack);
	qrAddUnity(x2, x2, ec->f);
	qrMul(x1, x1, x2, ec->f, stack);
	qrMul(x1, x1, ec->B, ec->f, stack);
	zmNeg(x1, x1, ec->f);
	// y <- (x1)^3 + A x1 + B
	qrSqr(x2, x1, ec->f, stack);
	qrMul(x2, x2, x1, ec->f, stack);
	qrMul(y, x1, ec->A, ec->f, stack);
	qrAdd(y, y, x2, ec->f);
	qrAdd(y, y, ec->B, ec->f);
	// x2 <- x1 t
	qrMul(x2, x1, t, ec->f, stack);
	// t <- y^{(p - 1) - (p + 1) / 4} = y^{s - (p - 3) / 4}
	wwCopy(t, ec->f->mod, n);
	wwShLo(t, n, 2);
	zzSub(s, s, t, n);
	qrPower(t, y, s, n, ec->f, stack);
	// s <- a^3 y
	qrSqr(s, a, ec->f, stack);
	qrMul(s, s, a, ec->f, stack);
	qrMul(s, s, y, ec->f, stack);
	// mask <- t^2 y == 1 ? 0 : -1;
	qrSqr(b, t, ec->f, stack);
	qrMul(b, b, y, ec->f, stack);
	mask = qrIsUnity(b, ec->f) - SIZE_1;
	// b <- mask == 0 ? (x1, t y) : (x2, t s)
	qrCopy(ecX(b), x1 + (mask & n), ec->f);
	qrMul(ecY(b, n), t, y + (mask & n), ec->f, stack);
	// очистка
	mask = 0;
}

size_t ecpSWU_deep(size_t n, size_t f_deep)
{
	return O_OF_W(5 * n) +
		utilMax(2,
			f_deep,
			qrPower_deep(n, n, f_deep));
}
