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
		ec->nega != 0 &&
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
	const octet order[], size_t order_len, u32 cofactor,
	size_t w, const octet Gs[], void* stack)
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
	// предвычисления
	ec->precomp_w = w;
	ec->precomp_Gs = (const word *)Gs;
	//TODO: выделить память под precomp_Gs в ec->descr и форсировать предвычисления, если Gs==NULL
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
Имеет порядок?
*******************************************************************************
*/

bool_t ecHasOrderA(const word a[], const ec_o* ec, const word q[], size_t m,
	void* stack)
{
	const size_t na = ec->f->n * 2;
	const size_t order_len = ec->f->n + 1;
	register bool_t f;
	// переменные в stack
	word* b = (word*)stack;
	word* qq = b + na;
	stack = qq + order_len;

	wwSetZero(qq, order_len);
	zzSubW(qq, q, m, WORD_1);
	//todo обсудить - добавить поддержку d >= q в SAFE(ecMulA) и вернуться к q a == O?

	// - ((q - 1) a) == a?
#ifdef SAFE_FAST
	if (!ecMulA(b, a, ec, qq, m, stack))
		return FALSE;
	ecNegA(b, b, ec);
	return wwEq(b, a, na);
#else
	f = ecMulA(b, a, ec, qq, m, stack);
	ecNegA(b, b, ec);
	f &= wwEq(b, a, na);
	return f;
#endif
}

size_t ecHasOrderA_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m)
{
	return O_OF_W(2 * n + n + 1) + ecMulA_deep(n, ec_d, ec_deep, m);
}

void ecDblAddA(word c[], const word a[], const word b[], bool_t neg_b, const struct ec_o* ec, void* stack) {
	//todo SAFE - memcpy b to another buffer and apply (-1)^(1+neg_b) to it?
	ecDbl(c, a, ec, stack);
	if (neg_b) {
		ecSubA(c, c, b, ec, stack);
	}
	else
	{
		ecAddA(c, c, b, ec, stack);
	}
}
