/*
*******************************************************************************
\file gfp.c
\brief Prime fields
\project bee2 [cryptographic library]
\created 2012.07.11
\version 2026.02.13
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/gfp.h"
#include "bee2/math/pri.h"
#include "bee2/math/zm.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Обращение и деление

Обращение выполняется по малой теореме Ферма: 
	a^{-1} <- a^{p-2} mod p.
Достигается регулярность по обращаемому элементу.
*******************************************************************************
*/

#define gfpInv_local(n)\
/* t */	O_OF_W(n)

static void gfpInv(word b[], const word a[], const qr_o* r, void* stack)
{
	word* t;			/* [n] */
	ASSERT(gfpIsOperable(r));
	ASSERT(zmIsIn(a, r));
	memSlice(stack,
		gfpInv_local(r->n), SIZE_0, SIZE_MAX,
		&t, &stack);
	wwCopy(t, r->mod, r->n);
	zzSubW2(t, r->n, 2);
	qrPower(b, a, t, r->n, r, stack);
}

size_t gfpInv_deep(size_t n, size_t r_deep)
{
	return memSliceSize(
		gfpInv_local(n), 
		qrPower_deep(n, n, r_deep),
		SIZE_MAX);
}

#define gfpDiv_local(n)\
/* t */	O_OF_W(n)

static void gfpDiv(word c[], const word a[], const word b[], const qr_o* r, 
	void* stack)
{
	word* t;			/* [n] */
	ASSERT(gfpIsOperable(r));
	ASSERT(zmIsIn(a, r));
	ASSERT(zmIsIn(b, r));
	memSlice(stack,
		gfpDiv_local(r->n), SIZE_0, SIZE_MAX,
		&t, &stack);
	wwCopy(t, r->mod, r->n);
	zzSubW2(t, r->n, 2);
	qrPower(t, b, t, r->n, r, stack);
	qrMul(c, a, t, r, stack);
}

size_t gfpDiv_deep(size_t n, size_t r_deep)
{
	return memSliceSize(
		gfpDiv_local(n), 
		utilMax(2,
			r_deep,
			qrPower_deep(n, n, r_deep)),
		SIZE_MAX);
}

/*
*******************************************************************************
Управление описанием поля

\todo Поддержать функции редукции для простых Солинаса из NIST:
P192, P224, P256, P384, P521.

\todo Реализовать алгоритм обращения a^{-1} mod p, p -- простое, предложенный 
в [TKL86] и цитируемый в [Doc05; Algorithm 11.9 -- prime field inversion]:
	t <- a mod p, b <- 1
	while t != 1
		q <- - (p div t)
		t <- p + q t
		b <- (q b) mod p
	return b

[TKL86] Thomas J.J., Keller J.M., Larsen G.N. The calculation of multiplicative 
        inverses over GF(p) efficiently where p is a Mersenne prime, 
        IEEE Trans. on Computers 35 No5 (1986), 478–482.
[Doc05] Doche C. Finite Field Arithmetic. In: Handbook of Elliptic and 
        Hyperelliptic Curve Cryptography, Chapman & Hall/CRC, 2005.
*******************************************************************************
*/

bool_t gfpCreate(qr_o* r, const octet p[], size_t no, void* stack)
{
	ASSERT(memIsValid(r, sizeof(*r)));
	ASSERT(memIsValid(p, no));
	ASSERT(no > 0 && p[no - 1] > 0);
	// p -- четное или p == 1?
	if (no == 0 || p[0] % 2 == 0 || no == 1 && p[0] == 1)
		return FALSE;
	// создать GF(p) как ZZ / (p)
	zmCreate(r, p, no, stack);
	// перегрузить функции обращения и деления
	r->inv = gfpInv, r->div = gfpDiv;
	r->deep = MAX3(r->deep, gfpInv_deep(r->n, r->deep), 
		gfpDiv_deep(r->n, r->deep));
	// все хорошо
	return TRUE;
}

size_t gfpCreate_keep(size_t no)
{
	return zmCreate_keep(no);
}

size_t gfpCreate_deep(size_t no)
{
	const size_t r_deep = zmCreate_deep(no);
	return MAX3(r_deep, gfpInv_deep(W_OF_O(no), r_deep),
		gfpDiv_deep(W_OF_O(no), r_deep));
}

bool_t gfpIsOperable(const qr_o* f)
{
	return zmIsValid(f) && 
		f->mod[0] % 2 &&
		(f->n > 1 || f->mod[0] > 1);
}

bool_t gfpIsValid(const qr_o* f, void* stack)
{
	return gfpIsOperable(f) &&
		priIsPrime(f->mod, f->n, stack);
}

size_t gfpIsValid_deep(size_t n)
{
	return priIsPrime_deep(n);
}
