/*
*******************************************************************************
\file pp_red.c
\brief Binary polynomials: modular reductions
\project bee2 [cryptographic library]
\created 2012.03.01
\version 2023.11.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/pp.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Редукции

Обоснование корректности ppRedTrinomial() (w == BITSPEWORD):
p(x)x^{w * i} \equiv
	p(x) x^{w * (i - mw) - mb}(x^k + 1) \equiv
	p(x) x^{w * (i - mw) - mb} + f(x)x^{w * (i - kw) - kb}
*******************************************************************************
*/

void ppRed(word a[], const word mod[], size_t n, void* stack)
{
	ppMod(a, a, 2 * n, mod, n, stack);
}

size_t ppRed_deep(size_t n)
{
	return ppMod_deep(2 * n, n);
}

void ppRedTrinomial(word a[], const pp_trinom_st* p)
{
	register word hi;
	size_t mb, mw, kb, kw;
	size_t n;
	// pre
	ASSERT(memIsValid(p, sizeof(pp_trinom_st)));
	ASSERT(wwIsValid(a, 2 * W_OF_B(p->m)));
	ASSERT(p->m % 8 != 0);
	ASSERT(p->m > p->k && p->k > 0);
	ASSERT(p->m - p->k >= B_PER_W);
	// разбор трехчлена
	mb = p->m % B_PER_W;
	mw = p->m / B_PER_W;
	kb = (p->m - p->k) % B_PER_W;
	kw = (p->m - p->k) / B_PER_W;
	// обработать старшие слова
	for (n = 2 * W_OF_B(p->m); --n > mw;)
	{
		hi = a[n];
		a[n - mw - 1] ^= hi << (B_PER_W - mb);
		a[n - mw] ^= hi >> mb;
		a[n - kw - 1] ^= kb ? hi << (B_PER_W - kb) : 0;
		a[n - kw] ^= hi >> kb;
	}
	// слово, на которое попадает моном x^m
	ASSERT(n == mw);
	hi = a[n] >> mb;
	a[0] ^= hi;
	hi <<= mb;
	if (kw < n && kb)
		a[n - kw - 1] ^= hi << (B_PER_W - kb);
	a[n - kw] ^= hi >> kb;
	a[n] ^= hi;
	// очистка
	hi = 0;
}

void ppRedPentanomial(word a[], const pp_pentanom_st* p)
{
	register word hi;
	size_t mb, mw, l1b, l1w, lb, lw, kb, kw;
	size_t n;
	// pre
	ASSERT(memIsValid(p, sizeof(pp_pentanom_st)));
	ASSERT(wwIsValid(a, 2 * W_OF_B(p->m)));
	ASSERT(p->m > p->k && p->k > p->l && p->l > p->l1 && p->l1 > 0);
	ASSERT(p->k < B_PER_W);
	ASSERT(p->m - p->k >= B_PER_W);
	// разбор пятичлена
	mb = p->m % B_PER_W;
	mw = p->m / B_PER_W;
	l1b = (p->m - p->l1) % B_PER_W;
	l1w = (p->m - p->l1) / B_PER_W;
	lb = (p->m - p->l) % B_PER_W;
	lw = (p->m - p->l) / B_PER_W;
	kb = (p->m - p->k) % B_PER_W;
	kw = (p->m - p->k) / B_PER_W;
	// обрабатываем старшие слова
	for (n = 2 * W_OF_B(p->m); --n > mw;)
	{
		hi = a[n];
		a[n - mw - 1] ^= mb ? hi << (B_PER_W - mb) : 0;
		a[n - mw] ^= hi >> mb;
		a[n - l1w - 1] ^= l1b ? hi << (B_PER_W - l1b) : 0;
		a[n - l1w] ^= hi >> l1b;
		a[n - lw - 1] ^= lb ? hi << (B_PER_W - lb) : 0;
		a[n - lw] ^= hi >> lb;
		a[n - kw - 1] ^= kb ? hi << (B_PER_W - kb) : 0;
		a[n - kw] ^= hi >> kb;
	}
	// слово, на которое попадает моном x^m
	ASSERT(n == mw);
	hi = a[n] >> mb;
	a[0] ^= hi;
	hi <<= mb;
	if (l1w < n && l1b)
		a[n - l1w - 1] ^= hi << (B_PER_W - l1b);
	a[n - l1w] ^= hi >> l1b;
	if (lw < n && lb)
		a[n - lw - 1] ^= hi << (B_PER_W - lb);
	a[n - lw] ^= hi >> lb;
	if (kw < n && kb)
		a[n - kw - 1] ^= hi << (B_PER_W - kb);
	a[n - kw] ^= hi >> kb;
	a[n] ^= hi;
	// очистка
	hi = 0;
}

void ppRedBelt(word a[])
{
	const size_t mw = W_OF_B(128);
	size_t n = 2 * mw;
	ASSERT(wwIsValid(a, 2 * mw));
	ASSERT(mw * B_PER_W == 128);
	while (--n >= mw)
	{
		a[n - mw] ^= a[n] ^ a[n] << 1 ^ a[n] << 2 ^ a[n] << 7;
		a[n - mw + 1] ^= a[n] >> (B_PER_W - 1) ^
			a[n] >> (B_PER_W - 2) ^ a[n] >> (B_PER_W - 7);
	}
}

