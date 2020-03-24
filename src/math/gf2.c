/*
*******************************************************************************
\file gf2.c
\brief Binary fields
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.17
\version 2015.11.03
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/mem.h"
#include "bee2/core/stack.h"
#include "bee2/core/util.h"
#include "bee2/math/gf2.h"
#include "bee2/math/pp.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Ускоренные варианты ppRedTrinomial

Предварительно рассчитываются числа bm, wm, bk, wk.

gf2RedTrinomial0: bk == 0.
gf2RedTrinomial1: bk != 0.
*******************************************************************************
*/

typedef struct
{
	size_t m;		/*< степень трехчлена */
	size_t k;		/*< степень среднего монома */
	size_t l;		/*< здесь должен быть 0 */
	size_t l1;		/*< здесь должен быть 0 */
	size_t bm;		/*< m % B_PER_W */
	size_t wm;		/*< m / B_PER_W */
	size_t bk;		/*< (m - k) % B_PER_W */
	size_t wk;		/*< (m - k) / B_PER_W */
} gf2_trinom_st;

static void gf2RedTrinomial0(word a[], size_t n, const gf2_trinom_st* p)
{
	register word hi;
	// pre
	ASSERT(wwIsValid(a, 2 * n));
	ASSERT(memIsValid(p, sizeof(*p)));
	ASSERT(p->m % 8 != 0);
	ASSERT(p->m > p->k && p->k > 0);
	ASSERT(p->m - p->k >= B_PER_W);
	ASSERT(p->bm < B_PER_W && p->bk < B_PER_W);
	ASSERT(p->m == p->wm * B_PER_W + p->bm);
	ASSERT(p->m == p->k + p->wk * B_PER_W + p->bk);
	ASSERT(n == W_OF_B(p->m));
	ASSERT(p->bk == 0);
	// обработать старшие слова
	n *= 2;
	while (--n > p->wm)
	{
		hi = a[n];
		a[n - p->wm - 1] ^= hi << (B_PER_W - p->bm);
		a[n - p->wm] ^= hi >> p->bm;
		a[n - p->wk] ^= hi;
	}
	// слово, на которое попадает моном x^m
	ASSERT(n == p->wm);
	hi = a[n] >> p->bm;
	a[0] ^= hi;
	hi <<= p->bm;
	a[n - p->wk] ^= hi;
	a[n] ^= hi;
	// очистка
	hi = 0;
}

static void gf2RedTrinomial1(word a[], size_t n, const gf2_trinom_st* p)
{
	register word hi;
	// pre
	ASSERT(wwIsValid(a, 2 * n));
	ASSERT(memIsValid(p, sizeof(*p)));
	ASSERT(p->m % 8 != 0);
	ASSERT(p->m > p->k && p->k > 0);
	ASSERT(p->m - p->k >= B_PER_W);
	ASSERT(p->bm < B_PER_W && p->bk < B_PER_W);
	ASSERT(p->m == p->wm * B_PER_W + p->bm);
	ASSERT(p->m == p->k + p->wk * B_PER_W + p->bk);
	ASSERT(n == W_OF_B(p->m));
	ASSERT(p->bk != 0);
	// обработать старшие слова
	n *= 2;
	while (--n > p->wm)
	{
		hi = a[n];
		a[n - p->wm - 1] ^= hi << (B_PER_W - p->bm);
		a[n - p->wm] ^= hi >> p->bm;
		a[n - p->wk - 1] ^= hi << (B_PER_W - p->bk);
		a[n - p->wk] ^= hi >> p->bk;
	}
	// слово, на которое попадает моном x^m
	ASSERT(n == p->wm);
	hi = a[n] >> p->bm;
	a[0] ^= hi;
	hi <<= p->bm;
	if (p->wk < n)
		a[n - p->wk - 1] ^= hi << (B_PER_W - p->bk);
	a[n - p->wk] ^= hi >> p->bk;
	a[n] ^= hi;
	// очистка
	hi = 0;
}

/*
*******************************************************************************
Ускоренные варианты ppRedPentanomial

Предварительно рассчитываются числа bm, wm, bk, wk, wl, bl, wl1, bl1.

Набор (bm, bk, bl, bl1) не может быть нулевым -- соответствующий многочлен
не является неприводимым.

\todo 15 функций gf2RedPentanomial[bm|bk|bl|bl1].
*******************************************************************************
*/

typedef struct
{
	size_t m;		/*< степень пятичлена */
	size_t k;		/*< степень старшего из средних мономов */
	size_t l;		/*< степень среднего из средних мономов */
	size_t l1;		/*< степень младшего из средних мономов */
	size_t bm;		/*< m % B_PER_W */
	size_t wm;		/*< m / B_PER_W */
	size_t bk;		/*< (m - k) % B_PER_W */
	size_t wk;		/*< (m - k) / B_PER_W */
	size_t bl;		/*< (m - l) % B_PER_W */
	size_t wl;		/*< (m - l) / B_PER_W */
	size_t bl1;		/*< (m - l1) % B_PER_W */
	size_t wl1;		/*< (m - l1) / B_PER_W */
} gf2_pentanom_st;

static void gf2RedPentanomial(word a[], size_t n, const gf2_pentanom_st* p)
{
	register word hi;
	// pre
	ASSERT(wwIsValid(a, 2 * n));
	ASSERT(memIsValid(p, sizeof(*p)));
	ASSERT(p->m > p->k && p->k > p->l && p->l > p->l1 && p->l1 > 0);
	ASSERT(p->k < B_PER_W);
	ASSERT(p->m - p->k >= B_PER_W);
	ASSERT(p->bm < B_PER_W && p->bk < B_PER_W);
	ASSERT(p->bl < B_PER_W && p->bl1 < B_PER_W);
	ASSERT(p->m == B_PER_W * p->wm + p->bm);
	ASSERT(p->m == p->k + B_PER_W * p->wk + p->bk);
	ASSERT(p->m == p->l + B_PER_W * p->wl + p->bl);
	ASSERT(p->m == p->l1 + B_PER_W * p->wl1 + p->bl1);
	ASSERT(n == W_OF_B(p->m));
	// обрабатываем старшие слова
	n *= 2;
	while (--n > p->wm)
	{
		hi = a[n];
		a[n - p->wm - 1] ^= p->bm ? hi << (B_PER_W - p->bm) : 0;
		a[n - p->wm] ^= hi >> p->bm;
		a[n - p->wl1 - 1] ^= p->bl1 ? hi << (B_PER_W - p->bl1) : 0;
		a[n - p->wl1] ^= hi >> p->bl1;
		a[n - p->wl - 1] ^= p->bl ? hi << (B_PER_W - p->bl) : 0;
		a[n - p->wl] ^= hi >> p->bl;
		a[n - p->wk - 1] ^= p->bk ? hi << (B_PER_W - p->bk) : 0;
		a[n - p->wk] ^= hi >> p->bk;
	}
	// слово, на которое попадает моном x^m
	ASSERT(n == p->wm);
	hi = a[n] >> p->bm;
	a[0] ^= hi;
	hi <<= p->bm;
	if (p->wl1 < n && p->bl1)
		a[n - p->wl1 - 1] ^= hi << (B_PER_W - p->bl1);
	a[n - p->wl1] ^= hi >> p->bl1;
	if (p->wl < n && p->bl)
		a[n - p->wl - 1] ^= hi << (B_PER_W - p->bl);
	a[n - p->wl] ^= hi >> p->bl;
	if (p->wk < n && p->bk)
		a[n - p->wk - 1] ^= hi << (B_PER_W - p->bk);
	a[n - p->wk] ^= hi >> p->bk;
	a[n] ^= hi;
	// очистка
	hi = 0;
}

/*
*******************************************************************************
Реализация интерфейсов qr_XXX_t

Если степень расширения m кратна B_PER_W, то модуль задается n + 1 словом,
а элементы поля -- n словами. Поэтому в функциях gf2From(), gf2Inv(), 
gf2Div() случай m % B_PER_W == 0 обрабатывается особенным образом.
*******************************************************************************
*/

static bool_t gf2From(word b[], const octet a[], const qr_o* f, void* stack)
{
	ASSERT(gf2IsOperable(f));
	wwFrom(b, a, f->no);
	return gf2IsIn(b, f);
}

static void gf2To(octet b[], const word a[], const qr_o* f, void* stack)
{
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	wwTo(b, f->no, a);
}

static void gf2Add3(word c[], const word a[], const word b[], const qr_o* f)
{
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	ASSERT(gf2IsIn(b, f));
	wwXor(c, a, b, f->n);
}

static void gf2Neg2(word b[], const word a[], const qr_o* f)
{
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	wwCopy(b, a, f->n);
}

static void gf2MulTrinomial0(word c[], const word a[], const word b[], 
	const qr_o* f, void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * f->n;
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	ASSERT(gf2IsIn(b, f));
	ppMul(prod, a, f->n, b, f->n, stack);
	gf2RedTrinomial0(prod, f->n, (const gf2_trinom_st*)f->params);
	wwCopy(c, prod, f->n);
}

static size_t gf2MulTrinomial0_deep(size_t n)
{
	return ppMul_deep(n, n);
}

static void gf2MulTrinomial1(word c[], const word a[], const word b[], 
	const qr_o* f, void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * f->n;
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	ASSERT(gf2IsIn(b, f));
	ppMul(prod, a, f->n, b, f->n, stack);
	gf2RedTrinomial1(prod, f->n, (const gf2_trinom_st*)f->params);
	wwCopy(c, prod, f->n);
}

static size_t gf2MulTrinomial1_deep(size_t n)
{
	return ppMul_deep(n, n);
}

static void gf2MulPentanomial(word c[], const word a[], const word b[], 
	const qr_o* f, void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * f->n;
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	ASSERT(gf2IsIn(b, f));
	ppMul(prod, a, f->n, b, f->n, stack);
	gf2RedPentanomial(prod, f->n, (const gf2_pentanom_st*)f->params);
	wwCopy(c, prod, f->n);
}

static size_t gf2MulPentanomial_deep(size_t n)
{
	return ppMul_deep(n, n);
}

static void gf2SqrTrinomial0(word b[], const word a[], const qr_o* f, 
	void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * f->n;
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	ppSqr(prod, a, f->n, stack);
	gf2RedTrinomial0(prod, f->n, (const gf2_trinom_st*)f->params);
	wwCopy(b, prod, f->n);
}

static size_t gf2SqrTrinomial0_deep(size_t n)
{
	return ppSqr_deep(n);
}

static void gf2SqrTrinomial1(word b[], const word a[], const qr_o* f, 
	void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * f->n;
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	ppSqr(prod, a, f->n, stack);
	gf2RedTrinomial1(prod, f->n, (const gf2_trinom_st*)f->params);
	wwCopy(b, prod, f->n);
}

static size_t gf2SqrTrinomial1_deep(size_t n)
{
	return ppSqr_deep(n);
}

static void gf2SqrPentanomial(word b[], const word a[], const qr_o* f, 
	void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * f->n;
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	ppSqr(prod, a, f->n, stack);
	gf2RedPentanomial(prod, f->n, (const gf2_pentanom_st*)f->params);
	wwCopy(b, prod, f->n);
}

static size_t gf2SqrPentanomial_deep(size_t n)
{
	return ppSqr_deep(n);
}

static void gf2Inv(word b[], const word a[], const qr_o* f, void* stack)
{
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	if (gf2Deg(f) % B_PER_W == 0)
	{
		word* c = (word*)stack;
		stack = c + f->n + 1;
		ppInvMod(c, a, f->mod, f->n + 1, stack);
		ASSERT(c[f->n] == 0);
		wwCopy(b, c, f->n);
	}
	else
		ppInvMod(b, a, f->mod, f->n, stack);
}

static size_t gf2Inv_deep(size_t n)
{
	return O_OF_W(n + 1) + ppInvMod_deep(n + 1);
}

static void gf2Div(word b[], const word divident[], const word a[], 
	const qr_o* f, void* stack)
{
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(divident, f));
	ASSERT(gf2IsIn(a, f));
	if (gf2Deg(f) % B_PER_W == 0)
	{
		word* c = (word*)stack;
		stack = c + f->n + 1;
		ppDivMod(c, divident, a, f->mod, f->n + 1, stack);
		ASSERT(c[f->n] == 0);
		wwCopy(b, c, f->n);
	}
	else
		ppDivMod(b, divident, a, f->mod, f->n, stack);
}

static size_t gf2Div_deep(size_t n)
{
	return O_OF_W(n + 1) + ppDivMod_deep(n + 1);
}

/*
*******************************************************************************
Управление описанием поля
*******************************************************************************
*/

bool_t gf2Create(qr_o* f, const size_t p[4], void* stack)
{
	ASSERT(memIsValid(f, sizeof(qr_o)));
	ASSERT(memIsValid(p, 4 * sizeof(size_t)));
	// нормальный базис?
	if (p[1] == 0)
	{
		// todo: реализовать
		return FALSE;
	}
	// трехчлен?
	else if (p[2] == 0)
	{
		gf2_trinom_st* t;
		size_t n1;
		// нарушены соглашения?
		if (p[2] != 0 || p[3] != 0)
			return FALSE;
		// нарушены условия функции ppRedTrinomial?
		if (p[0] % 8 == 0 || p[1] >= p[0] || p[0] - p[1] < B_PER_W)
			return FALSE;
		// зафиксировать размерность
		f->n = W_OF_B(p[0]);
		n1 = f->n + (p[0] % B_PER_W == 0);
		f->no = O_OF_B(p[0]);
		// сформировать mod
		f->mod = (word*)f->descr;
		wwSetZero(f->mod, n1);
		wwSetBit(f->mod, p[0], 1);
		wwSetBit(f->mod, p[1], 1);
		wwSetBit(f->mod, 0, 1);
		// сформировать unity
		f->unity = f->mod + n1;
		wwSetW(f->unity, f->n, 1);
		// сформировать params
		f->params = (size_t*)(f->unity + f->n);
		t = (gf2_trinom_st*)f->params;
		t->m = p[0];
		t->k = p[1];
		t->l = t->l1 = 0;
		t->bm = p[0] % B_PER_W;
		t->wm = p[0] / B_PER_W;
		t->bk = (p[0] - p[1]) % B_PER_W;
		t->wk = (p[0] - p[1]) / B_PER_W;
		// настроить интерфейсы
		f->from = gf2From;
		f->to = gf2To;
		f->add = gf2Add3;
		f->sub = gf2Add3;
		f->neg = gf2Neg2;
		f->mul = t->bk == 0 ? gf2MulTrinomial0 : gf2MulTrinomial1;
		f->sqr = t->bk == 0 ? gf2SqrTrinomial0 : gf2SqrTrinomial1;
		f->inv = gf2Inv;
		f->div = gf2Div;
		// заголовок
		f->hdr.keep = sizeof(qr_o) + O_OF_W(n1 + f->n) + sizeof(gf2_trinom_st);
		f->hdr.p_count = 3;
		f->hdr.o_count = 0;
		// глубина стека
		if (t->bk == 0)
			f->deep = utilMax(4,
				gf2MulTrinomial0_deep(f->n),
				gf2SqrTrinomial0_deep(f->n),
				gf2Inv_deep(f->n),
				gf2Div_deep(f->n));
		else 
			f->deep = utilMax(4,
				gf2MulTrinomial1_deep(f->n),
				gf2SqrTrinomial1_deep(f->n),
				gf2Inv_deep(f->n),
				gf2Div_deep(f->n));
	}
	// пятичлен?
	else
	{
		gf2_pentanom_st* t;
		size_t n1;
		// нарушены соглашения?
		if (p[3] == 0)
			return FALSE;
		// нарушены условия функции ppRedPentanomial?
		if (p[1] >= p[0] || p[2] >= p[1] || p[3] >= p[2] || p[3] == 0 ||
			p[0] - p[1] < B_PER_W || p[1] >= B_PER_W)
			return FALSE;
		// зафиксировать размерность
		f->n = W_OF_B(p[0]);
		n1 = f->n + (p[0] % B_PER_W == 0);
		f->no = O_OF_B(p[0]);
		// сформировать mod
		f->mod = (word*)f->descr;
		wwSetZero(f->mod, n1);
		wwSetBit(f->mod, p[0], 1);
		wwSetBit(f->mod, p[1], 1);
		wwSetBit(f->mod, p[2], 1);
		wwSetBit(f->mod, p[3], 1);
		wwSetBit(f->mod, 0, 1);
		// сформировать unity
		f->unity = f->mod + n1;
		wwSetW(f->unity, f->n, 1);
		// сформировать params
		f->params = (size_t*)(f->unity + f->n);
		t = (gf2_pentanom_st*)f->params;
		t->m = p[0];
		t->k = p[1];
		t->l = p[2];
		t->l1 = p[3];
		t->bm = p[0] % B_PER_W;
		t->wm = p[0] / B_PER_W;
		t->bk = (p[0] - p[1]) % B_PER_W;
		t->wk = (p[0] - p[1]) / B_PER_W;
		t->bl = (p[0] - p[2]) % B_PER_W;
		t->wl = (p[0] - p[2]) / B_PER_W;
		t->bl1 = (p[0] - p[3]) % B_PER_W;
		t->wl1 = (p[0] - p[3]) / B_PER_W;
		// настроить интерфейсы
		f->from = gf2From;
		f->to = gf2To;
		f->add = gf2Add3;
		f->sub = gf2Add3;
		f->neg = gf2Neg2;
		f->mul = gf2MulPentanomial;
		f->sqr = gf2SqrPentanomial;
		f->inv = gf2Inv;
		f->div = gf2Div;
		// заголовок
		f->hdr.keep = sizeof(qr_o) + O_OF_W(n1 + f->n) + 
			sizeof(gf2_pentanom_st);
		f->hdr.p_count = 3;
		f->hdr.o_count = 0;
		// глубина стека
		f->deep = utilMax(4,
			gf2MulPentanomial_deep(f->n),
			gf2SqrPentanomial_deep(f->n),
			gf2Inv_deep(f->n),
			gf2Div_deep(f->n));
	}
	return TRUE;
}

size_t gf2Create_keep(size_t m)
{
	const size_t n = W_OF_B(m);
	const size_t n1 = n + (m % B_PER_W == 0);
	return sizeof(qr_o) + O_OF_W(n1 + n) + 
		utilMax(2, 
			sizeof(gf2_trinom_st),
			sizeof(gf2_pentanom_st));
}

size_t gf2Create_deep(size_t m)
{
	const size_t n = W_OF_B(m);
	return utilMax(8, 
		gf2MulTrinomial0_deep(n),
		gf2SqrTrinomial0_deep(n),
		gf2MulTrinomial1_deep(n),
		gf2SqrTrinomial1_deep(n),
		gf2MulPentanomial_deep(n),
		gf2SqrPentanomial_deep(n),
		gf2Inv_deep(n),
		gf2Div_deep(n));
}

bool_t gf2IsOperable(const qr_o* f)
{
	const size_t* p;
	size_t n1;
	if (!qrIsOperable(f) || 
		!memIsValid(f->params, 4 * sizeof(size_t)))
		return FALSE;
	// проверить описание многочлена
	p = (size_t*)f->params;
	if (p[0] <= p[1] || p[1] < p[2] || p[2] < p[3] ||
		(p[2] > 0 && (p[1] == p[2] || p[2] == p[3] || p[3] == 0)) ||
		f->n != W_OF_B(p[0]) || f->no != O_OF_B(p[0]))
		return FALSE;
	// проверить модуль
	n1 = f->n + (p[0] % B_PER_W == 0);
	if (!wwIsValid(f->mod, n1) || f->mod[n1 - 1] == 0)
		return FALSE;
	// все нормально
	return TRUE;
}

bool_t gf2IsValid(const qr_o* f, void* stack)
{
	const size_t* p;
	if (!gf2IsOperable(f))
		return FALSE;
	p = (const size_t*)f->params;
	if (p[1] > 0)
	{
		// согласованность
		const size_t n1 = f->n + (p[0] % B_PER_W == 0);
		word* mod = (word*)stack;
		wwSetZero(mod, n1);
		wwSetBit(mod, p[0], 1);
		wwSetBit(mod, p[1], 1);
		wwSetBit(mod, p[2], 1);
		wwSetBit(mod, p[3], 1);
		wwSetBit(mod, 0, 1);
		if (!wwEq(mod, f->mod, n1))
			return FALSE;
		// неприводимость
		return ppIsIrred(f->mod, n1, stack);
	}
	return TRUE;
}

size_t gf2IsValid_deep(size_t n)
{
	return O_OF_W(n + 1) + ppIsIrred_deep(n + 1);
}

size_t gf2Deg(const qr_o* f)
{
	ASSERT(gf2IsOperable(f));
	return ((size_t*)f->params)[0];
}

/*
*******************************************************************************
Дополнительные функции

В gf2QSolve() реализован алгоритм из раздела 6.7 ДСТУ 4145-2002.
*******************************************************************************
*/

bool_t gf2Tr(const word a[], const qr_o* f, void* stack)
{
	size_t m = gf2Deg(f);
	word* t = (word*)stack;
	stack = t + f->n;
	// pre
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	// t <- sum_{i = 0}^{m - 1} a^{2^i}
	qrCopy(t, a, f);
	while (--m)
	{
		qrSqr(t, t, f, stack);
		gf2Add2(t, a, f);
	}
	// t == 0?
	if (qrIsZero(t, f))
		return FALSE;
	// t == 1?
	ASSERT(qrIsUnity(t, f));
	return TRUE;
}

size_t gf2Tr_deep(size_t n, size_t f_deep)
{
	return O_OF_W(n) + f_deep;
}

bool_t gf2QSolve(word x[], const word a[], const word b[],
	const qr_o* f, void* stack)
{
	size_t m = gf2Deg(f);
	word* t = (word*)stack;
	stack = t + f->n;
	// pre
	ASSERT(gf2IsOperable(f));
	ASSERT(gf2IsIn(a, f));
	ASSERT(gf2IsIn(b, f));
	ASSERT(x + f->n <= a || x >= a + f->n);
	ASSERT(m % 2);
	// a == 0?
	if (qrIsZero(a, f))
	{
		// x <- b^{2^{m - 1}}
		qrCopy(x, b, f);
		while (--m)
			qrSqr(x, x, f, stack);
		return TRUE;
	}
	// a != 0, b == 0?
	if (qrIsZero(b, f))
	{
		qrSetZero(x, f);
		return TRUE;
	}
	// t <- ba^{-2}
	qrSqr(t, a, f, stack);
	qrDiv(t, b, t, f, stack);
	// tr(t) == 1?
	if (gf2Tr(t, f, stack))
		return FALSE;
	// x <- htr(t) (полуслед)
	qrCopy(x, t, f);
	m = (m - 1) / 2;
	while (m--)
	{
		qrSqr(x, x, f, stack);
		qrSqr(x, x, f, stack);
		gf2Add2(x, t, f);
	}
	// x <- x * a
	qrMul(x, x, a, f, stack);
	// решение есть
	return TRUE;
}

size_t gf2QSolve_deep(size_t n, size_t f_deep)
{
	return O_OF_W(n) + f_deep;
}
