/*
*******************************************************************************
\file zm.с
\brief Quotient rings of integers modulo m
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.09.14
\version 2016.07.04
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ww.h"
#include "bee2/math/zm.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Кольцо с обычной редукцией
*******************************************************************************
*/

static bool_t zmFrom(word b[], const octet a[], const qr_o* r, void* stack)
{
	ASSERT(zmIsOperable(r));
	wwFrom(b, a, r->no);
	return zmIsIn(b, r);
}

static void zmTo(octet b[], const word a[], const qr_o* r, void* stack)
{
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	wwTo(b, r->no, a);
}

static void zmAdd2(word c[], const word a[], const word b[], const qr_o* r)
{
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	ASSERT(zmIsIn(b, r));
	zzAddMod(c, a, b, r->mod, r->n);
}

static void zmSub2(word c[], const word a[], const word b[], const qr_o* r)
{
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	ASSERT(zmIsIn(b, r));
	zzSubMod(c, a, b, r->mod, r->n);
}

static void zmNeg2(word b[], const word a[], const qr_o* r)
{
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	zzNegMod(b, a, r->mod, r->n);
}

static void zmMul(word c[], const word a[], const word b[],
	const qr_o* r, void* stack)
{
	word* prod = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	ASSERT(zmIsIn(b, r));
	stack = prod + 2 * r->n;
	zzMul(prod, a, r->n, b, r->n, stack);
	zzRed(prod, r->mod, r->n, stack);
	wwCopy(c, prod, r->n);
}

static size_t zmMul_deep(size_t n)
{
	return utilMax(2,
		zzMul_deep(n, n),
		zzRed_deep(n));
}

static void zmSqr(word b[], const word a[], const qr_o* r, void* stack)
{
	word* prod = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	stack = prod + 2 * r->n;
	zzSqr(prod, a, r->n, stack);
	zzRed(prod, r->mod, r->n, stack);
	wwCopy(b, prod, r->n);
}

static size_t zmSqr_deep(size_t n)
{
	return utilMax(2,
		zzSqr_deep(n),
		zzRed_deep(n));
}

static void zmInv(word b[], const word a[], const qr_o* r, void* stack)
{
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	zzInvMod(b, a, r->mod, r->n, stack);
}

static size_t zmInv_deep(size_t n)
{
	return zzInvMod_deep(n);
}

static void zmDiv(word b[], const word divident[], const word a[],
	const qr_o* r, void* stack)
{
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(divident, r));
	ASSERT(zmIsIn(a, r));
	zzDivMod(b, divident, a, r->mod, r->n, stack);
}

static size_t zmDiv_deep(size_t n)
{
	return zzDivMod_deep(n);
}

void zmCreatePlain(qr_o* r, const octet mod[], size_t no, void* stack)
{
	ASSERT(memIsValid(r, sizeof(qr_o)));
	ASSERT(memIsValid(mod, no));
	ASSERT(no > 0 && mod[no - 1] > 0);
	// зафиксировать размерности
	r->n = W_OF_O(no);
	r->no = no;
	// зафиксировать модуль
	r->mod = (word*)r->descr;
	wwFrom(r->mod, mod, no);
	// подготовить единицу
	r->unity = r->mod + r->n;
	r->unity[0] = 1;
	wwSetZero(r->unity + 1, r->n - 1);
	// не использовать параметры
	r->params = 0;
	// настроить функции
	r->from = zmFrom;
	r->to = zmTo;
	r->add = zmAdd2;
	r->sub = zmSub2;
	r->neg = zmNeg2;
	r->mul = zmMul;
	r->sqr = zmSqr;
	r->inv = zmInv;
	r->div = zmDiv;
	r->deep = utilMax(4,
		zmMul_deep(r->n),
		zmSqr_deep(r->n),
		zmInv_deep(r->n),
		zmDiv_deep(r->n));
	// настроить заголовок
	r->hdr.keep = sizeof(qr_o) + O_OF_W(2 * r->n);
	r->hdr.p_count = 3;
	r->hdr.o_count = 0;
}

size_t zmCreatePlain_keep(size_t no)
{
	const size_t n = W_OF_O(no);
	return sizeof(qr_o) + O_OF_W(2 * n);
}

size_t zmCreatePlain_deep(size_t no)
{
	const size_t n = W_OF_O(no);
	return utilMax(4,
		zmMul_deep(n),
		zmSqr_deep(n),
		zmInv_deep(n),
		zmDiv_deep(n));
}

/*
*******************************************************************************
Кольцо с редукцией Крэндалла
*******************************************************************************
*/

static void zmMulCrand(word c[], const word a[], const word b[],
	const qr_o* r, void* stack)
{
	word* prod = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	ASSERT(zmIsIn(b, r));
	stack = prod + 2 * r->n;
	zzMul(prod, a, r->n, b, r->n, stack);
	zzRedCrand(prod, r->mod, r->n, stack);
	wwCopy(c, prod, r->n);
}

static size_t zmMulCrand_deep(size_t n)
{
	return utilMax(2,
		zzMul_deep(n, n),
		zzRedCrand_deep(n));
}

static void zmSqrCrand(word b[], const word a[], const qr_o* r, void* stack)
{
	word* prod = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	stack = prod + 2 * r->n;
	zzSqr(prod, a, r->n, stack);
	zzRedCrand(prod, r->mod, r->n, stack);
	wwCopy(b, prod, r->n);
}

static size_t zmSqrCrand_deep(size_t n)
{
	return utilMax(2,
		zzSqr_deep(n),
		zzRedCrand_deep(n));
}

void zmCreateCrand(qr_o* r, const octet mod[], size_t no, void* stack)
{
	ASSERT(memIsValid(r, sizeof(qr_o)));
	ASSERT(memIsValid(mod, no));
	ASSERT(no > 0 && mod[no - 1] > 0);
	ASSERT(no % O_PER_W == 0 && no >= 2 * O_PER_W);
	ASSERT(!memIsZero(mod, O_PER_W));
	ASSERT(memIsRep(mod + O_PER_W, no - O_PER_W, 0xFF));
	// зафиксировать размерности
	r->n = W_OF_O(no);
	r->no = no;
	// зафиксировать модуль
	r->mod = (word*)r->descr;
	wwFrom(r->mod, mod, no);
	// подготовить единицу
	r->unity = r->mod + r->n;
	r->unity[0] = 1;
	wwSetZero(r->unity + 1, r->n - 1);
	// не использовать параметры
	r->params = 0;
	// настроить функции
	r->from = zmFrom;
	r->to = zmTo;
	r->add = zmAdd2;
	r->sub = zmSub2;
	r->neg = zmNeg2;
	r->mul = zmMulCrand;
	r->sqr = zmSqrCrand;
	r->inv = zmInv;
	r->div = zmDiv;
	r->deep = utilMax(4,
		zmMulCrand_deep(r->n),
		zmSqrCrand_deep(r->n),
		zmInv_deep(r->n),
		zmDiv_deep(r->n));
	// настроить заголовок
	r->hdr.keep = sizeof(qr_o) + O_OF_W(2 * r->n);
	r->hdr.p_count = 3;
	r->hdr.o_count = 0;
}

size_t zmCreateCrand_keep(size_t no)
{
	const size_t n = W_OF_O(no);
	return sizeof(qr_o) + O_OF_W(2 * n);
}

size_t zmCreateCrand_deep(size_t no)
{
	const size_t n = W_OF_O(no);
	return utilMax(4,
		zmMulCrand_deep(n),
		zmSqrCrand_deep(n),
		zmInv_deep(n),
		zmDiv_deep(n));
}

/*
*******************************************************************************
Кольцо с редукцией Барретта
*******************************************************************************
*/

static void zmMulBarr(word c[], const word a[], const word b[],
	const qr_o* r, void* stack)
{
	word* prod = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	ASSERT(zmIsIn(b, r));
	stack = prod + 2 * r->n;
	zzMul(prod, a, r->n, b, r->n, stack);
	zzRedBarr(prod, r->mod, r->n, r->params, stack);
	wwCopy(c, prod, r->n);
}

static size_t zmMulBarr_deep(size_t n)
{
	return utilMax(2,
		zzMul_deep(n, n),
		zzRedBarr_deep(n));
}

static void zmSqrBarr(word b[], const word a[], const qr_o* r, void* stack)
{
	word* prod = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	stack = prod + 2 * r->n;
	zzSqr(prod, a, r->n, stack);
	zzRedBarr(prod, r->mod, r->n, r->params, stack);
	wwCopy(b, prod, r->n);
}

static size_t zmSqrBarr_deep(size_t n)
{
	return utilMax(2,
		zzSqr_deep(n),
		zzRedBarr_deep(n));
}

void zmCreateBarr(qr_o* r, const octet mod[], size_t no, void* stack)
{
	ASSERT(memIsValid(r, sizeof(qr_o)));
	ASSERT(memIsValid(mod, no));
	ASSERT(no > 0 && mod[no - 1] > 0);
	// зафиксировать размерности
	r->n = W_OF_O(no);
	r->no = no;
	// зафиксировать модуль
	r->mod = (word*)r->descr;
	wwFrom(r->mod, mod, no);
	// подготовить единицу
	r->unity = r->mod + r->n;
	r->unity[0] = 1;
	wwSetZero(r->unity + 1, r->n - 1);
	// подготовить параметры
	r->params = r->unity + r->n;
	zzRedBarrStart(r->params, r->mod, r->n, stack);
	// настроить функции
	r->from = zmFrom;
	r->to = zmTo;
	r->add = zmAdd2;
	r->sub = zmSub2;
	r->neg = zmNeg2;
	r->mul = zmMulBarr;
	r->sqr = zmSqrBarr;
	r->inv = zmInv;
	r->div = zmDiv;
	r->deep = utilMax(4,
		zmMulBarr_deep(r->n),
		zmSqrBarr_deep(r->n),
		zmInv_deep(r->n),
		zmDiv_deep(r->n));
	// настроить заголовок
	r->hdr.keep = sizeof(qr_o) + O_OF_W(3 * r->n + 2);
	r->hdr.p_count = 3;
	r->hdr.o_count = 0;
}

size_t zmCreateBarr_keep(size_t no)
{
	const size_t n = W_OF_O(no);
	return sizeof(qr_o) + O_OF_W(3 * n + 2);
}

size_t zmCreateBarr_deep(size_t no)
{
	const size_t n = W_OF_O(no);
	return utilMax(5,
		zzRedBarrStart_deep(n),
		zmMulBarr_deep(n),
		zmSqrBarr_deep(n),
		zmInv_deep(n),
		zmDiv_deep(n));
}

/*
*******************************************************************************
Кольцо с редукцией Монтгомери

Функция zmFromMont() задает переход a -> a R (\mod mod), R = B^n.
Функция zmToMont() задает обратный переход a -> a R^{-1} (\mod mod).

\todo В функции zmInvMont() переход от a^{-1} 2^k \mod mod к
a^{-1} R^2 \mod mod реализуется последовательными удвоениями по модулю mod.
Можно ускорить расчеты, если предварительно вычислить R^2 \mod mod.
Подробнее см. [E. Savas, K. Koc. The Montgomery Modular Inverse --
Revisited. IEEE Transactions on Computers, 49(7):763–766, 2000].
*******************************************************************************
*/

static bool_t zmFromMont(word b[], const octet a[], const qr_o* r,
	void* stack)
{
	word* c = (word*)stack;
	ASSERT(zmIsOperable(r));
	stack = c + 2 * r->n;
	// a \in r?, c <- a * R
	wwFrom(c + r->n, a, r->no);
	if (!zmIsIn(c + r->n, r))
		return FALSE;
	wwSetZero(c, r->n);
	// b <- c \mod mod
	zzMod(b, c, 2 * r->n, r->mod, r->n, stack);
	return TRUE;
}

static size_t zmFromMont_deep(size_t n)
{
	return O_OF_W(2 * n) + zzMod_deep(2 * n, n);
}

static void zmToMont(octet b[], const word a[], const qr_o* r, void* stack)
{
	word* c = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	stack = c + 2 * r->n;
	// c <- a * R^{-1} \mod mod
	wwCopy(c, a, r->n);
	wwSetZero(c + r->n, r->n);
	zzRedMont(c, r->mod, r->n, *(word*)r->params, stack);
	// b <- c
	wwTo(b, r->no, c);
}

static size_t zmToMont_deep(size_t n)
{
	return O_OF_W(2 * n) + zzRedMont_deep(n);
}

static void zmMulMont(word c[], const word a[], const word b[],
	const qr_o* r, void* stack)
{
	word* prod = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	ASSERT(zmIsIn(b, r));
	stack = prod + 2 * r->n;
	zzMul(prod, a, r->n, b, r->n, stack);
	zzRedMont(prod, r->mod, r->n, *(word*)r->params, stack);
	wwCopy(c, prod, r->n);
}

static size_t zmMulMont_deep(size_t n)
{
	return utilMax(2,
		zzMul_deep(n, n),
		zzRedMont_deep(n));
}

static void zmSqrMont(word b[], const word a[], const qr_o* r, void* stack)
{
	word* prod = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	stack = prod + 2 * r->n;
	zzSqr(prod, a, r->n, stack);
	zzRedMont(prod, r->mod, r->n, *(word*)r->params, stack);
	wwCopy(b, prod, r->n);
}

static size_t zmSqrMont_deep(size_t n)
{
	return utilMax(2,
		zzSqr_deep(n),
		zzRedMont_deep(n));
}

static void zmInvMont(word b[], const word a[], const qr_o* r, void* stack)
{
	register size_t k;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	// b <- a^{-1} 2^k \mod mod
	k = zzAlmostInvMod(b, a, r->mod, r->n, stack);
	ASSERT(wwBitSize(r->mod, r->n) <= k);
	ASSERT(k <= 2 * wwBitSize(r->mod, r->n));
	// b <- a^{-1} R^2 \mod mod
	for (; k < 2 * r->n * B_PER_W; ++k)
		zzDoubleMod(b, b, r->mod, r->n);
}

static size_t zmInvMont_deep(size_t n)
{
	return zzAlmostInvMod_deep(n);
}

static void zmDivMont(word b[], const word divident[], const word a[],
	const qr_o* r, void* stack)
{
	word* c = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(divident, r));
	ASSERT(zmIsIn(a, r));
	stack = c + r->n;
	// c <- a^{(-1)} (в кольце Монтгомери)
	zmInvMont(c, a, r, stack);
	// b <- divident * c
	zmMulMont(b, divident, c, r, stack);
}

static size_t zmDivMont_deep(size_t n)
{
	return utilMax(2,
		zmInvMont_deep(n),
		zmMulMont_deep(n));
}

void zmCreateMont(qr_o* r, const octet mod[], size_t no, void* stack)
{
	ASSERT(memIsValid(r, sizeof(qr_o)));
	ASSERT(memIsValid(mod, no));
	ASSERT(no > 0 && mod[no - 1] > 0);
	ASSERT(mod[0] % 2 != 0);
	// зафиксировать размерности
	r->n = W_OF_O(no);
	r->no = no;
	// зафиксировать модуль
	r->mod = (word*)r->descr;
	wwFrom(r->mod, mod, no);
	// подготовить единицу
	r->unity = r->mod + r->n;
	wwSetZero(r->unity, r->n);
	zzSub2(r->unity, r->mod, r->n);
	zzMod(r->unity, r->unity, r->n, r->mod, r->n, stack);
	// подготовить параметры
	r->params = r->unity + r->n;
	*((word*)r->params) = wordNegInv(r->mod[0]);
	// настроить функции
	r->from = zmFromMont;
	r->to = zmToMont;
	r->add = zmAdd2;
	r->sub = zmSub2;
	r->neg = zmNeg2;
	r->mul = zmMulMont;
	r->sqr = zmSqrMont;
	r->inv = zmInvMont;
	r->div = zmDivMont;
	r->deep = utilMax(6,
		zmFromMont_deep(r->n),
		zmToMont_deep(r->n),
		zmMulMont_deep(r->n),
		zmSqrMont_deep(r->n),
		zmInvMont_deep(r->n),
		zmDivMont_deep(r->n));
	// настроить заголовок
	r->hdr.keep = sizeof(qr_o) + O_OF_W(2 * r->n + 1);
	r->hdr.p_count = 3;
	r->hdr.o_count = 0;
}

size_t zmCreateMont_keep(size_t no)
{
	const size_t n = W_OF_O(no);
	return sizeof(qr_o) + O_OF_W(2 * n + 1);
}

size_t zmCreateMont_deep(size_t no)
{
	const size_t n = W_OF_O(no);
	return utilMax(7,
		zzMod_deep(n, n),
		zmFromMont_deep(n),
		zmToMont_deep(n),
		zmMulMont_deep(n),
		zmSqrMont_deep(n),
		zmInvMont_deep(n),
		zmDivMont_deep(n));
}

/*
*******************************************************************************
Создание оптимального кольца
*******************************************************************************
*/

void zmCreate(qr_o* r, const octet mod[], size_t no, void* stack)
{
	ASSERT(memIsValid(r, sizeof(qr_o)));
	ASSERT(memIsValid(mod, no));
	ASSERT(no > 0 && mod[no - 1] > 0);
	// короткий модуль?
	if (no <= 2 * O_PER_W)
		zmCreatePlain(r, mod, no, stack);
	// подходит редукция Крэндалла?
	else if (no % O_PER_W == 0 && no >= 2 * O_PER_W &&
		!memIsZero(mod, O_PER_W) &&
		memIsRep(mod + O_PER_W, no - O_PER_W, 0xFF))
		zmCreateCrand(r, mod, no, stack);
	// подходит редукция Монтгомери?
	else if (mod[0] % 2)
		zmCreateMont(r, mod, no, stack);
	// длинный модуль?
	else if (no >= 4 * O_PER_W)
		zmCreateBarr(r, mod, no, stack);
	// средний четный модуль
	else
		zmCreatePlain(r, mod, no, stack);
}

size_t zmCreate_keep(size_t no)
{
	return utilMax(4,
		zmCreatePlain_keep(no),
		zmCreateCrand_keep(no),
		zmCreateBarr_keep(no),
		zmCreateMont_keep(no));
}

size_t zmCreate_deep(size_t no)
{
	return utilMax(4,
		zmCreatePlain_deep(no),
		zmCreateCrand_deep(no),
		zmCreateBarr_deep(no),
		zmCreateMont_deep(no));
}

/*
*******************************************************************************
Проверка описания кольца
*******************************************************************************
*/

bool_t zmIsValid(const qr_o* r)
{
	return qrIsOperable(r) &&
		wwIsValid(r->mod, r->n) &&
		r->mod[r->n - 1] != 0;
}

/*
*******************************************************************************
Кольцо Монтгомери
*******************************************************************************
*/

typedef struct
{
	word m0;			/* параметр m0 */
	size_t l;			/* размерность */
} zm_mont_params_st;

static void zmMulMont2(word c[], const word a[], const word b[],
	const qr_o* r, void* stack)
{
	register size_t k;
	const zm_mont_params_st* params;
	word* prod = (word*)stack;
	// pre
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	ASSERT(zmIsIn(b, r));
	// настроить указатели
	params = (const zm_mont_params_st*)r->params;
	stack = prod + 2 * r->n;
	// c <- a b B^{-n} \mod mod
	zzMul(prod, a, r->n, b, r->n, stack);
	zzRedMont(prod, r->mod, r->n, *(word*)r->params, stack);
	wwCopy(c, prod, r->n);
	// c <- c * B^n / 2^l \mod mod
	for (k = params->l; k < B_PER_W * r->n; ++k)
		zzDoubleMod(c, c, r->mod, r->n);
}

static size_t zmMulMont2_deep(size_t n)
{
	return utilMax(2,
		zzMul_deep(n, n),
		zzRedMont_deep(n));
}

static void zmSqrMont2(word b[], const word a[], const qr_o* r, void* stack)
{
	register size_t k;
	const zm_mont_params_st* params;
	word* prod = (word*)stack;
	// pre
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	// настроить указатели
	params = (const zm_mont_params_st*)r->params;
	stack = prod + 2 * r->n;
	// b <- a^2 B^{-n} \mod mod
	zzSqr(prod, a, r->n, stack);
	zzRedMont(prod, r->mod, r->n, *(word*)r->params, stack);
	wwCopy(b, prod, r->n);
	// b <- b * B^n / 2^l \mod mod
	for (k = params->l; k < B_PER_W * r->n; ++k)
		zzDoubleMod(b, b, r->mod, r->n);
}

static size_t zmSqrMont2_deep(size_t n)
{
	return utilMax(2,
		zzSqr_deep(n),
		zzRedMont_deep(n));
}

static void zmInvMont2(word b[], const word a[], const qr_o* r, void* stack)
{
	register size_t k;
	const zm_mont_params_st* params;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(a, r));
	params = (const zm_mont_params_st*)r->params;
	// b <- a^{-1} 2^k \mod mod
	k = zzAlmostInvMod(b, a, r->mod, r->n, stack);
	ASSERT(wwBitSize(r->mod, r->n) <= k);
	ASSERT(k <= 2 * wwBitSize(r->mod, r->n));
	// b <- a^{-1} R^2 \mod mod
	for (; k < 2 * params->l; ++k)
		zzDoubleMod(b, b, r->mod, r->n);
}

static size_t zmInvMont2_deep(size_t n)
{
	return zzAlmostInvMod_deep(n);
}

static void zmDivMont2(word b[], const word divident[], const word a[],
	const qr_o* r, void* stack)
{
	word* c = (word*)stack;
	ASSERT(zmIsOperable(r));
	ASSERT(zmIsIn(divident, r));
	ASSERT(zmIsIn(a, r));
	stack = c + r->n;
	// c <- a^{(-1)} (в кольце Монтгомери)
	zmInvMont2(c, a, r, stack);
	// b <- divident * c
	zmMulMont2(b, divident, c, r, stack);
}

static size_t zmDivMont2_deep(size_t n)
{
	return utilMax(2,
		zmInvMont2_deep(n),
		zmMulMont2_deep(n));
}

void zmMontCreate(qr_o* r, const octet mod[], size_t no, size_t l, void* stack)
{
	ASSERT(memIsValid(r, sizeof(qr_o)));
	ASSERT(memIsValid(mod, no));
	ASSERT(no > 0 && mod[no - 1] > 0);
	ASSERT(mod[0] % 2 != 0);
	// зафиксировать размерности
	r->n = W_OF_O(no);
	r->no = no;
	// зафиксировать модуль
	r->mod = (word*)r->descr;
	wwFrom(r->mod, mod, no);
	ASSERT(wwBitSize(r->mod, r->n) <= l && B_OF_W(r->n) >= l);
	// подготовить единицу: unity <- R \mod mod
	r->unity = r->mod + r->n;
	wwSetZero(r->unity, r->n);
	if (l == B_OF_W(r->n))
		zzSub2(r->unity, r->mod, r->n);
	else
		wwSetBit(r->unity, l, 1);
	zzMod(r->unity, r->unity, r->n, r->mod, r->n, stack);
	// подготовить параметры
	r->params = r->unity + r->n;
	((zm_mont_params_st*)r->params)->m0 = wordNegInv(r->mod[0]);
	((zm_mont_params_st*)r->params)->l = l;
	// настроить функции
	r->from = zmFrom;
	r->to = zmTo;
	r->add = zmAdd2;
	r->sub = zmSub2;
	r->neg = zmNeg2;
	r->mul = zmMulMont2;
	r->sqr = zmSqrMont2;
	r->inv = zmInvMont2;
	r->div = zmDivMont2;
	r->deep = utilMax(4,
		zmMulMont2_deep(r->n),
		zmSqrMont2_deep(r->n),
		zmInvMont2_deep(r->n),
		zmDivMont2_deep(r->n));
	// настроить заголовок
	r->hdr.keep = sizeof(qr_o) + O_OF_W(2 * r->n) + sizeof(zm_mont_params_st);
	r->hdr.p_count = 3;
	r->hdr.o_count = 0;
}

size_t zmMontCreate_keep(size_t no)
{
	const size_t n = W_OF_O(no);
	return sizeof(qr_o) + O_OF_W(2 * n) + sizeof(zm_mont_params_st);
}

size_t zmMontCreate_deep(size_t no)
{
	const size_t n = W_OF_O(no);
	return utilMax(5,
		zzMod_deep(n, n),
		zmMulMont_deep(n),
		zmSqrMont_deep(n),
		zmInvMont_deep(n),
		zmDivMont_deep(n));
}
