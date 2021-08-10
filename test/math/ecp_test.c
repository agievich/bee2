/*
*******************************************************************************
\file ecp_test.c
\brief Tests for elliptic curves over prime fields
\project bee2/test
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2017.05.29
\version 2021.07.20
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/hex.h>
#include <bee2/core/obj.h>
#include <bee2/core/util.h>
#include <bee2/math/gfp.h>
#include <bee2/math/ecp.h>
#include <bee2/math/qr.h>
#include <bee2/math/ww.h>
#include <bee2/math/zz.h>
#include <bee2/crypto/bign.h>

/*
*******************************************************************************
Проверочная кривая
*******************************************************************************
*/

static const size_t no = 32;
static char p[] =
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43";
static char a[] =
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40";
static char b[] =
	"00000000000000000000000000000000000000000000000000000000000014B8";
static char q[] =
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D1229165911507C328526818EC4E11D";
static char xbase[] =
	"0000000000000000000000000000000000000000000000000000000000000000";
static char ybase[] =
	"B0E9804939D7C2E931D4CE052CCC6B6B692514CCADBA44940484EEA5F52D9268";
static u32 cofactor = 1;
/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

static bool_t qrMontInvTest(const qr_o* qr, void* stack)
{
	size_t m, i;
	word *c = (word *)stack;
	word *u = (c + 3 * qr->n);
	word *v = (u + 3 * qr->n);
	word *ci, *ui;
	stack = (void *)(v + qr->n);

	// u := [2, 3, 4]
	qrAdd(u, qr->unity, qr->unity, qr);
	qrAdd(u + qr->n, u, qr->unity, qr);
	qrAdd(u + 2 * qr->n, u + qr->n, qr->unity, qr);

	for(m = 0; m++ < 3;)
	{
		qrMontInv(c, u, m, qr, stack);
		ci = c;
		ui = u;
		for(i = 0; i < m; ++i)
		{
			qrMul(v, ci, ui, qr, stack);
			if(0 != qrCmp(v, qr->unity, qr))
				return FALSE;
			ci += qr->n;
			ui += qr->n;
		}

		wwCopy(c, u, qr->n * m);
		qrMontInv(c, c, m, qr, stack);
		ci = c;
		ui = u;
		for(i = 0; i < m; ++i)
		{
			qrMul(v, ci, ui, qr, stack);
			if(0 != qrCmp(v, qr->unity, qr))
				return FALSE;
			ci += qr->n;
			ui += qr->n;
		}
	}

	return TRUE;
}

static bool_t ecMulADoubleAdd(word *c, word const *a, const ec_o *ec, word const *d, size_t m, void *stack)
{
	size_t i;
	word b;
	word *q = (word*)stack;
	stack = (void*)(q + ec->d * ec->f->n);

	ecSetO(q, ec);
	for(i = m * B_PER_W; i--; )
	{
		ecDbl(q, q, ec, stack);
		b = wwGetBits(d, i, 1);
		if(b)
			ecAddA(q, q, a, ec, stack);
	}
	return ecToA(c, q, ec, stack);
}

static bool_t ecSmallMultTest(const ec_o* ec, void *stack)
{
	size_t const MIN_W = 2;
	size_t const MAX_W = 7;
	const size_t na = ec->f->n * 2;
	const size_t n = ec->f->n * ec->d;
	size_t w, i, f;

	word* bj = (word*)stack;

	word* d = bj + n;
	word* p = d + n;
	word* sa = p + n;
	word* ta = sa + na;
	word* c = ta + na;
	word* ci;
	word b[1];

	stack = (void*)(bj + n);
	ecFromA(bj, ec->base, ec, stack);

	for(;;)
	{
		for(w = MIN_W; w <= MAX_W; ++w)
		{
			stack = (void*)(c + (na << (w - 1)));

			for(f = 0; f < 2; ++f)
			{
				if(f == 0)
					ecSmallMultAdd2A(c, d, ec->base, w, ec, stack);
				else
					ecpSmallMultDivpA(c, d, ec->base, w, ec, stack);

				if(d)
				{
					ecDblA(p, ec->base, ec, stack);
					ecToA(ta, p, ec, stack);
					if(0 != wwCmp(d, ta, na))
						return FALSE;
				}

				ci = c;
				*b = 1;
				for(i = SIZE_1 << (w - 1); i--;)
				{
					//if(!ecMulA(ta, ec->base, ec, b, 1, stack))
					//	return FALSE;
					if(!ecMulADoubleAdd(ta, ec->base, ec, b, 1, stack))
						return FALSE;
					if(0 != wwCmp(ci, ta, na))
						return FALSE;
					ci += na;
					*b += 2;
				}
			}
		}

		for(w = MIN_W; w <= MAX_W; ++w)
		{
			stack = (void*)(c + (n << (w - 1)));

			for(f = 0; f < 2; ++f)
			{
				if(f == 0)
					ecSmallMultAdd2J(c, d, ec->base, w, ec, stack);
				else
					ecpSmallMultDivpJ(c, d, ec->base, w, ec, stack);

				if(d)
				{
					ecToA(sa, d, ec, stack);
					ecAdd(p, bj, bj, ec, stack);
					ecToA(ta, p, ec, stack);
					if(0 != wwCmp(sa, ta, na))
						return FALSE;
				}

				ci = c;
				*b = 1;
				for(i = SIZE_1 << (w - 1); i--;)
				{
					ecToA(sa, ci, ec, stack);
					//if(!ecMulA(ta, ec->base, ec, b, 1, stack))
					//	return FALSE;
					if(!ecMulADoubleAdd(ta, ec->base, ec, b, 1, stack))
						return FALSE;
					if(0 != wwCmp(sa, ta, na))
						return FALSE;
					ci += n;
					*b += 2;
				}
			}
		}

		if(!d) break;
		d = NULL;
	}

	return TRUE;
}

static bool_t ecMulTest(const ec_o* ec, void *stack)
{
	const size_t MIN_W = 2;
	const size_t MAX_W = 7;
	const size_t na = ec->f->n * 2;

	size_t w, k, m = ec->f->n;
	size_t d0, dk, ik;
	word* d = (word*)stack;
	word* ba = d + m + 1;
	word* sa = ba + na;
	word* fa = sa + na;
	bool_t sb, fb;
	stack = (void*)(fa + na);

	ecDblA(sa, ec->base, ec, stack);
	ecToA(ba, sa, ec, stack);

	{
		wwSetZero(d, m + 1);
		d[0] = 0x0f;
		fb = ecMulA(fa, /*ba*/ec->base, ec, d, m + 1, stack);
		sb = ecMulADoubleAdd(sa, /*ba*/ec->base, ec, d, m + 1, stack);
		if(fb != sb)
			return FALSE;
		if(fb && (0 != wwCmp(sa, fa, na)))
			return FALSE;
	}

	{
		zzSubW(d, ec->order, m + 1, 1);
		fb = ecMulA(fa, /*ba*/ec->base, ec, d, m + 1, stack);
		sb = ecMulADoubleAdd(sa, /*ba*/ec->base, ec, d, m + 1, stack);
		if (fb != sb)
			return FALSE;
		if (fb && (0 != wwCmp(sa, fa, na)))
			return FALSE;
	}

	for(;;)
	{
		// w = MIN_W .. MAX_W
		// d = d_0 + .. + d_k 2^{wk}
		for(w = MIN_W; w <= MAX_W; ++w)
		{
			const word ds[8] = {0, 1, 2, (1<<(w-1))-1, 1<<(w-1), (1<<(w-1))+1, (1<<w)-2, (1<<w)-1, };
			m = (3 * w + B_PER_W - 1) / B_PER_W;
			for(d0 = 0; d0 < 8; ++d0)
			{
				for(dk = 0; dk < 8; ++dk)
				{
					const size_t ks[9] = {w-1, w, w+1, w+w-1, w+w, w+w+1, (m * B_PER_W) - w-2, (m * B_PER_W) - w-1, (m * B_PER_W) - w};
					for(ik = 0; ik < 9; ++ik)
					{
						wwSetZero(d, m + 1);
						wwSetBits(d, 0, w, ds[d0]);
						k = ks[ik];
						wwSetBits(d, k, w, ds[dk]);

						fb = ecMulA(fa, ba, ec, d, m, stack);
						sb = ecMulADoubleAdd(sa, ba, ec, d, m, stack);
						if(fb != sb)
							return FALSE;
						if(fb && (0 != wwCmp(sa, fa, na)))
							return FALSE;
					}
				}
			}
		}

		if(ba == ec->base)
			break;
		ba = ec->base;
	}

	return TRUE;
}


//одна и та же точка в якобиевых координатах?
static bool_t ecIsSamePointJ(const word a[], const word b[], const ec_o* ec, void* stack) {
	const size_t na = ec->f->n * 2;
	const size_t n = ec->f->n * 3;
	word* aa;
	word* ba;

	if (!wwCmp(a, b, n))
		return TRUE;

	aa = (word*)stack;
	ba = aa + na;
	stack = ba + na;

	ecToA(aa, a, ec, stack);
	ecToA(ba, b, ec, stack);

	return wwCmp(aa, ba, na) == 0;
}

static bool_t ecpTestDblAddA(const ec_o* ec, void* stack)
{	const size_t n = ec->f->n * 3;

	size_t i;

	word* a = (word*)stack;
	word* base_dbl = a + n;
	word* actual = base_dbl + n;
	word* expected = actual + n;
	stack = (void*)(expected + n);

	ecDblA(base_dbl, ec->base, ec, stack);
	wwCopy(a, base_dbl, n);

	ecDbl(expected, base_dbl, ec, stack);
	ecAddA(expected, expected, ec->base, ec, stack);

	//a = [3,4,5...] * ec->base
	//expected = [5,7, 7,9, ...] * ec->base
	for (i = 0; i < 20; ++i)
	{
		ecAddA(a, a, ec->base, ec, stack);

		ecpDblAddA(actual, a, ec->base, TRUE, ec, stack);

		if (!ecIsSamePointJ(expected, actual, ec, stack))
			return FALSE;

		ecAdd(expected, expected, base_dbl, ec, stack);

		ecpDblAddA(actual, a, ec->base, FALSE, ec, stack);

		if (!ecIsSamePointJ(expected, actual, ec, stack))
			return FALSE;
	}
	return TRUE;
}

extern void ecpJToH(word* c, const word a[], const ec_o* ec, void* stack);
extern void ecpAddJJ_complete(word* c, const word a[], const word b[], const ec_o* ec, void* stack);
extern void ecpAddJA_complete(word* c, const word a[], const word b[], const ec_o* ec, void* stack);
extern bool_t ecpHToA(word b[], const word a[], const ec_o* ec, void* stack);
extern bool_t ecpHToJ(word b[], const word a[], const ec_o* ec, void* stack);

static bool_t ecpTestComplete(const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n * 3;
	const size_t na = ec->f->n * 2;

	size_t i;

	word* a = (word*)stack;
	word* b = a + n;
	word* c = b + n;
	word* actual = c + n;
	word* expected = actual + n;
	stack = (void*)(expected + n);

	ecFromA(expected, ec->base, ec, stack);

	//test conversions only
	ecpJToH(a, expected, ec, stack);
	ecpHToJ(actual, a, ec, stack);

	if (!ecIsSamePointJ(actual, expected, ec, stack))
		return FALSE;

	ecpHToA(actual, a, ec, stack);
	if (wwCmp(actual, ec->base, na) != 0)
		return FALSE;

	//test affine doubling
	ecDblA(expected, ec->base, ec, stack);
	ecFromA(a, ec->base, ec, stack);
	ecpAddJA_complete(b, a, ec->base, ec, stack);
	ecpHToJ(actual, b, ec, stack);

	if (!ecIsSamePointJ(actual, expected, ec, stack))
		return FALSE;


	//test affine addition
	ecDblA(a, ec->base, ec, stack);
	ecAddA(expected, a, ec->base, ec, stack);
	ecpAddJA_complete(b, a, ec->base, ec, stack);
	ecpHToJ(actual, b, ec, stack);

	if (!ecIsSamePointJ(actual, expected, ec, stack))
		return FALSE;


	//test jacobian doubling
	ecDblA(expected, ec->base, ec, stack);
	ecFromA(a, ec->base, ec, stack);
	ecpAddJJ_complete(b, a, a, ec, stack);
	ecpHToJ(actual, b, ec, stack);

	if (!ecIsSamePointJ(actual, expected, ec, stack))
		return FALSE;


	//test jacobian addition
	ecDblA(a, ec->base, ec, stack);
	ecFromA(c, ec->base, ec, stack);
	ecAddA(expected, a, ec->base, ec, stack);
	ecpAddJJ_complete(b, a, c, ec, stack);
	ecpHToJ(actual, b, ec, stack);

	if (!ecIsSamePointJ(actual, expected, ec, stack))
		return FALSE;
}



extern err_t bignStart(void* state, const bign_params* params);

bool_t ecpTest()
{
	// размерности
	const size_t n = W_OF_O(no);
	const size_t f_keep = gfpCreate_keep(no);
	const size_t f_deep = gfpCreate_deep(no);
	const size_t ec_keep = ecpCreateJ_keep(n);
	const size_t ec_deep = ecpCreateJ_deep(n, f_deep);
	// состояние и стек
	octet state[2048];
	octet stack[30*4096];
	octet t[96];
	// поле и эк
	qr_o* f;
	ec_o* ec;
	// хватает памяти?
	ASSERT(f_keep + ec_keep <= sizeof(state));
	ASSERT(ec_deep  <= sizeof(stack));
	// создать f = GF(p)
	hexToRev(t, p);
	f = (qr_o*)(state + ec_keep);
	if (!gfpCreate(f, t, no, stack))
		return FALSE;
	// создать ec = EC_{ab}(f)
	hexToRev(t, a), hexToRev(t + 32, b);
	ec = (ec_o*)state;
	if (!ecpCreateJ(ec, f, t, t + 32, stack))
		return FALSE;
	// создать группу точек ec
	hexToRev(t, xbase), hexToRev(t + 32, ybase), hexToRev(t + 64, q);
	if (!ecCreateGroup(ec, t, t + 32, t + 64, no, cofactor, 0, NULL, stack))
		return FALSE;
	// присоединить f к ec
	objAppend(ec, f, 0);
	// корректная кривая?
	ASSERT(ecpIsValid_deep(n, f_deep) <= sizeof(stack));
	if (!ecpIsValid(ec, stack))
		return FALSE;
	// корректная группа?
	ASSERT(ecpSeemsValidGroup_deep(n, f_deep) <= sizeof(stack));
	if (!ecpSeemsValidGroup(ec, stack))
		return FALSE;
	// надежная группа?
	ASSERT(ecpIsSafeGroup_deep(n) <= sizeof(stack));
	if (!ecpIsSafeGroup(ec, 40, stack))
		return FALSE;
	// базовая точка имеет порядок q?
	ASSERT(ecHasOrderA_deep(n, ec->d, ec_deep, n) <= sizeof(stack));
	//TODO: ecHasOrderA uses ecMulA and ecNegA before they are tested
	if (!ecHasOrderA(ec->base, ec, ec->order, n, stack))
		return FALSE;
	// проверить алгоритм Монтгомери инвертирования элементов поля
	if (!qrMontInvTest(ec->f, stack))
		return FALSE;
	// проверить алгоритм расчета малых кратных
	if (!ecSmallMultTest(ec, stack))
		return FALSE;
	// проверить алгоритм удвоения и вычитания/сложения с афинной точкой
	if (!ecpTestDblAddA(ec, stack))
		return FALSE;
	if (!ecpTestComplete(ec, stack)) {
		return FALSE;
	}
	// проверить алгоритм скалярного умножения
	if (!ecMulTest(ec, stack))
		return FALSE;


	{
		bign_params params[1];
		char oid[] = "1.2.112.0.2.0.34.101.45.3.0";
		for(; ++oid[sizeof(oid)-2] < '4'; )
		{
			bignStdParams(params, oid);
			bignStart(ec, params);
			if(!ecSmallMultTest(ec, stack))
				return FALSE;
			if(!ecMulTest(ec, stack))
				return FALSE;
		}
	}
	// все нормально
	return TRUE;
}
