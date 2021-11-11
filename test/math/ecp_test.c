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
#include <crypto/bign_lcl.h>


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

static bool_t ecMulA2(word *c, word const *a, const ec_o *ec, word const *d, size_t m, void *stack)
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

static bool_t ecpEqJ(const word a[], const word b[], const ec_o* ec, void* stack) {
	const size_t n = ec->f->n;
    bool_t r = TRUE;
	word *za, *ta;
	word *zb, *tb;

	za = (word*)stack;
	ta = za + n;
	zb = ta + n;
	tb = zb + n;
	stack = tb + n;

    qrSqr(za, ecZ(a, n), ec->f, stack);
    qrSqr(zb, ecZ(b, n), ec->f, stack);
    qrMul(ta, zb, ecX(a), ec->f, stack);
    qrMul(tb, za, ecX(b), ec->f, stack);
    r = wwCmp(ta, tb, n) == 0;
    qrMul(za, za, ecZ(a, n), ec->f, stack);
    qrMul(zb, zb, ecZ(b, n), ec->f, stack);
    qrMul(ta, zb, ecY(a, n), ec->f, stack);
    qrMul(tb, za, ecY(b, n), ec->f, stack);
    r = (wwCmp(ta, tb, n) == 0) && r;
	return r;
}

static bool_t ecpDblAddATest(const ec_o* ec, void* stack)
{
    const size_t n = ec->f->n * 3;
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
	for (i = 0; i < 10; ++i)
	{
		ecAddA(a, a, ec->base, ec, stack);
		ecpDblAddA(actual, a, ec->base, TRUE, ec, stack);
		if (!ecpEqJ(expected, actual, ec, stack))
			return FALSE;

		ecAdd(expected, expected, base_dbl, ec, stack);
		ecpDblAddA(actual, a, ec->base, FALSE, ec, stack);
		if (!ecpEqJ(expected, actual, ec, stack))
			return FALSE;
	}
	return TRUE;
}

static bool_t ecpSmallMultTest(const ec_o* ec, void *stack)
{
	size_t const MIN_W = 2;
	size_t const MAX_W = 6;
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

    for(w = MIN_W; w <= MAX_W; ++w)
    {
        stack = (void*)(c + (na << (w - 1)));
        ecpSmallMultA(c, ec->base, w, ec, stack);

        ci = c;
        *b = 1;
        for(i = SIZE_1 << (w - 1); i--;)
        {
            if(!ecMulA(ta, ec->base, ec, b, 1, stack))
                return FALSE;
            if(0 != wwCmp(ci, ta, na))
                return FALSE;
            ci += na;
            *b += 2;
        }
    }

    for(w = MIN_W; w <= MAX_W; ++w)
    {
        stack = (void*)(c + (n << (w - 1)));
        ecpSmallMultJ(c, ec->base, w, ec, stack);

        ci = c;
        *b = 1;
        for(i = SIZE_1 << (w - 1); i--;)
        {
            ecToA(sa, ci, ec, stack);
            if(!ecMulA(ta, ec->base, ec, b, 1, stack))
                return FALSE;
            if(0 != wwCmp(sa, ta, na))
                return FALSE;
            ci += n;
            *b += 2;
        }
    }

	return TRUE;
}

extern void ecpJToH(word* c, const word a[], const ec_o* ec, void* stack);
extern void ecpAddAJJ_complete(word* c, const word a[], const word b[], const ec_o* ec, void* stack);
extern void ecpAddAJA_complete(word* c, const word a[], const word b[], const ec_o* ec, void* stack);
extern bool_t ecpHToA(word b[], const word a[], const ec_o* ec, void* stack);
extern bool_t ecpHToJ(word b[], const word a[], const ec_o* ec, void* stack);

static bool_t ecpTestComplete(const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n * 3;
	const size_t na = ec->f->n * 2;

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

	if (!ecpEqJ(actual, expected, ec, stack))
		return FALSE;

	ecpHToA(actual, a, ec, stack);
	if (wwCmp(actual, ec->base, na) != 0)
		return FALSE;

	//test affine doubling
	ecDblA(expected, ec->base, ec, stack);
	ecFromA(a, ec->base, ec, stack);
	ecpAddAJA_complete(actual, a, ec->base, ec, stack);
	ecFromA(actual, actual, ec, stack);

	if (!ecpEqJ(actual, expected, ec, stack))
		return FALSE;

	//test affine addition
	ecDblA(a, ec->base, ec, stack);
	ecAddA(expected, a, ec->base, ec, stack);
	ecpAddAJA_complete(actual, a, ec->base, ec, stack);
	ecFromA(actual, actual, ec, stack);

	if (!ecpEqJ(actual, expected, ec, stack))
		return FALSE;

	//test jacobian doubling
	ecDblA(expected, ec->base, ec, stack);
	ecFromA(a, ec->base, ec, stack);
	ecpAddAJJ_complete(actual, a, a, ec, stack);
	ecFromA(actual, actual, ec, stack);

	if (!ecpEqJ(actual, expected, ec, stack))
		return FALSE;

	//test jacobian addition
	ecDblA(a, ec->base, ec, stack);
	ecFromA(c, ec->base, ec, stack);
	ecAddA(expected, a, ec->base, ec, stack);
	ecpAddAJJ_complete(actual, a, c, ec, stack);
	ecFromA(actual, actual, ec, stack);

	if (!ecpEqJ(actual, expected, ec, stack))
		return FALSE;

	return TRUE;
}

static bool_t ecpMulATest(const ec_o* ec, void *stack)
{
	const size_t MIN_W = 2;
	const size_t MAX_W = 5;
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
		wwSetZero(d, m);
		d[0] = 0x0f;
		fb = ecpMulA(fa, /*ba*/ec->base, ec, d, m, stack);
		sb = ecMulA(sa, /*ba*/ec->base, ec, d, m, stack);
		if(fb != sb)
			return FALSE;
		if(fb && (0 != wwCmp(sa, fa, na)))
			return FALSE;
		sb = ecMulA2(sa, /*ba*/ec->base, ec, d, m, stack);
		if(fb != sb)
			return FALSE;
		if(fb && (0 != wwCmp(sa, fa, na)))
			return FALSE;
	}

	for (w = 3; ++w < 6;) {
		//протестировать особую точку для которой происходит удвоение на последнем шаге
		//особая точка существует только для кривых с нечетным (q / 2^w)
		//нечетная особая точка строится из порядка q имеет следующий вид:
		//1. бит в позиции w выставлен в 0
		//2. младшие 0 ... w - 1 бит (число k) выставляются 2^w - k
 		if (wwGetBits(ec->order, w, 1)) {
			//построить нечетную особую точку
			wwCopy(d, ec->order, ec->f->n + 1);
			k = wwGetBits(d, 0, w);
			k = (1 << w) - k;
			wwSetBits(d, 0, w + 1, k);
			//проверить нечетную особую точку
			fb = ecpMulA(fa, /*ba*/ec->base, ec, d, m, stack);
			sb = ecMulA(sa, /*ba*/ec->base, ec, d, m, stack);
			if (fb != sb)
				return FALSE;
			if (fb && (0 != wwCmp(sa, fa, na)))
				return FALSE;
			sb = ecMulA2(sa, /*ba*/ec->base, ec, d, m, stack);
			if (fb != sb)
				return FALSE;
			if (fb && (0 != wwCmp(sa, fa, na)))
				return FALSE;

			//четная особая точка
			qrSub(d, ec->order, d, ec->f);
			//проверить четную особую точку
			fb = ecpMulA(fa, /*ba*/ec->base, ec, d, m, stack);
			sb = ecMulA(sa, /*ba*/ec->base, ec, d, m, stack);
			if (fb != sb)
				return FALSE;
			if (fb && (0 != wwCmp(sa, fa, na)))
				return FALSE;
			sb = ecMulA2(sa, /*ba*/ec->base, ec, d, m, stack);
			if (fb != sb)
				return FALSE;
			if (fb && (0 != wwCmp(sa, fa, na)))
				return FALSE;
		}
	}

	{
		zzSubW(d, ec->order, m, 1);
		fb = ecpMulA(fa, /*ba*/ec->base, ec, d, m, stack);
		sb = ecMulA(sa, /*ba*/ec->base, ec, d, m, stack);
		if (fb != sb)
			return FALSE;
		if (fb && (0 != wwCmp(sa, fa, na)))
			return FALSE;
		sb = ecMulA2(sa, /*ba*/ec->base, ec, d, m, stack);
		if (fb != sb)
			return FALSE;
		if (fb && (0 != wwCmp(sa, fa, na)))
			return FALSE;
	}

    if(0)
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
						wwSetZero(d, m);
						wwSetBits(d, 0, w, ds[d0]);
						k = ks[ik];
						wwSetBits(d, k, w, ds[dk]);

						fb = ecpMulA(fa, ba, ec, d, m, stack);
						sb = ecMulA(sa, ba, ec, d, m, stack);
						if(fb != sb)
							return FALSE;
						if(fb && (0 != wwCmp(sa, fa, na)))
							return FALSE;
						sb = ecMulA2(sa, ba, ec, d, m, stack);
						if(fb != sb)
							return FALSE;
						if(fb && (0 != wwCmp(sa, fa, na)))
							return FALSE;
					}
				}
			}
		}

		ba = ec->base;
	}

	return TRUE;
}

static bool_t ecpMulATestFullGroup(const ec_o* ec, void* stack)
{
	const size_t na = ec->f->n * 2;

	bool_t fb;
	size_t m = W_OF_B(wwBitSize(ec->order, ec->f->n + 1));
	word* d = (word*)stack;
	word* exp_j = d + m;
	word* exp_a = exp_j + ec->f->n * ec->d;
	word* act_a = exp_a + na;
	stack = (void*)(act_a + na);

	{
		wwSetZero(d, m);
		fb = ecpMulA(act_a, ec->base, ec, d, m, stack);
		if (fb != FALSE)
			return FALSE;
	}

	{
		zzAddW2(d, m, 1);
		fb = ecpMulA(act_a, ec->base, ec, d, m, stack);
		wwCopy(exp_a, ec->base, na);
		if (fb == FALSE)
			return FALSE;
		if (0 != wwCmp(exp_a, act_a, na))
			return FALSE;
	}

	{
		zzAddW2(d, m, 1);
		fb = ecpMulA(act_a, ec->base, ec, d, m, stack);
		if (fb == FALSE)
			return FALSE;
		ecDblA(exp_j, ec->base, ec, stack);
		ecToA(exp_a, exp_j, ec, stack);
		if (0 != wwCmp(exp_a, act_a, na))
			return FALSE;
	}

	for (;;)
	{
		zzAddW2(d, m, 1);
		if (0 == wwCmp(d, ec->order, m))
			break;
		fb = ecpMulA(act_a, ec->base, ec, d, m, stack);
		if (fb == FALSE)
			return FALSE;
		ecAddA(exp_j, exp_j, ec->base, ec, stack);
		ecToA(exp_a, exp_j, ec, stack);
		if (0 != wwCmp(exp_a, act_a, na))
			return FALSE;
	}

	return TRUE;
}

bool_t testEcp(const ec_o* ec, void* stack, const size_t sizeOfStack, const size_t n, const size_t f_deep, const size_t ec_deep)
{
	// корректная кривая?
	ASSERT(ecpIsValid_deep(n, f_deep) <= sizeOfStack);
	if (!ecpIsValid(ec, stack))
		return FALSE;
	// корректная группа?
	ASSERT(ecpSeemsValidGroup_deep(n, f_deep) <= sizeOfStack);
	if (!ecpSeemsValidGroup(ec, stack))
		return FALSE;
	// надежная группа?
	ASSERT(ecpIsSafeGroup_deep(n) <= sizeOfStack);
	if (!ecpIsSafeGroup(ec, 40, stack))
		return FALSE;
	// базовая точка имеет порядок q?
	ASSERT(ecHasOrderA_deep(n, ec->d, ec_deep, n) <= sizeOfStack);
	//TODO: ecHasOrderA uses ecMulA and ecNegA before they are tested
	if (!ecHasOrderA(ec->base, ec, ec->order, n, stack))
		return FALSE;
	// проверить алгоритм Монтгомери инвертирования элементов поля
	if (!qrMontInvTest(ec->f, stack))
		return FALSE;
	// проверить алгоритм расчета малых кратных
	if (!ecpSmallMultTest(ec, stack))
		return FALSE;
	// проверить алгоритм удвоения и вычитания/сложения с афинной точкой
	if (!ecpDblAddATest(ec, stack))
		return FALSE;
	// проверить complete
	if (!ecpTestComplete(ec, stack)) {
		return FALSE;
	}
	return TRUE;
}

bool_t testStdCurves(const void* state, void* stack)
{
	bign_params params[1];
	ec_o* ec = (ec_o*)state;
	char oid[] = "1.2.112.0.2.0.34.101.45.3.0";
	for (; ++oid[sizeof(oid) - 2] < '4'; )
	{
		bignStdParams(params, oid);
		bignStart(ec, params);
		if (!ecpSmallMultTest(ec, stack))
			return FALSE;
		if (!ecpMulATest(ec, stack))
			return FALSE;
	}
	return TRUE;
}

bool_t testSmallCurves(const void* state, void* stack, const size_t sizeOfStack)
{
	ec_o* ec = (ec_o*)state;
	bign_params params[1];
	const char* testCurveNames[] = {
		"bign-curve8v1",
		//остальные кривые работают довольно долго
		//"bign-curve16v1",
		//"bign-curve32v1",
		//"bign-curve64v1",
		//"bign-curve128v1",
		//"bign-curve192v1"
	};

	for (int i = 0; i < sizeof(testCurveNames) / sizeof(testCurveNames[0]); ++i)
	{
		bignTestParams(params, testCurveNames[i]);
		bignStart(ec, params);
		if (!testEcp(ec, stack, sizeOfStack, ec->f->n, ec->f->deep, ec->deep))
			return FALSE;
		if (!ecpMulATestFullGroup(ec, stack))
			return FALSE;
	}

	return TRUE;
}

bool_t ecpTest()
{
	// состояние и стек
	octet state[2048];
	octet stack[30*4096];
	octet t[96];

	{
		// размерности
		const size_t n = W_OF_O(no);
		const size_t f_keep = gfpCreate_keep(no);
		const size_t f_deep = gfpCreate_deep(no);
		const size_t ec_keep = ecpCreateJ_keep(n);
		const size_t ec_deep = ecpCreateJ_deep(n, f_deep);

		// поле и эк
		qr_o* f;
		ec_o* ec;
		// хватает памяти?
		ASSERT(f_keep + ec_keep <= sizeof(state));
		ASSERT(ec_deep <= sizeof(stack));
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
		if (!ecCreateGroup(ec, t, t + 32, t + 64, no, cofactor, stack))
			return FALSE;
		// присоединить f к ec
		objAppend(ec, f, 0);

		if (!testEcp(ec, stack, sizeof(stack), n, f_deep, ec_deep))
			return FALSE;

		// проверить алгоритм скалярного умножения
		if (!ecpMulATest(ec, stack))
			return FALSE;
	}

	if(!testSmallCurves(state, stack, sizeof(stack)))
		return FALSE;

	if(!testStdCurves(state, stack))
		return FALSE;

	// все нормально
	return TRUE;
}
