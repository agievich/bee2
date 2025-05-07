/*
*******************************************************************************
\file bign.c
\brief STB 34.101.45 (bign): public parameters
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2025.05.07
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/der.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign.h"
#include "bee2/math/ecp.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "bign_lcl.h"

/*
*******************************************************************************
Стандартные параметры: приложение Б к СТБ 34.101.45
*******************************************************************************
*/

// bign-curve128v1
static const char _curve128v1_name[] = "1.2.112.0.2.0.34.101.45.3.1";

static const octet _curve128v1_p[32] = {
	0x43, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve128v1_a[32] = {
	0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve128v1_b[32] = {
	0xF1, 0x03, 0x9C, 0xD6, 0x6B, 0x7D, 0x2E, 0xB2,
	0x53, 0x92, 0x8B, 0x97, 0x69, 0x50, 0xF5, 0x4C,
	0xBE, 0xFB, 0xD8, 0xE4, 0xAB, 0x3A, 0xC1, 0xD2,
	0xED, 0xA8, 0xF3, 0x15, 0x15, 0x6C, 0xCE, 0x77,
};

static const octet _curve128v1_seed[8] = {
	0x5E, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve128v1_q[32] = {
	0x07, 0x66, 0x3D, 0x26, 0x99, 0xBF, 0x5A, 0x7E,
	0xFC, 0x4D, 0xFB, 0x0D, 0xD6, 0x8E, 0x5C, 0xD9,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve128v1_yG[32] = {
	0x93, 0x6A, 0x51, 0x04, 0x18, 0xCF, 0x29, 0x1E,
	0x52, 0xF6, 0x08, 0xC4, 0x66, 0x39, 0x91, 0x78,
	0x5D, 0x83, 0xD6, 0x51, 0xA3, 0xC9, 0xE4, 0x5C,
	0x9F, 0xD6, 0x16, 0xFB, 0x3C, 0xFC, 0xF7, 0x6B,
};

// bign-curve192v1
static const char _curve192v1_name[] = "1.2.112.0.2.0.34.101.45.3.2";

static const octet _curve192v1_p[48] = {
	0xC3, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve192v1_a[48] = {
	0xC0, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve192v1_b[48] = {
	0x64, 0xBF, 0x73, 0x68, 0x23, 0xFC, 0xA7, 0xBC,
	0x7C, 0xBD, 0xCE, 0xF3, 0xF0, 0xE2, 0xBD, 0x14,
	0x3A, 0x2E, 0x71, 0xE9, 0xF9, 0x6A, 0x21, 0xA6,
	0x96, 0xB1, 0xFB, 0x0F, 0xBB, 0x48, 0x27, 0x71,
	0xD2, 0x34, 0x5D, 0x65, 0xAB, 0x5A, 0x07, 0x33,
	0x20, 0xEF, 0x9C, 0x95, 0xE1, 0xDF, 0x75, 0x3C,
};

static const octet _curve192v1_seed[8] = {
	0x23, 0xAF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve192v1_q[48] = {
	0xB7, 0xA7, 0x0C, 0xF3, 0x3F, 0xDC, 0xB7, 0x3D,
	0x0A, 0xFF, 0xA4, 0xA6, 0xE7, 0xDA, 0x46, 0x80,
	0xBB, 0x7B, 0xAF, 0x73, 0x03, 0xC4, 0xCC, 0x6C,
	0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve192v1_yG[48] =
{
	0x51, 0xC4, 0x33, 0xF7, 0x31, 0xCB, 0x5E, 0xEA,
	0xF9, 0x42, 0x2A, 0x6B, 0x27, 0x3E, 0x40, 0x84,
	0x55, 0xD3, 0xB1, 0x66, 0x9E, 0xE7, 0x49, 0x05,
	0xA0, 0xFF, 0x86, 0xDC, 0x11, 0x9A, 0x72, 0x3A,
	0x89, 0xBF, 0x2D, 0x43, 0x7E, 0x11, 0x30, 0x63,
	0x9E, 0x9E, 0x2E, 0xA8, 0x24, 0x82, 0x43, 0x5D,
};

// bign-curve256v1
static const char _curve256v1_name[] = "1.2.112.0.2.0.34.101.45.3.3";

static const octet _curve256v1_p[64] = {
	0xC7, 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve256v1_a[64] = {
	0xC4, 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve256v1_b[64] = {
	0x90, 0x9C, 0x13, 0xD6, 0x98, 0x69, 0x34, 0x09,
	0x7A, 0xA2, 0x49, 0x3A, 0x27, 0x22, 0x86, 0xEA,
	0x43, 0xA2, 0xAC, 0x87, 0x8C, 0x00, 0x33, 0x29,
	0x95, 0x5E, 0x24, 0xC4, 0xB5, 0xDC, 0x11, 0x27,
	0x88, 0xB0, 0xAD, 0xDA, 0xE3, 0x13, 0xCE, 0x17,
	0x51, 0x25, 0x5D, 0xDD, 0xEE, 0xA9, 0xC6, 0x5B,
	0x89, 0x58, 0xFD, 0x60, 0x6A, 0x5D, 0x8C, 0xD8,
	0x43, 0x8C, 0x3B, 0x93, 0x44, 0x59, 0xB4, 0x6C,
};

static const octet _curve256v1_seed[8] = {
	0xAE, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve256v1_q[64] = {
	0xF1, 0x8E, 0x06, 0x0D, 0x49, 0xAD, 0xFF, 0xDC,
	0x32, 0xDF, 0x56, 0x95, 0xE5, 0xCA, 0x1B, 0x36,
	0xF4, 0x13, 0x21, 0x2E, 0xB0, 0xEB, 0x6B, 0xF2,
	0x4E, 0x00, 0x98, 0x01, 0x2C, 0x09, 0xC0, 0xB2,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve256v1_yG[64] =
{
	0xBD, 0xED, 0xEF, 0xCE, 0x6F, 0xAE, 0x92, 0xB7,
	0x04, 0x0D, 0x4C, 0xC9, 0xB9, 0x83, 0xAA, 0x67,
	0x61, 0x22, 0xE8, 0xEE, 0x95, 0x73, 0x77, 0xFF,
	0xD2, 0x6F, 0xFA, 0x0E, 0xE2, 0xDD, 0x73, 0x69,
	0xDA, 0xCA, 0xCC, 0x00, 0x1B, 0xF8, 0xED, 0xD2,
	0xE2, 0xBC, 0x61, 0xB3, 0xB3, 0x41, 0xAB, 0xB0,
	0xAB, 0x8F, 0xD1, 0xA0, 0xF7, 0xE6, 0x82, 0xB1,
	0x81, 0x76, 0x03, 0xE4, 0x7A, 0xFF, 0x26, 0xA8,
};

/*
*******************************************************************************
Загрузка стандартных параметров
*******************************************************************************
*/

err_t bignParamsStd(bign_params* params, const char* name)
{
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	memSetZero(params, sizeof(bign_params));
	if (strEq(name, _curve128v1_name))
	{
		params->l = 128;
		memCopy(params->p, _curve128v1_p, 32);
		memCopy(params->a, _curve128v1_a, 32);
		memCopy(params->seed, _curve128v1_seed, 8);
		memCopy(params->b, _curve128v1_b, 32);
		memCopy(params->q, _curve128v1_q, 32);
		memCopy(params->yG, _curve128v1_yG, 32);
		return ERR_OK;
	}
	if (strEq(name, _curve192v1_name))
	{
		params->l = 192;
		memCopy(params->p, _curve192v1_p, 48);
		memCopy(params->a, _curve192v1_a, 48);
		memCopy(params->seed, _curve192v1_seed, 8);
		memCopy(params->b, _curve192v1_b, 48);
		memCopy(params->q, _curve192v1_q, 48);
		memCopy(params->yG, _curve192v1_yG, 48);
		return ERR_OK;
	}
	if (strEq(name, _curve256v1_name))
	{
		params->l = 256;
		memCopy(params->p, _curve256v1_p, 64);
		memCopy(params->a, _curve256v1_a, 64);
		memCopy(params->seed, _curve256v1_seed, 8);
		memCopy(params->b, _curve256v1_b, 64);
		memCopy(params->q, _curve256v1_q, 64);
		memCopy(params->yG, _curve256v1_yG, 64);
		return ERR_OK;
	}
	return ERR_FILE_NOT_FOUND;
}

/*
*******************************************************************************
Проверка параметров

-#	l \in {128, 192, 256} (bignIsOperable)
-#	2^{l - 1} < p, q < 2^l (bignIsOperable)
-#	p \equiv 3 \mod 4 (bignIsOperable)
-#	0 < a (bignIsOperable)
-#	0 < b (bignIsOperable, zzJacobi)
-#	p -- простое (ecpIsValid)
-#	q -- простое (ecpIsSafeGroup)
-#	q != p (ecpIsSafeGroup)
-#	p^m \not\equiv 1 (mod q), m = 1, 2,..., 50 (ecpIsSafeGroup)
-#	a, b < p (ecpCreateJ in bignStart)
-#	b \equiv B (mod p) (bignValParams)
-#	4a^3 + 27b^2 \not\equiv 0 (\mod p) (ecpIsValid)
-#	(b / p) = 1 (zzJacobi)
-#	G = (0, b^{(p + 1) /4}) (bignValParams)
-#	qG = O (ecpHasOrder)
*******************************************************************************
*/

static void bignSeedInc(octet seed[8])
{
	register word carry;
	size_t pos;
	ASSERT(memIsValid(seed, 8));
	for (carry = 1, pos = 0; pos < 8; ++pos)
		carry += seed[pos], seed[pos] = (octet)carry, carry >>= 8;
	carry = 0;
}

static size_t bignParamsVal_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return beltHash_keep() + O_OF_B(512) +
		utilMax(6,
			beltHash_keep(),
			ecpIsValid_deep(n, f_deep),
			ecpIsSafeGroup_deep(n),
			ecpIsOnA_deep(n, f_deep),
			qrPower_deep(n, n, f_deep),
			ecHasOrderA_deep(n, ec_d, ec_deep, n));
}

err_t bignParamsVal(const bign_params* params)
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	octet* hash_state;		/* [beltHash_keep] состояние хэширования */
	octet* seed;			/* [8] копия seed */
	word* B;				/* [W_OF_B(512)] переменная B */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (!bignIsOperable(params))
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignParamsVal_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// раскладка состояния
	hash_state = objEnd(ec, octet);
	seed = hash_state + beltHash_keep();
	B = (word*)seed;
	stack = B + W_OF_B(512);
	// belt-hash(p..)
	beltHashStart(hash_state);
	beltHashStepH(params->p, no, hash_state);
	// belt-hash(..a..)
	beltHashStepH(params->a, no, hash_state);
	memCopy(stack, hash_state, beltHash_keep());
	// belt-hash(..seed)
	beltHashStepH(params->seed, 8, hash_state);
	// belt-hash(..seed + 1)
	memCopy(seed, params->seed, 8);
	bignSeedInc(seed);
	beltHashStepH(seed, 8, stack);
	// B <- belt-hash(p || a || seed) || belt-hash(p || a || seed + 1)
	beltHashStepG((octet*)B, hash_state);
	beltHashStepG((octet*)B + 32, stack);
	wwFrom(B, B, 64);
	// B <- B \mod p
	zzMod(B, B, W_OF_O(64), ec->f->mod, n, stack);
	wwTo(B, 64, B);
	// проверить условия алгоритма 6.1.4
	if (qrFrom(B, (octet*)B, ec->f, stack) &&
		wwEq(B, ec->B, n) &&
		!wwIsZero(ec->B, n) &&
		ecpIsValid(ec, stack) &&
		ecpIsSafeGroup(ec, 50, stack) &&
		zzJacobi(ec->B, n, ec->f->mod, n, stack) == 1)
	{
		// B <- b^{(p + 1) / 4} = \sqrt{b} mod p
		wwCopy(B, ec->f->mod, n);
		zzAddW2(B, n, 1);
		wwShLo(B, n, 2);
		qrPower(B, ec->B, B, n, ec->f, stack);
		// оставшиеся условия
		if (!wwEq(B, ecY(ec->base, n), n) ||
			!ecHasOrderA(ec->base, ec, ec->order, n, stack))
			code = ERR_BAD_PARAMS;
	}
	else
		code = ERR_BAD_PARAMS;
	// завершение
	blobClose(state);
	return code;
}

/*
*******************************************************************************
Генерация параметров
*******************************************************************************
*/

static bool_t ecpDetIsZero(const word a[], const word b[], const word p[],
	size_t n, void* stack)
{
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// t1 <- 4 A^3
	zzSqrMod(t1, a, p, n, stack);
	zzMulMod(t1, t1, a, p, n, stack);
	zzMulWMod(t1, t1, 4, p, n, stack);
	// t2 <- 27 B^2
	zzSqrMod(t2, b, p, n, stack);
	zzMulWMod(t2, t2, 27, p, n, stack);
	// t1 <- t1 + t2 [4 A^3 + 27 B^2 -- дискриминант]
	zzAddMod(t1, t1, t2, p, n);
	// t1 == 0?
	return wwIsZero(t1, n);
}

static size_t ecpDetIsZero_deep(size_t n)
{
	return O_OF_W(2 * n) +
		utilMax(3,
			zzSqrMod_deep(n),
			zzMulMod_deep(n),
			zzMulWMod_deep(n)
		);
}

static bool_t ecpMOVIsMet(const word q[], const word p[], size_t n,
	size_t threshold, void* stack)
{
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// t1, t2 <- p mod q
	ASSERT(threshold > 0);
	zzMod(t1, p, n, q, n, stack);
	wwCopy(t2, t1, n);
	// p mod q == 1?
	if (wwCmpW(t2, n, 1) == 0)
		return FALSE;
	while (--threshold)
	{
		// p^i mod q == 1?
		zzMulMod(t2, t2, t1, q, n, stack);
		if (wwCmpW(t2, n, 1) == 0)
			return FALSE;
	}
	return TRUE;
}

static size_t ecpMOVIsMet_deep(size_t n)
{
	return O_OF_W(2 * n) +
		utilMax(2,
			zzMod_deep(n, n),
			zzMulMod_deep(n)
		);
}

static size_t bignParamsGen_deep(size_t n)
{
	return O_OF_W(4 * n) + 8 + beltHash_keep() + 
		utilMax(5,
			beltHash_keep(),
			priIsPrime_deep(n),
			ecpDetIsZero_deep(n),
			ecpMOVIsMet_deep(n),
			zzPowerMod_deep(n, n)
		);
}

err_t bignParamsGen(bign_params* params, bign_pgen_calc_q calc_q,
	bign_pgen_on_seed on_seed, void* state)
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* st;
	word* p;				/* [n] */
	word* a;				/* [n] */
	word* b;				/* [W_OF_B(512)] B / [n] b */
	word* q;				/* [n] */
	word* yG;				/* [n] */
	octet* seed;			/* [8] */
	octet* hash_state;		/* [beltHash_keep] */
	void* stack;
	// проверить входные данные
	if (!memIsValid(params, sizeof(bign_params)) || 
		!calc_q)
		return ERR_BAD_INPUT;
	// проверить уровень стойкости
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// размерности
	no = O_OF_B(2 * params->l);
	n = W_OF_B(2 * params->l);
	// проверить params:
	// - p -- 2l-битовое число?
	// - p mod 4 == 3?
	// - 0 < a < p?
	// - неиспользуемые октеты p и a обнулены?
	if (params->p[0] % 4 != 3 || params->p[no - 1] < 128 ||
		memIsZero(params->a, no) ||
		memCmpRev(params->a, params->p, no) >= 0 ||
		!memIsZero(params->p + no, sizeof(params->p) - no) ||
		!memIsZero(params->a + no, sizeof(params->a) - no))
		return ERR_BAD_PARAMS;
	// создать состояние
	st = blobCreate(bignParamsGen_deep(n));
	if (st == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	p = (word*)st;
	a = p + n;
	b = a + n;
	q = yG = b + n;
	seed = (octet*)(q + n);
	hash_state = seed + 8;
	stack = hash_state + beltHash_keep();
	ASSERT((octet*)b + 64 <= seed);
	// загрузить и проверить p
	wwFrom(p, params->p, no);
	ASSERT(wwBitSize(p, n) == params->l * 2);
	ASSERT(wwGetBits(p, 0, 2) == 3);
	if (!priIsPrime(p, n, stack))
	{
		blobClose(st);
		return ERR_BAD_PARAMS;
	}
	// загрузить a
	wwFrom(a, params->a, no);
	ASSERT(!wwIsZero(a, n));
	ASSERT(wwCmp(a, p, n) < 0);
	// загрузить seed
	memCopy(seed, params->seed, 8);
	// цикл генерации
	while (1)
	{
		// обработать seed
		memCopy(params->seed, seed, 8);
		if (on_seed)
		{
			code = on_seed(params, state);
			ERR_CALL_HANDLE(code, blobClose(st));
		}
		// belt-hash(p || a ||..)
		beltHashStart(hash_state);
		beltHashStepH(params->p, no, hash_state);
		beltHashStepH(params->a, no, hash_state);
		memCopy(stack, hash_state, beltHash_keep());
		// belt-hash(..seed)
		beltHashStepH(params->seed, 8, hash_state);
		// belt-hash(..seed + 1)
		bignSeedInc(seed);
		beltHashStepH(seed, 8, stack);
		// B <- belt-hash(p || a || seed) || belt-hash(p || a || seed + 1)
		beltHashStepG((octet*)b, hash_state);
		beltHashStepG((octet*)b + 32, stack);
		// b <- B \mod p
		wwFrom(b, b, 64);
		zzMod(b, b, W_OF_O(64), p, n, stack);
		// проверить b
		if (ecpDetIsZero(a, b, p, n, stack) ||
			zzJacobi(b, n, p, n, stack) != 1)
			continue;
		// сохранить b
		wwTo(params->b, no, b);
		memSetZero(params->b + no, sizeof(params->b) - no);
		// вычиcлить q
		code = calc_q(params, state);
		if (code == ERR_NO_RESULT)
			continue;
		ERR_CALL_HANDLE(code, blobClose(st));
		// загрузить и проверить q
		wwFrom(q, params->q, no);
		if (wwBitSize(q, n) == params->l * 2 &&
			!wwEq(q, p, n) &&
			priIsPrime(q, n, stack) &&
			ecpMOVIsMet(q, p, n, 50, stack))
			break;
	}
	// сохранить q
	memSetZero(params->q + no, sizeof(params->q) - no);
	// вычислить yG = b^{(p + 1) / 4} mod p
	wwCopy(a, p, n);
	zzAddW2(a, n, 1);
	ASSERT(!wwIsZero(a, n));
	wwShLo(a, n, 2);
	zzPowerMod(yG, b, n, a, n, p, stack);
	// сохранить yG
	wwTo(params->yG, no, yG);
	memSetZero(params->yG + no, sizeof(params->yG) - no);
	// завершение
	blobClose(st);
	return code;
}

/*
*******************************************************************************
DER-кодирование

  SEQ ECParameters
	SIZE(1) -- version
	SEQ FieldID
	  OID(bign-primefield)
	  UINT -- parameters (p)
	SEQ Curve
	  OCT(SIZE(32|48|64)) -- a
	  OCT(SIZE(32|48|64)) -- b
	  BIT(SIZE(64)) -- seed
	OCT(SIZE(32|48|64)) -- base (yG)
	UINT -- order (q)
	UINT(1) OPTIONAL -- cofactor

*******************************************************************************
*/

static const char oid_bign_primefield[] = "1.2.112.0.2.0.34.101.45.4.1";

#define derEncStep(step, ptr, count)\
do {\
	size_t _t = step;\
	ASSERT(_t != SIZE_MAX);\
	ptr = ptr ? ptr + _t : 0;\
	count += _t;\
} while(0)\

#define derDecStep(step, ptr, count)\
do {\
	size_t _t = step;\
	if (_t == SIZE_MAX)\
		return SIZE_MAX;\
	ptr += _t, count -= _t;\
} while(0)\

#define derDecStep2(step, ptr, count)\
do {\
	size_t t = step;\
	if (t != SIZE_MAX)\
		ptr += t, count -= t;\
} while(0)\

static size_t bignParamsEnc_internal(octet der[], const bign_params* params)
{
	der_anchor_t ParamSeq[1];
	der_anchor_t FieldSeq[1];
	der_anchor_t CurveSeq[1];
	size_t count = 0;
	// начать кодирование...
	derEncStep(derSEQEncStart(ParamSeq, der, count), der, count);
	 // ...version...
	 derEncStep(derSIZEEnc(der, 1), der, count);
	 // ...FieldID...
	 derEncStep(derSEQEncStart(FieldSeq, der, count), der, count);
	  derEncStep(derOIDEnc(der, oid_bign_primefield), der, count);
	  derEncStep(derUINTEnc(der, params->p, params->l / 4), der, count);
	 derEncStep(derSEQEncStop(der, count, FieldSeq), der, count);
	 // ...Curve...
	 derEncStep(derSEQEncStart(CurveSeq, der, count), der, count);
	  derEncStep(derOCTEnc(der, params->a, params->l / 4), der, count);
	  derEncStep(derOCTEnc(der, params->b, params->l / 4), der, count);
	  derEncStep(derBITEnc(der, params->seed, 64), der, count);
	 derEncStep(derSEQEncStop(der, count, CurveSeq), der, count);
	 // ...base...
	 derEncStep(derOCTEnc(der, params->yG, params->l / 4), der, count);
	 // ...order...
	 derEncStep(derUINTEnc(der, params->q, params->l / 4), der, count);
	 // ...завершить кодирование
	derEncStep(derSEQEncStop(der, count, ParamSeq), der, count);
	// возвратить длину DER-кода
	return count;
}

static size_t bignParamsDec_internal(bign_params* params, const octet der[],
	size_t count)
{
	der_anchor_t ParamSeq[1];
	der_anchor_t FieldSeq[1];
	der_anchor_t CurveSeq[1];
	const octet* ptr = der;
	size_t len = 32;
	// pre
	ASSERT(memIsValid(params, sizeof(bign_params)));
	ASSERT(memIsValid(der, count));
	// начать декодирование...
	memSetZero(params, sizeof(bign_params));
	derDecStep(derSEQDecStart(ParamSeq, ptr, count), ptr, count);
	 // ...version...
	 derDecStep(derSIZEDec2(ptr, count, 1), ptr, count);
	 // ...FieldID...
	 derDecStep(derSEQDecStart(FieldSeq, ptr, count), ptr, count);
	  derDecStep(derOIDDec2(ptr, count, oid_bign_primefield), ptr, count);
	  if (derUINTDec(0, &len, ptr, count) == SIZE_MAX ||
		len != 32 && len != 48 && len != 64)
		return SIZE_MAX;
	  params->l = len * 4;
	  derDecStep(derUINTDec(params->p, &len, ptr, count), ptr, count);
	 derDecStep(derSEQDecStop(ptr, FieldSeq), ptr, count);
	 // ...Curve...
	 derDecStep(derSEQDecStart(CurveSeq, ptr, count), ptr, count);
	  derDecStep(derOCTDec2(params->a, ptr, count,  len), ptr, count);
	  derDecStep(derOCTDec2(params->b, ptr, count,  len), ptr, count);
	  derDecStep(derBITDec2(params->seed, ptr, count, 64), ptr, count);
	 derDecStep(derSEQDecStop(ptr, CurveSeq), ptr, count);
	 // ...base...
	 derDecStep(derOCTDec2(params->yG, ptr, count, len), ptr, count);
	 // ...order...
	 derDecStep(derUINTDec2(params->q, ptr, count, len), ptr, count);
	 // ...cofactor(optional)...
	 derDecStep2(derSIZEDec2(ptr, count, 1), ptr, count);
	 // ...завершить декодирование
	derDecStep(derSEQDecStop(ptr, ParamSeq), ptr, count);
	// возвратить точную длину DER-кода
	return ptr - der;
}

err_t bignParamsEnc(octet der[], size_t* count, const bign_params* params)
{
	size_t len;
	if (!memIsValid(params, sizeof(bign_params)) ||
		!memIsValid(count, O_PER_S) ||
		!memIsNullOrValid(der, *count))
		return ERR_BAD_INPUT;
	if (!bignIsOperable(params))
		return ERR_BAD_PARAMS;
	len = bignParamsEnc_internal(0, params);
	if (len == SIZE_MAX)
		return ERR_BAD_PARAMS;
	if (der)
	{
		if (*count < len)
			return ERR_OUTOFMEMORY;
		len = bignParamsEnc_internal(der, params);
		ASSERT(len != SIZE_MAX);
	}
	*count = len;
	return ERR_OK;
}

err_t bignParamsDec(bign_params* params, const octet der[], size_t count)
{
	size_t len;
	if (!memIsValid(params, sizeof(bign_params)) ||
		!memIsValid(der, count))
		return ERR_BAD_INPUT;
	len = bignParamsDec_internal(params, der, count);
	if (len == SIZE_MAX || len != count)
		return ERR_BAD_FORMAT;
	return ERR_OK;
}
