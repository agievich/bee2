/*
*******************************************************************************
\file bign.c
\brief STB 34.101.45 (bign): digital signature and key transport algorithms
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.27
\version 2015.11.03
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/der.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign.h"
#include "crypto/bign_lcl.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ecp.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

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

static const octet _curve128v1_seed[32] = {
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

static const octet _curve192v1_seed[48] = {
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

static const octet _curve256v1_seed[64] = {
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

err_t bignStdParams(bign_params* params, const char* name)
{
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
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
Создание / закрытие эллиптической кривой
*******************************************************************************
*/

err_t bignStart(void* state, const bign_params* params)
{
	// размерности
	size_t no, n;
	size_t f_keep;
	size_t ec_keep;
	// состояние
	qr_o* f;			/* поле */
	ec_o* ec;			/* кривая */
	void* stack;	/* вложенный стек */
	// pre
	ASSERT(memIsValid(params, sizeof(bign_params)));
	ASSERT(params->l == 128 || params->l == 192  || params->l == 256);
	ASSERT(memIsValid(state, bignStart_keep(params->l, 0)));
	// определить размерности
	no = O_OF_B(2 * params->l);
	n = W_OF_B(2 * params->l);
	f_keep = gfpCreate_keep(no);
	ec_keep = ecpCreateJ_keep(n);
	// создать поле и выполнить минимальные проверки p
	f = (qr_o*)((octet*)state + ec_keep);
	stack = (octet*)f + f_keep;
	if (!gfpCreate(f, params->p, no, stack) ||
		wwBitSize(f->mod, n) != params->l * 2 ||
		wwGetBits(f->mod, 0, 2) != 3)
		return ERR_BAD_PARAMS;
	// создать кривую и группу, выполнить минимальную проверку order
	ec = (ec_o*)state;
	if (!ecpCreateJ(ec, f, params->a, params->b, stack) ||
		!ecCreateGroup(ec, 0, params->yG, params->q, no, 1, stack) ||
		wwBitSize(ec->order, n) != params->l * 2 ||
		zzIsEven(ec->order, n))
		return ERR_BAD_PARAMS;
	// присоединить f к ec
	objAppend(ec, f, 0);
	// все нормально
	return ERR_OK;
}

size_t bignStart_keep(size_t l, bign_deep_i deep)
{
	// размерности
	size_t no = O_OF_B(2 * l);
	size_t n = W_OF_B(2 * l);
	size_t f_keep = gfpCreate_keep(no);
	size_t f_deep = gfpCreate_deep(no);
	size_t ec_d = 3;
	size_t ec_keep = ecpCreateJ_keep(n);
	size_t ec_deep = ecpCreateJ_deep(n, f_deep);
	// расчет
	return f_keep + ec_keep +
		utilMax(3,
			ec_deep,
			ecCreateGroup_deep(f_deep),
			deep ? deep(n, f_deep, ec_d, ec_deep) : 0);
}

/*
*******************************************************************************
Проверка параметров

-#	l \in {128, 192, 256} (bignCreateEc)
-#	2^{l - 1} < p, q < 2^l (bignCreateEc)
-#	p -- простое (ecpIsValid)
-#	q -- простое (ecpIsSafeGroup)
-#	p \equiv 3 \mod 4 (bignCreateEc)
-#	q != p (ecpIsSafeGroup)
-#	p^m \not\equiv 1 (mod q), m = 1, 2,..., 50 (ecpIsSafeGroup)
-#	a, b < p (ecpCreateJ in bignCreateEc)
-#	0 != b (bignValParams)
-#	b \equiv B (mod p) (bignValParams)
-#	4a^3 + 27b^2 \not\equiv 0 (\mod p) (ecpIsValid)
-#	(b / p) = 1 (zzJacobi)
-#	G = (0, b^{(p + 1) /4}) (bignValParams)
-#	qG = O (ecpHasOrder)
*******************************************************************************
*/

static size_t bignValParams_deep(size_t n, size_t f_deep, size_t ec_d,
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

err_t bignValParams(const bign_params* params)
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	octet* hash_state;		/* [beltHash_keep] состояние хэширования */
	octet* hash_data;		/* [8] данные хэширования */
	word* B;				/* [W_OF_B(512)] переменная B */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignValParams_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// раскладка состояния
	hash_state = objEnd(ec, octet);
	hash_data = hash_state + beltHash_keep();
	B = (word*)hash_data;
	stack = hash_data + O_OF_B(512);
	// belt-hash(p..)
	beltHashStart(hash_state);
	beltHashStepH(params->p, no, hash_state);
	// belt-hash(..a..)
	beltHashStepH(params->a, no, hash_state);
	memCopy(stack, hash_state, beltHash_keep());
	// belt-hash(..seed)
	memCopy(hash_data, params->seed, 8);
	beltHashStepH(hash_data, 8, hash_state);
	// belt-hash(..seed + 1)
	wwFrom(B, hash_data, 8);
	zzAddW2(B, W_OF_O(8), 1);
	wwTo(hash_data, 8, B);
	beltHashStepH(hash_data, 8, stack);
	// B <- belt-hash(p || a || seed) || belt-hash(p || a || seed + 1)
	beltHashStepG(hash_data, hash_state);
	beltHashStepG(hash_data + 32, stack);
	wwFrom(B, hash_data, 64);
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
Идентификатор объекта
*******************************************************************************
*/

err_t bignOidToDER(octet oid_der[], size_t* oid_len, const char* oid)
{
	size_t len;
	if (!strIsValid(oid) || 
		!memIsValid(oid_len, sizeof(size_t)) ||
		!memIsNullOrValid(oid_der, *oid_len))
		return ERR_BAD_INPUT;
	len = oidToDER(0, oid);
	if (len == SIZE_MAX)
		return ERR_BAD_OID;
	if (oid_der)
	{
		if (*oid_len < len)
			return ERR_NOT_ENOUGH_MEMORY;
		oidToDER(oid_der, oid);
	}
	*oid_len = len;
	return ERR_OK;
}

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

static size_t bignGenKeypair_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(n + 2 * n) +
		ecMulA_deep(n, ec_d, ec_deep, n);
}

err_t bignGenKeypair(octet privkey[], octet pubkey[],
	const bign_params* params, gen_i rng, void* rng_state)
{
	err_t code;
	size_t no, n;
	// состояние
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2n] открытый ключ */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignGenKeypair_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(privkey, no) ||
		!memIsValid(pubkey, 2 * no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	Q = d + n;
	stack = Q + 2 * n;
	// d <-R {1,2,..., q - 1}
	if (!zzRandNZMod(d, ec->f->mod, n, rng, rng_state))
	{
		blobClose(state);
		return ERR_BAD_RNG;
	}
	// Q <- d G
	if (ecMulA(Q, ec->base, ec, d, n, stack))
	{
		// выгрузить ключи
		wwTo(privkey, no, d);
		qrTo(pubkey, ecX(Q), ec->f, stack);
		qrTo(pubkey + ec->f->no, ecY(Q, n), ec->f, stack);
	}
	else
		code = ERR_BAD_PARAMS;
	// завершение
	blobClose(state);
	return code;
}

static size_t bignValPubkey_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(2 * n) +
		ecpIsOnA_deep(n, f_deep);
}

err_t bignValPubkey(const bign_params* params, const octet pubkey[])
{
	err_t code;
	size_t no, n;
	// состояние
	void* state;
	ec_o* ec;			/* описание эллиптической кривой */
	word* Q;			/* [2n] открытый ключ */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignValPubkey_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(pubkey, 2 * no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	Q = objEnd(ec, word);
	stack = Q + 2 * n;
	// загрузить pt
	if (!qrFrom(ecX(Q), pubkey, ec->f, stack) ||
		!qrFrom(ecY(Q, n), pubkey + no, ec->f, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// Q \in ec?
	code = ecpIsOnA(Q, ec, stack) ? ERR_OK : ERR_BAD_PUBKEY;
	// завершение
	blobClose(state);
	return code;
}

static size_t bignCalcPubkey_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(n + 2 * n) +
		ecMulA_deep(n, ec_d, ec_deep, n);
}

err_t bignCalcPubkey(octet pubkey[], const bign_params* params,
	const octet privkey[])
{
	err_t code;
	size_t no, n;
	// состояние
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2n] открытый ключ */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignCalcPubkey_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(privkey, no) ||
		!memIsValid(pubkey, 2 * no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	Q = d + n;
	stack = Q + 2 * n;
	// загрузить d
	wwFrom(d, privkey, no);
	if (wwIsZero(d, n) || wwCmp(d, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// Q <- d G
	if (ecMulA(Q, ec->base, ec, d, n, stack))
	{
		// выгрузить открытый ключ
		qrTo(pubkey, ecX(Q), ec->f, stack);
		qrTo(pubkey + no, ecY(Q, n), ec->f, stack);
	}
	else
		code = ERR_BAD_PARAMS;
	// завершение
	blobClose(state);
	return code;
}

static size_t bignDH_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(n + 2 * n) +
		utilMax(2,
			ecpIsOnA_deep(n, f_deep),
			ecMulA_deep(n, ec_d, ec_deep, n));
}

err_t bignDH(octet key[], const bign_params* params, const octet privkey[],
	const octet pubkey[], size_t key_len)
{
	err_t code;
	size_t no, n;
	// состояние
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2n] открытый ключ */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignDH_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить длину key
	if (key_len > 2 * no)
	{
		blobClose(state);
		return ERR_BAD_SHAREKEY;
	}
	// проверить входные указатели
	if (!memIsValid(privkey, no) ||
		!memIsValid(pubkey, 2 * no) ||
		!memIsValid(key, key_len))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	Q = d + n;
	stack = Q + 2 * n;
	// загрузить d
	wwFrom(d, privkey, no);
	if (wwIsZero(d, n) || wwCmp(d, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// загрузить Q
	if (!qrFrom(ecX(Q), pubkey, ec->f, stack) ||
		!qrFrom(ecY(Q, n), pubkey + no, ec->f, stack) ||
		!ecpIsOnA(Q, ec, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// Q <- d Q
	if (ecMulA(Q, Q, ec, d, n, stack))
	{
		// выгрузить общий ключ
		qrTo((octet*)Q, ecX(Q), ec->f, stack);
		if (key_len > no)
			qrTo((octet*)Q + no, ecY(Q, n), ec->f, stack);
		memCopy(key, Q, key_len);
	}
	else
		code = ERR_BAD_PARAMS;
	// завершение
	blobClose(state);
	return code;
}

/*
*******************************************************************************
Выработка ЭЦП
*******************************************************************************
*/

static size_t bignSign_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(4 * n) +
		utilMax(4,
			beltHash_keep(),
			ecMulA_deep(n, ec_d, ec_deep, n),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n));
}

err_t bignSign(octet sig[], const bign_params* params, const octet oid_der[],
	size_t oid_len, const octet hash[], const octet privkey[], gen_i rng, 
	void* rng_state)
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;			
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ */
	word* R;				/* [2n] точка R */
	word* s0;				/* [n/2] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignSign_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(hash, no) ||
		!memIsValid(privkey, no) ||
		!memIsValid(sig, no + no / 2))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = s1 = objEnd(ec, word);
	k = d + n;
	R = k + n;
	s0 = R + n + n / 2;
	stack = (octet*)(R + 2 * n);
	// загрузить d
	wwFrom(d, privkey, no);
	if (wwIsZero(d, n) || wwCmp(d, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// сгенерировать k с помощью rng
	if (!zzRandNZMod(k, ec->order, n, rng, rng_state))
	{
		blobClose(state);
		return ERR_BAD_RNG;
	}
	// R <- k G
	if (!ecMulA(R, ec->base, ec, k, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 <- belt-hash(oid || R || H)
	beltHashStart(stack);
	beltHashStepH(oid_der, oid_len, stack);
	beltHashStepH(R, no, stack);
	beltHashStepH(hash, no, stack);
	beltHashStepG2(sig, no / 2, stack);
	wwFrom(s0, sig, no / 2);
	// R <- (s0 + 2^l) d
	zzMul(R, s0, n / 2, d, n, stack);
	R[n + n / 2] = zzAdd(R + n / 2, R + n / 2, d, n);
	// s1 <- R mod q
	zzMod(s1, R, n + n / 2 + 1, ec->order, n, stack);
	// s1 <- (k - s1 - H) mod q
	zzSubMod(s1, k, s1, ec->order, n);
	wwFrom(k, hash, no);
	zzSubMod(s1, s1, k, ec->order, n);
	// выгрузить s1
	wwTo(sig + no / 2, no, s1);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

static size_t bignSign2_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(4 * n) + beltHash_keep() +
		utilMax(5,
			beltHash_keep(),
			beltKWP_keep(),
			ecMulA_deep(n, ec_d, ec_deep, n),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n));
}

err_t bignSign2(octet sig[], const bign_params* params, const octet oid_der[],
	size_t oid_len, const octet hash[], const octet privkey[], const void* t, 
	size_t t_len)
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ */
	word* R;				/* [2n] точка R */
	word* s0;				/* [n/2] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* hash_state;		/* [beltHash_keep] состояние хэширования */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// проверить t
	if (!memIsNullOrValid(t, t_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignSign2_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(hash, no) ||
		!memIsValid(privkey, no) ||
		!memIsValid(sig, no + no / 2))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = s1 = objEnd(ec, word);
	k = d + n;
	R = k + n;
	s0 = R + n + n / 2;
	hash_state = (octet*)(R + 2 * n);
	stack = hash_state + beltHash_keep();
	// загрузить d
	wwFrom(d, privkey, no);
	if (wwIsZero(d, n) || wwCmp(d, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// хэшировать oid
	beltHashStart(hash_state);
	beltHashStepH(oid_der, oid_len, hash_state);
	// сгенерировать k по алгоритму 6.3.3
	{
		// theta <- belt-hash(oid || d || t)
		memCopy(stack, hash_state, beltHash_keep());
		beltHashStepH(privkey, no, stack);
		if (t != 0)
			beltHashStepH(t, t_len, stack);
		beltHashStepG(stack, stack);
		// инициализировать beltKWP ключом theta
		beltKWPStart(stack, stack, 32);
		// k <- H
		memCopy(k, hash, no);
		// k <- beltKWP(k, theta) пока k \notin {1,..., q - 1}
		while (1)
		{
			beltKWPStepE(k, no, stack);
			wwFrom(k, k, no);
			if (!wwIsZero(k, n) && wwCmp(k, ec->order, n) < 0)
				break;
			wwTo(k, no, k);
		}
	}
	// R <- k G
	if (!ecMulA(R, ec->base, ec, k, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 <- belt-hash(oid || R || H)
	beltHashStepH(R, no, hash_state);
	beltHashStepH(hash, no, hash_state);
	beltHashStepG2(sig, no / 2, hash_state);
	wwFrom(s0, sig, no / 2);
	// R <- (s0 + 2^l) d
	zzMul(R, s0, n / 2, d, n, stack);
	R[n + n / 2] = zzAdd(R + n / 2, R + n / 2, d, n);
	// s1 <- R mod q
	zzMod(s1, R, n + n / 2 + 1, ec->order, n, stack);
	// s1 <- (k - s1 - H) mod q
	zzSubMod(s1, k, s1, ec->order, n);
	wwFrom(k, hash, no);
	zzSubMod(s1, s1, k, ec->order, n);
	// выгрузить s1
	wwTo(sig + no / 2, no, s1);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Проверка ЭЦП
*******************************************************************************
*/

static size_t bignVerify_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(4 * n) +
		utilMax(2,
			beltHash_keep(),
			ecAddMulA_deep(n, ec_d, ec_deep, 2, n, n / 2 + 1));
}

err_t bignVerify(const bign_params* params, const octet oid_der[],
	size_t oid_len, const octet hash[], const octet sig[], const octet pubkey[])
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;			/* описание эллиптической кривой */	
	word* Q;			/* [2n] открытый ключ */
	word* R;			/* [2n] точка R */
	word* H;			/* [n] хэш-значение */
	word* s0;			/* [n / 2 + 1] первая часть подписи */
	word* s1;			/* [n] вторая часть подписи */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignVerify_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(hash, no) ||
		!memIsValid(sig, no + no / 2) ||
		!memIsValid(pubkey, 2 * no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	Q = R = objEnd(ec, word);
	H = s0 = Q + 2 * n;
	s1 = H + n;
	stack = (octet*)(s1 + n);
	// загрузить Q
	if (!qrFrom(ecX(Q), pubkey, ec->f, stack) ||
		!qrFrom(ecY(Q, n), pubkey + no, ec->f, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// загрузить и проверить s1
	wwFrom(s1, sig + no / 2, O_OF_W(n));
	if (wwCmp(s1, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	// s1 <- (s1 + H) mod q
	wwFrom(H, hash, no);
	if (wwCmp(H, ec->order, n) >= 0)
	{
		zzSub2(H, ec->order, n);
		// 2^{l - 1} < q < 2^l, H < 2^l => H - q < q
		ASSERT(wwCmp(H, ec->order, n) < 0);
	}
	zzAddMod(s1, s1, H, ec->order, n);
	// загрузить s0
	wwFrom(s0, sig, no / 2);
	s0[n / 2] = 1;
	// R <- s1 G + (s0 + 2^l) Q
	if (!ecAddMulA(R, ec, stack, 2, ec->base, s1, n, Q, s0, n / 2 + 1))
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 == belt-hash(oid || R || H)?
	beltHashStart(stack);
	beltHashStepH(oid_der, oid_len, stack);
	beltHashStepH(R, no, stack);
	beltHashStepH(hash, no, stack);
	code = beltHashStepV2(sig, no / 2, stack) ? ERR_OK : ERR_BAD_SIG;
	// завершение
	blobClose(state);
	return code;
}

/*
*******************************************************************************
Создание токена
*******************************************************************************
*/

static size_t bignKeyWrap_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(3 * n) + 32 +
		utilMax(2,
			ecMulA_deep(n, ec_d, ec_deep, n),
			beltKWP_keep());
}

err_t bignKeyWrap(octet token[], const bign_params* params, const octet key[],
	size_t len, const octet header[16], const octet pubkey[],
	gen_i rng, void* rng_state)
{
	err_t code;
	size_t no, n;
	// состояние
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* k;				/* [n] одноразовый личный ключ */
	word* R;				/* [2n] точка R */
	octet* theta;			/* [32] ключ защиты */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// проверить header и key
	if (len < 16 ||
		!memIsValid(key, len) ||
		!memIsNullOrValid(header, 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignKeyWrap_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(pubkey, 2 * no) ||
		!memIsValid(token, 16 + no + len))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	k = objEnd(ec, word);
	R = k + n;
	theta = (octet*)(R + 2 * n);
	stack = theta + 32;
	// сгенерировать k
	if (!zzRandNZMod(k, ec->order, n, rng, rng_state))
	{
		blobClose(state);
		return ERR_BAD_RNG;
	}
	// R <- k Q
	if (!qrFrom(ecX(R), pubkey, ec->f, stack) ||
		!qrFrom(ecY(R, n), pubkey + no, ec->f, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	if (!ecMulA(R, R, ec, k, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// theta <- <R>_{256}
	qrTo(theta, ecX(R), ec->f, stack);
	// R <- k G
	if (!ecMulA(R, ec->base, ec, k, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// сформировать блок для шифрования
	// (буферы key, header и token могут пересекаться)
	if (header)
		memCopy(R + n, header, 16);
	else
		memSetZero(R + n, 16);
	memMove(token + no, key, len);
	memCopy(token + no + len, R + n, 16);
	// зашифровать
	beltKWPStart(stack, theta, 32);
	beltKWPStepE(token + no, len + 16, stack);
	// доопределить токен
	memCopy(token, R, no);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Разбор токена
*******************************************************************************
*/

static size_t bignKeyUnwrap_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return MAX2(O_OF_W(5 * n), 32 + 16) +
		utilMax(3,
			beltKWP_keep(),
			qrPower_deep(n, n, f_deep),
			ecMulA_deep(n, ec_d, ec_deep, n));
}

err_t bignKeyUnwrap(octet key[], const bign_params* params, const octet token[], 
	size_t len, const octet header[16], const octet privkey[])
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* R;				/* [2n] точка R */
	word* t1;				/* [n] вспомогательное число */
	word* t2;				/* [n] вспомогательное число */
	octet* theta;			/* [32] ключ защиты */
	octet* header2;			/* [16] заголовок2 */
	void* stack;			/* граница стека */
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить token и header
	if (!memIsValid(token, len) ||
		!memIsNullOrValid(header, 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignKeyUnwrap_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить длину токена
	if (len < 32 + no)
	{
		blobClose(state);
		return ERR_BAD_KEYTOKEN;
	}
	// проверить входные указатели
	if (!memIsValid(privkey, no) ||
		!memIsValid(key, len - 16 - no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	R = d + n;
	t1 = R + 2 * n;
	t2 = t1 + n;
	theta = (octet*)d;
	header2 = theta + 32;
	if (5 * no >= 48)
		stack = t2 + n;
	else
		stack = header2 + 16;
	// загрузить d
	wwFrom(d, privkey, no);
	if (wwIsZero(d, n) || wwCmp(d, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// xR <- x
	if (!qrFrom(R, token, ec->f, stack))
	{
		blobClose(state);
		return ERR_BAD_KEYTOKEN;
	}
	// t1 <- x^3 + a x + b
	qrSqr(t1, R, ec->f, stack);
	zmAdd(t1, t1, ec->A, ec->f);
	qrMul(t1, t1, R, ec->f, stack);
	zmAdd(t1, t1, ec->B, ec->f);
	// yR <- t1^{(p + 1) / 4}
	wwCopy(R + n, ec->f->mod, n);
	zzAddW2(R + n, n, 1);
	wwShLo(R + n, n, 2);
	qrPower(R + n, t1, R + n, n, ec->f, stack);
	// t2 <- yR^2
	qrSqr(t2, R + n, ec->f, stack);
	// (xR, yR) на кривой? t1 == t2?
	if (!wwEq(t1, t2, n))
	{
		blobClose(state);
		return ERR_BAD_KEYTOKEN;
	}
	// R <- d R
	if (!ecMulA(R, R, ec, d, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// theta <- <R>_{256}
	qrTo(theta, ecX(R), ec->f, stack);
	// сформировать данные для расшифрования
	memCopy(key, token + no, len - no - 16);
	memCopy(header2, token + len - 16, 16);
	// расшифровать
	beltKWPStart(stack, theta, 32);
	beltKWPStepD2(key, header2, len - no, stack);
	// проверить целостность
	if (header && !memEq(header, header2, 16) ||
		header == 0 && !memIsZero(header2, 16))
	{
		memSetZero(key, len - no - 16);
		code = ERR_BAD_KEYTOKEN;
	}
	// завершение
	blobClose(state);
	return code;
}

/*
*******************************************************************************
Извлечение ключей идентификационной ЭЦП
*******************************************************************************
*/

static size_t bignIdExtract_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(4 * n) +
		utilMax(2,
			beltHash_keep(),
			ecAddMulA_deep(n, ec_d, ec_deep, 2, n, n / 2 + 1));
}

err_t bignIdExtract(octet id_privkey[], octet id_pubkey[], 
	const bign_params* params, const octet oid_der[], size_t oid_len,
	const octet id_hash[], const octet sig[], octet pubkey[])
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;			/* описание эллиптической кривой */
	word* Q;			/* [2n] открытый ключ */
	word* R;			/* [2n] точка R */
	word* H;			/* [n] хэш-значение */
	word* s0;			/* [n / 2 + 1] первая часть подписи */
	word* s1;			/* [n] вторая часть подписи */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignIdExtract_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(id_hash, no) ||
		!memIsValid(sig, no + no / 2) ||
		!memIsValid(pubkey, 2 * no) ||
		!memIsValid(id_privkey, no) ||
		!memIsValid(id_pubkey, 2 * no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	Q = R = objEnd(ec, word);
	H = s0 = Q + 2 * n;
	s1 = H + n;
	stack = (octet*)(s1 + n);
	// загрузить Q
	if (!qrFrom(ecX(Q), pubkey, ec->f, stack) ||
		!qrFrom(ecY(Q, n), pubkey + no, ec->f, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// загрузить и проверить s1
	wwFrom(s1, sig + no / 2, no);
	if (wwCmp(s1, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	// s1 <- (s1 + H) mod q
	wwFrom(H, id_hash, no);
	if (wwCmp(H, ec->order, n) >= 0)
	{
		zzSub2(H, ec->order, n);
		// 2^{l - 1} < q < 2^l, H < 2^l => H - q < q
		ASSERT(wwCmp(H, ec->order, n) < 0);
	}
	zzAddMod(s1, s1, H, ec->order, n);
	// загрузить s0
	wwFrom(s0, sig, no);
	s0[n / 2] = 1;
	// R <- s1 G + (s0 + 2^l) Q
	if (!ecAddMulA(R, ec, stack, 2, ec->base, s1, n, Q, s0, n / 2 + 1))
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 == belt-hash(oid || R || H)?
	beltHashStart(stack);
	beltHashStepH(oid_der, oid_len, stack);
	beltHashStepH(R, no, stack);
	beltHashStepH(id_hash, no, stack);
	if (beltHashStepV2(sig, no / 2, stack))
	{
		wwTo(id_privkey, no, s1);
		memCopy(id_pubkey, R, no);
		qrTo(id_pubkey + no, ecY(R, n), ec->f, stack);
	}
	else
		code = ERR_BAD_SIG;
	// завершение
	blobClose(state);
	return code;
}

/*
*******************************************************************************
Выработка идентификационной ЭЦП
*******************************************************************************
*/

static size_t bignIdSign_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(4 * n) +
		utilMax(4,
			beltHash_keep(),
			ecMulA_deep(n, ec_d, ec_deep, n),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n));
}

err_t bignIdSign(octet id_sig[], const bign_params* params, 
	const octet oid_der[], size_t oid_len, const octet id_hash[], 
	const octet hash[], const octet id_privkey[], gen_i rng, void* rng_state)
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* e;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ */
	word* V;				/* [2n] точка V */
	word* s0;				/* [n/2] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignIdSign_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(id_hash, no) ||
		!memIsValid(hash, no) ||
		!memIsValid(id_privkey, no) ||
		!memIsValid(id_sig, no + no / 2))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	e = s1 = objEnd(ec, word);
	k = e + n;
	V = k + n;
	s0 = V + n + n / 2;
	stack = (octet*)(V + 2 * n);
	// загрузить e
	wwFrom(e, id_privkey, no);
	if (wwCmp(e, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// сгенерировать k с помощью rng
	if (!zzRandNZMod(k, ec->order, n, rng, rng_state))
	{
		blobClose(state);
		return ERR_BAD_RNG;
	}
	// V <- k G
	if (!ecMulA(V, ec->base, ec, k, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)V, ecX(V), ec->f, stack);
	// s0 <- belt-hash(oid || V || H0 || H)
	beltHashStart(stack);
	beltHashStepH(oid_der, oid_len, stack);
	beltHashStepH(V, no, stack);
	beltHashStepH(id_hash, no, stack);
	beltHashStepH(hash, no, stack);
	beltHashStepG2(id_sig, no / 2, stack);
	wwFrom(s0, id_sig, no / 2);
	// V <- (s0 + 2^l) e
	zzMul(V, s0, n / 2, e, n, stack);
	V[n + n / 2] = zzAdd(V + n / 2, V + n / 2, e, n);
	// s1 <- V mod q
	zzMod(s1, V, n + n / 2 + 1, ec->order, n, stack);
	// s1 <- (k - s1 - H) mod q
	zzSubMod(s1, k, s1, ec->order, n);
	wwFrom(k, hash, no);
	zzSubMod(s1, s1, k, ec->order, n);
	// выгрузить s1
	wwTo(id_sig + no / 2, no, s1);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

static size_t bignIdSign2_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(4 * n) + beltHash_keep() +
		utilMax(5,
			beltHash_keep(),
			beltKWP_keep(),
			ecMulA_deep(n, ec_d, ec_deep, n),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n));
}

err_t bignIdSign2(octet id_sig[], const bign_params* params, 
	const octet oid_der[], size_t oid_len, const octet id_hash[], 
	const octet hash[], const octet id_privkey[], const void* t, size_t t_len)
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* e;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ */
	word* V;				/* [2n] точка V */
	word* s0;				/* [n/2] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* hash_state;		/* [beltHash_keep] состояние хэширования */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// проверить t
	if (!memIsNullOrValid(t, t_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignIdSign2_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(id_hash, no) ||
		!memIsValid(hash, no) ||
		!memIsValid(id_privkey, no) ||
		!memIsValid(id_sig, no + no / 2))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	e = s1 = objEnd(ec, word);
	k = e + n;
	V = k + n;
	s0 = V + n + n / 2;
	hash_state = (octet*)(V + 2 * n);
	stack = hash_state + beltHash_keep();
	// загрузить e
	wwFrom(e, id_privkey, no);
	if (wwCmp(e, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// хэшировать oid
	beltHashStart(hash_state);
	beltHashStepH(oid_der, oid_len, hash_state);
	// сгенерировать k по алгоритму 6.3.3
	{
		// theta <- belt-hash(oid || e || t)
		memCopy(stack, hash_state, beltHash_keep());
		beltHashStepH(id_privkey, no, stack);
		if (t != 0)
			beltHashStepH(t, t_len, stack);
		beltHashStepG(stack, stack);
		// инициализировать beltKWP ключом theta
		beltKWPStart(stack, stack, 32);
		// k <- H
		memCopy(k, hash, no);
		// k <- beltKWP(k, theta) пока k \notin {1,..., q - 1}
		while (1)
		{
			beltKWPStepE(k, no, stack);
			wwFrom(k, k, no);
			if (!wwIsZero(k, n) && wwCmp(k, ec->order, n) < 0)
				break;
			wwTo(k, no, k);
		}
	}
	// V <- k G
	if (!ecMulA(V, ec->base, ec, k, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)V, ecX(V), ec->f, stack);
	// s0 <- belt-hash(oid || V || H0 || H)
	beltHashStepH(V, no, hash_state);
	beltHashStepH(id_hash, no, hash_state);
	beltHashStepH(hash, no, hash_state);
	beltHashStepG2(id_sig, no / 2, hash_state);
	wwFrom(s0, id_sig, no / 2);
	// V <- (s0 + 2^l) e
	zzMul(V, s0, n / 2, e, n, stack);
	V[n + n / 2] = zzAdd(V + n / 2, V + n / 2, e, n);
	// s1 <- V mod q
	zzMod(s1, V, n + n / 2 + 1, ec->order, n, stack);
	// s1 <- (k - s1 - H) mod q
	zzSubMod(s1, k, s1, ec->order, n);
	wwFrom(k, hash, no);
	zzSubMod(s1, s1, k, ec->order, n);
	// выгрузить s1
	wwTo(id_sig + no / 2, no, s1);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Проверка идентификационной ЭЦП
*******************************************************************************
*/

static size_t bignIdVerify_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(7 * n + 2) + beltHash_keep() +
		utilMax(5,
			beltHash_keep(),
			ecpIsOnA_deep(n, f_deep),
			zzMul_deep(n / 2, n / 2),
			zzMod_deep(n + 1, n),
			ecAddMulA_deep(n, ec_d, ec_deep, 3, n, n / 2 + 1, n));
}

err_t bignIdVerify(const bign_params* params, const octet oid_der[], 
	size_t oid_len, const octet* id_hash, const octet* hash, 
	const octet id_sig[], const octet id_pubkey[], const octet pubkey[])
{
	err_t code;
	size_t no, n;
	// состояние (буферы R и V совпадают)
	void* state;
	ec_o* ec;			/* описание эллиптической кривой */	
	word* R;			/* [2n] открытый ключ R */
	word* Q;			/* [2n] открытый ключ Q */
	word* V;			/* [2n] точка V (V == R) */
	word* s0;			/* [n / 2 + 1] первая часть подписи */
	word* s1;			/* [n] вторая часть подписи */
	word* t;			/* [n / 2] переменная t */
	word* t1;			/* [n + 1] произведение (s0 + 2^l)(t + 2^l) */
	octet* hash_state;	/* [beltHash_keep] состояние хэширования */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignIdVerify_deep));
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(id_hash, no) ||
		!memIsValid(hash, no) ||
		!memIsValid(id_sig, no + no / 2) ||
		!memIsValid(id_pubkey, 2 * no) ||
		!memIsValid(pubkey, 2 * no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	R = V = objEnd(ec, word);
	Q = R + 2 * n;
	s0 = Q + 2 * n;
	s1 = s0 + n / 2 + 1;
	t = s1 + n;
	t1 = t + n / 2;
	hash_state = (octet*)(t1 + n + 1);
	stack = hash_state + beltHash_keep();
	// загрузить R
	if (!qrFrom(ecX(R), id_pubkey, ec->f, stack) ||
		!qrFrom(ecY(R, n), id_pubkey + no, ec->f, stack) ||
		!ecpIsOnA(R, ec, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// загрузить Q
	if (!qrFrom(ecX(Q), pubkey, ec->f, stack) ||
		!qrFrom(ecY(Q, n), pubkey + no, ec->f, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// загрузить и проверить s1
	wwFrom(s1, id_sig + no / 2, no);
	if (wwCmp(s1, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	// s1 <- (s1 + H) mod q
	wwFrom(t, hash, no);
	if (wwCmp(t, ec->order, n) >= 0)
	{
		zzSub2(t, ec->order, n);
		// 2^{l - 1} < q < 2^l, H < 2^l => H - q < q
		ASSERT(wwCmp(t, ec->order, n) < 0);
	}
	zzAddMod(s1, s1, t, ec->order, n);
	// загрузить s0
	wwFrom(s0, id_sig, no / 2);
	s0[n / 2] = 1;
	// belt-hash(oid...)
	beltHashStart(hash_state);
	beltHashStepH(oid_der, oid_len, hash_state);
	// t <- belt-hash(oid || R || H0)
	memCopy(stack, hash_state, beltHash_keep());
	beltHashStepH(id_pubkey, no, stack);
	beltHashStepH(id_hash, no, stack);
	beltHashStepG2((octet*)t, no / 2, stack);
	wwFrom(t, t, no / 2);
	// t1 <- -(t + 2^l)(s0 + 2^l) mod q
	zzMul(t1, t, n / 2, s0, n / 2, stack);
	t1[n] = zzAdd2(t1 + n / 2, t, n / 2);
	t1[n] += zzAdd2(t1 + n / 2, s0, n / 2);
	++t1[n];
	zzMod(t1, t1, n + 1, ec->order, n, stack);
	zzNegMod(t1, t1, ec->order, n);
	// V <- s1 G + (s0 + 2^l) R + t Q
	if (!ecAddMulA(V, ec, stack,
		3, ec->base, s1, n, R, s0, n / 2 + 1, Q, t1, n))
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	qrTo((octet*)V, ecX(V), ec->f, stack);
	// s0 == belt-hash(oid || V || H0 || H)?
	beltHashStepH(V, no, hash_state);
	beltHashStepH(id_hash, no, hash_state);
	beltHashStepH(hash, no, hash_state);
	code = beltHashStepV2(id_sig, no / 2, hash_state) ? ERR_OK : ERR_BAD_SIG;
	// завершение
	blobClose(state);
	return code;
}
