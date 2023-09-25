/*
*******************************************************************************
\file bign96.c
\brief Experimental Bign level 96 signatures
\project bee2 [cryptographic library]
\created 2021.01.20
\version 2023.09.22
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/der.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/str.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign.h"
#include "bee2/crypto/bign96.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ecp.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Стандартные параметры
*******************************************************************************
*/

// bign-curve96v1
static const char _curve96v1_name[] = "1.2.112.0.2.0.34.101.45.3.0";

static const octet _curve96v1_p[24] = {
	0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve96v1_a[24] = {
	0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve96v1_b[24] = {
	0x83, 0x4C, 0x34, 0x64, 0x4C, 0xE8, 0xDD, 0x6A,
	0x7A, 0x73, 0x01, 0x89, 0x88, 0x8E, 0x18, 0x87,
	0xA8, 0x98, 0x23, 0xFD, 0x25, 0xB9, 0x99, 0x31,
};

static const octet _curve96v1_seed[8] = {
	0xC6, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve96v1_q[24] = {
	0xAD, 0x11, 0x64, 0xFD, 0xBE, 0xEC, 0x0B, 0x91,
	0x37, 0xD3, 0x3A, 0x65, 0xFE, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve96v1_yG[24] = {
	0xEC, 0xCC, 0x48, 0xF6, 0xEB, 0x7F, 0x21, 0xE0,
	0x0C, 0x93, 0xDA, 0x03, 0xB2, 0x1B, 0xF9, 0xE6,
	0x17, 0xC3, 0x68, 0xC1, 0x4B, 0x96, 0x38, 0x81,
};

/*
*******************************************************************************
belt-32block

Алгоритм belt-32block определен в СТБ 34.101.31-2020. В Bign96 счетчик
числа тактов round не сбрасывается при последовательных обращениях
к belt-32block, а продолжает инкрементироваться.

\remark На основе bee2/crypto/belt/belt_fmt.с.
*******************************************************************************
*/

static void belt32BlockEncr(octet block[24], const u32 key[8], u32* round)
{
	u32* t = (u32*)block;
	u32From(t, block, 24);
	// round #1
	beltBlockEncr3(t + 2, t + 3, t + 4, t + 5, key);
	t[2] ^= (*round)++, t[0] ^= t[2], t[1] ^= t[3];
	// round #2
	beltBlockEncr3(t + 4, t + 5, t + 0, t + 1, key);
	t[4] ^= (*round)++, t[2] ^= t[4], t[3] ^= t[5];
	// round #3
	beltBlockEncr3(t + 0, t + 1, t + 2, t + 3, key);
	t[0] ^= (*round)++, t[4] ^= t[0], t[5] ^= t[1];
	// возврат
	u32To(block, 24, t);
}

/*
*******************************************************************************
Загрузка стандартных параметров
*******************************************************************************
*/

err_t bign96ParamsStd(bign_params* params, const char* name)
{
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (strEq(name, _curve96v1_name))
	{
		params->l = 96;
		memCopy(params->p, _curve96v1_p, 24);
		memCopy(params->a, _curve96v1_a, 24);
		memCopy(params->seed, _curve96v1_seed, 8);
		memCopy(params->b, _curve96v1_b, 24);
		memCopy(params->q, _curve96v1_q, 24);
		memCopy(params->yG, _curve96v1_yG, 24);
		return ERR_OK;
	}
	return ERR_FILE_NOT_FOUND;
}

/*
*******************************************************************************
Создание / закрытие эллиптической кривой
*******************************************************************************
*/

typedef size_t(*bign96_deep_i)(
	size_t n,				/*!< [in] число слов для хранения элемента поля */
	size_t f_deep,			/*!< [in] глубина стека базового поля */
	size_t ec_d,			/*!< [in] число проективных координат */
	size_t ec_deep			/*!< [in] глубина стека эллиптической кривой */
);

size_t bign96Start_keep(bign96_deep_i deep)
{
	// размерности
	size_t n = W_OF_B(192);
	size_t f_keep = gfpCreate_keep(24);
	size_t f_deep = gfpCreate_deep(24);
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

err_t bign96Start(void* state, const bign_params* params)
{
	// размерности
	size_t n;
	size_t f_keep;
	size_t ec_keep;
	// состояние
	qr_o* f;		/* поле */
	ec_o* ec;		/* кривая */
	void* stack;	/* вложенный стек */
	// pre
	ASSERT(memIsValid(params, sizeof(bign_params)));
	ASSERT(params->l == 96);
	ASSERT(memIsValid(state, bign96Start_keep(0)));
	// определить размерности
	n = W_OF_B(192);
	f_keep = gfpCreate_keep(24);
	ec_keep = ecpCreateJ_keep(n);
	// создать поле и выполнить минимальные проверки p
	f = (qr_o*)((octet*)state + ec_keep);
	stack = (octet*)f + f_keep;
	if (!gfpCreate(f, params->p, 24, stack) ||
		wwBitSize(f->mod, n) != 192 ||
		wwGetBits(f->mod, 0, 2) != 3)
		return ERR_BAD_PARAMS;
	// создать кривую и группу, выполнить минимальную проверку order
	ec = (ec_o*)state;
	if (!ecpCreateJ(ec, f, params->a, params->b, stack) ||
		!ecCreateGroup(ec, 0, params->yG, params->q, 24, 1, stack) ||
		wwBitSize(ec->order, n) != params->l * 2 ||
		zzIsEven(ec->order, n))
		return ERR_BAD_PARAMS;
	// присоединить f к ec
	objAppend(ec, f, 0);
	// все нормально
	return ERR_OK;
}

/*
*******************************************************************************
Проверка параметров

-#	l = 96 (bign96ParamsVal)
-#	2^{l - 1} < p, q < 2^l (bign96Start)
-#	p -- простое (ecpIsValid)
-#	q -- простое (ecpIsSafeGroup)
-#	p \equiv 3 \mod 4 (bign96Start)
-#	q != p (ecpIsSafeGroup)
-#	p^m \not\equiv 1 (mod q), m = 1, 2,..., 50 (ecpIsSafeGroup)
-#	a, b < p (ecpCreateJ in bign96Start)
-#	0 != b (bign96ParamsVal)
-#	b \equiv B (mod p) (bign96ParamsVal)
-#	4a^3 + 27b^2 \not\equiv 0 (\mod p) (ecpIsValid)
-#	(b / p) = 1 (zzJacobi)
-#	G = (0, b^{(p + 1) /4}) (bign96ParamsVal)
-#	qG = O (ecpHasOrder)
*******************************************************************************
*/

static size_t bign96ParamsVal_deep(size_t n, size_t f_deep, size_t ec_d,
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

err_t bign96ParamsVal(const bign_params* params)
{
	err_t code;
	size_t n;
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
	if (params->l != 96)
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bign96Start_keep(bign96ParamsVal_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bign96Start(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	n = ec->f->n;
	// раскладка состояния
	hash_state = objEnd(ec, octet);
	hash_data = hash_state + beltHash_keep();
	B = (word*)hash_data;
	stack = hash_data + O_OF_B(512);
	// belt-hash(p..)
	beltHashStart(hash_state);
	beltHashStepH(params->p, 24, hash_state);
	// belt-hash(..a..)
	beltHashStepH(params->a, 24, hash_state);
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
Управление ключами
*******************************************************************************
*/

static size_t bign96KeypairGen_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(n + 2 * n) +
		ecMulA_deep(n, ec_d, ec_deep, n);
}

err_t bign96KeypairGen(octet privkey[24], octet pubkey[48],
	const bign_params* params, gen_i rng, void* rng_state)
{
	err_t code;
	size_t n;
	// состояние
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2n] открытый ключ */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 96)
		return ERR_BAD_PARAMS;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// создать состояние
	state = blobCreate(bign96Start_keep(bign96KeypairGen_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bign96Start(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(privkey, 24) || !memIsValid(pubkey, 48))
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
		wwTo(privkey, 24, d);
		qrTo(pubkey, ecX(Q), ec->f, stack);
		qrTo(pubkey + 24, ecY(Q, n), ec->f, stack);
	}
	else
		code = ERR_BAD_PARAMS;
	// завершение
	blobClose(state);
	return code;
}

static size_t bign96KeypairVal_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(n + 2 * n) +
		ecMulA_deep(n, ec_d, ec_deep, n);
}

err_t bign96KeypairVal(const bign_params* params, const octet privkey[24],
	const octet pubkey[48])
{
	err_t code;
	size_t n;
	// состояние
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2n] открытый ключ */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 96)
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bign96Start_keep(bign96KeypairVal_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bign96Start(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(privkey, 24) || !memIsValid(pubkey, 48))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	Q = d + n;
	stack = Q + 2 * n;
	// d <- privkey
	wwFrom(d, privkey, 24);
	// 0 < d < q?
	wwFrom(Q, params->q, 24);
	if (wwIsZero(d, n) || wwCmp(d, Q, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// Q <- d G
	if (ecMulA(Q, ec->base, ec, d, n, stack))
	{
		// Q == pubkey?
		wwTo(Q, 48, Q);
		if (!memEq(Q, pubkey, 48))
			code = ERR_BAD_PUBKEY;
	}
	else
		code = ERR_BAD_PARAMS;
	// завершение
	blobClose(state);
	return code;
}

static size_t bign96PubkeyVal_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(2 * n) +
		ecpIsOnA_deep(n, f_deep);
}

err_t bign96PubkeyVal(const bign_params* params, const octet pubkey[48])
{
	err_t code;
	size_t n;
	// состояние
	void* state;
	ec_o* ec;			/* описание эллиптической кривой */
	word* Q;			/* [2n] открытый ключ */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 96)
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bign96Start_keep(bign96PubkeyVal_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bign96Start(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(pubkey, 48))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	Q = objEnd(ec, word);
	stack = Q + 2 * n;
	// загрузить pt
	if (!qrFrom(ecX(Q), pubkey, ec->f, stack) ||
		!qrFrom(ecY(Q, n), pubkey + 24, ec->f, stack))
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

static size_t bign96PubkeyCalc_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(n + 2 * n) +
		ecMulA_deep(n, ec_d, ec_deep, n);
}

err_t bign96PubkeyCalc(octet pubkey[48], const bign_params* params,
	const octet privkey[24])
{
	err_t code;
	size_t n;
	// состояние
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2n] открытый ключ */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 96)
		return ERR_BAD_PARAMS;
	// создать состояние
	state = blobCreate(bign96Start_keep(bign96PubkeyCalc_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bign96Start(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(privkey, 24) || !memIsValid(pubkey, 48))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	Q = d + n;
	stack = Q + 2 * n;
	// загрузить d
	wwFrom(d, privkey, 24);
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
		qrTo(pubkey + 24, ecY(Q, n), ec->f, stack);
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

static size_t bign96Sign_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(3 * n + 2 * W_OF_O(13)) +
		utilMax(4,
			beltHash_keep(),
			ecMulA_deep(n, ec_d, ec_deep, n),
			zzMul_deep(W_OF_O(13), n),
			zzMod_deep(n + W_OF_O(13), n));
}

err_t bign96Sign(octet sig[34], const bign_params* params,
	const octet oid_der[], size_t oid_len, const octet hash[24],
	const octet privkey[24], gen_i rng, void* rng_state)
{
	err_t code;
	size_t n;
	// состояние (буферы могут пересекаться)
	void* state;			
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ */
	word* R;				/* [2n] точка R */
	word* s0;				/* [W_OF_O(13)] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 96)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len) == SIZE_MAX)
		return ERR_BAD_OID;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// создать состояние
	state = blobCreate(bign96Start_keep(bign96Sign_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bign96Start(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(hash, 24) ||
		!memIsValid(privkey, 24) ||
		!memIsValid(sig, 34) ||
		!memIsDisjoint2(hash, 24, sig, 34))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = s1 = objEnd(ec, word);
	k = d + n;
	R = k + n;
	s0 = R + n + W_OF_O(13);
	stack = (octet*)(s0 + W_OF_O(13));
	// загрузить d
	wwFrom(d, privkey, 24);
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
	// s0 <- belt-hash(oid || R || H) mod 2^80 + 2^l
	beltHashStart(stack);
	beltHashStepH(oid_der, oid_len, stack);
	beltHashStepH(R, 24, stack);
	beltHashStepH(hash, 24, stack);
	beltHashStepG2(sig, 10, stack);
	sig[10] = sig[11] = 0, sig[12] = 0x80;
	wwFrom(s0, sig, 13);
	// R <- (s0 + 2^l) d
	zzMul(R, s0, W_OF_O(13), d, n, stack);
	// s1 <- R mod q
	zzMod(s1, R, n + W_OF_O(13), ec->order, n, stack);
	// s1 <- (k - s1 - H) mod q
	zzSubMod(s1, k, s1, ec->order, n);
	wwFrom(k, hash, 24);
	zzSubMod(s1, s1, k, ec->order, n);
	// выгрузить s1
	wwTo(sig + 10, 24, s1);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

static size_t bign96Sign2_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(3 * n + 2 * W_OF_O(13)) +
		beltHash_keep() +
		utilMax(6,
			beltHash_keep(),
			32,
			beltKWP_keep(),
			ecMulA_deep(n, ec_d, ec_deep, n),
			zzMul_deep(W_OF_O(13), n),
			zzMod_deep(n + W_OF_O(13), n));
}

err_t bign96Sign2(octet sig[34], const bign_params* params,
	const octet oid_der[], size_t oid_len, const octet hash[24],
	const octet privkey[24], const void* t, size_t t_len)
{
	err_t code;
	size_t n;
	u32 round = 1;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ */
	word* R;				/* [2n] точка R */
	word* s0;				/* [W_OF_O(13)] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* hash_state;		/* [beltHash_keep] состояние хэширования */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 96)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// проверить t
	if (!memIsNullOrValid(t, t_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(bign96Start_keep(bign96Sign2_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bign96Start(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(hash, 24) ||
		!memIsValid(privkey, 24) ||
		!memIsValid(sig, 34) ||
		!memIsDisjoint2(hash, 24, sig, 34))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = s1 = objEnd(ec, word);
	k = d + n;
	R = k + n;
	s0 = R + n + W_OF_O(13);
	hash_state = (octet*)(s0 + W_OF_O(13));
	stack = hash_state + beltHash_keep();
	// загрузить d
	wwFrom(d, privkey, 24);
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
		beltHashStepH(privkey, 24, stack);
		if (t != 0)
			beltHashStepH(t, t_len, stack);
		beltHashStepG(stack, stack);
		beltKeyExpand2((u32*)stack, stack, 32);
		// k <- H
		memCopy(k, hash, 24);
		// k <- belt32Block(k, theta) пока k \notin {1,..., q - 1}
		while (1)
		{
			belt32BlockEncr((octet*)k, (u32*)stack, &round);
			wwFrom(k, k, 24);
			if (!wwIsZero(k, n) && wwCmp(k, ec->order, n) < 0)
				break;
			wwTo(k, 24, k);
		}
	}
	// R <- k G
	if (!ecMulA(R, ec->base, ec, k, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 <- belt-hash(oid || R || H) mod 2^80 + 2^l
	beltHashStepH(R, 24, hash_state);
	beltHashStepH(hash, 24, hash_state);
	beltHashStepG2(sig, 10, hash_state);
	sig[10] = sig[11] = 0, sig[12] = 0x80;
	wwFrom(s0, sig, 13);
	// R <- (s0 + 2^96) d
	zzMul(R, s0, W_OF_O(13), d, n, stack);
	// s1 <- R mod q
	zzMod(s1, R, n + W_OF_O(13), ec->order, n, stack);
	// s1 <- (k - s1 - H) mod q
	zzSubMod(s1, k, s1, ec->order, n);
	wwFrom(k, hash, 24);
	zzSubMod(s1, s1, k, ec->order, n);
	// выгрузить s1
	wwTo(sig + 10, 24, s1);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Проверка ЭЦП
*******************************************************************************
*/

static size_t bign96Verify_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(4 * n) +
		utilMax(2,
			beltHash_keep(),
			ecAddMulA_deep(n, ec_d, ec_deep, 2, n, n / 2 + 1));
}

err_t bign96Verify(const bign_params* params, const octet oid_der[],
	size_t oid_len, const octet hash[24], const octet sig[34],
	const octet pubkey[48])
{
	err_t code;
	size_t n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;			/* описание эллиптической кривой */	
	word* Q;			/* [2n] открытый ключ */
	word* R;			/* [2n] точка R */
	word* H;			/* [n] хэш-значение */
	word* s0;			/* [W_OF_O(13)] первая часть подписи */
	word* s1;			/* [n] вторая часть подписи */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 96)
		return ERR_BAD_PARAMS;
	// проверить oid_der
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// создать состояние
	state = blobCreate(bign96Start_keep(bign96Verify_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bign96Start(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(hash, 24) ||
		!memIsValid(sig, 34) ||
		!memIsValid(pubkey, 48))
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
		!qrFrom(ecY(Q, n), pubkey + 24, ec->f, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// загрузить и проверить s1
	wwFrom(s1, sig + 10, 24);
	if (wwCmp(s1, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	// s1 <- (s1 + H) mod q
	wwFrom(H, hash, 24);
	if (wwCmp(H, ec->order, n) >= 0)
	{
		zzSub2(H, ec->order, n);
		// 2^{l - 1} < q < 2^l, H < 2^l => H - q < q
		ASSERT(wwCmp(H, ec->order, n) < 0);
	}
	zzAddMod(s1, s1, H, ec->order, n);
	// загрузить s0
	memCopy(s0, sig, 10);
	((octet*)s0)[10] = ((octet*)s0)[11] = 0, ((octet*)s0)[12] = 0x80;
	wwFrom(s0, s0, 13);
	// R <- s1 G + (s0 + 2^l) Q
	if (!ecAddMulA(R, ec, stack, 2, ec->base, s1, n, Q, s0, (size_t)W_OF_O(13)))
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 == belt-hash(oid || R || H) mod 2^80?
	beltHashStart(stack);
	beltHashStepH(oid_der, oid_len, stack);
	beltHashStepH(R, 24, stack);
	beltHashStepH(hash, 24, stack);
	code = beltHashStepV2(sig, 10, stack) ? ERR_OK : ERR_BAD_SIG;
	// завершение
	blobClose(state);
	return code;
}
