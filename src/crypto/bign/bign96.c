/*
*******************************************************************************
\file bign96.c
\brief Experimental Bign signatures of security level 96
\project bee2 [cryptographic library]
\created 2021.01.20
\version 2026.03.10
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mt.h"
#include "bee2/core/str.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign96.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "bign_lcl.h"

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
Загрузка стандартных параметров
*******************************************************************************
*/

err_t bign96ParamsStd(bign_params* params, const char* name)
{
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (strEq(name, _curve96v1_name))
	{
		memSetZero(params, sizeof(bign_params));
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
Предвычисленные точки
*******************************************************************************
*/

#include "pre/bign96_pre_od7.c"

/*
*******************************************************************************
Кривая
*******************************************************************************
*/

static size_t _once;			/*< триггер однократности */
static mt_mtx_t _mtx[1];		/*< мьютекс */
static bool_t _inited;			/*< мьютекс создан? */
static ec_o* _ec;				/*< кривая */

static void bign96Destroy()
{
	mtMtxLock(_mtx);
	bignEcClose(_ec), _ec = 0;
	mtMtxUnlock(_mtx);
	mtMtxClose(_mtx);
}

static void bign96Init()
{
	ASSERT(!_inited);
	// создать мьютекс
	if (!mtMtxCreate(_mtx))
		return;
	// зарегистрировать деструктор
	if (!utilOnExit(bign96Destroy))
	{
		mtMtxClose(_mtx);
		return;
	}
	_inited = TRUE;
}

static err_t bign96Ec(const ec_o** pec)
{
	ASSERT(memIsValid(pec, sizeof(const ec_o*)));
	// инициализировать однократно
	if (!mtCallOnce(&_once, bign96Init) || !_inited)
		return ERR_FILE_CREATE;
	// заблокировать мьютекс
	mtMtxLock(_mtx);
	// кривая не создана?
	if (_ec == 0)
	{
		err_t code;
		bign_params params[1];
		// загрузить параметры
		code = bign96ParamsStd(params, "1.2.112.0.2.0.34.101.45.3.0");
		ERR_CALL_HANDLE(code, mtMtxUnlock(_mtx));
		// создать кривую
		code = bignEcCreate(&_ec, params);
		ERR_CALL_HANDLE(code, mtMtxUnlock(_mtx));
		// настроить ec->pre
//		_ec->pre = &_pre;
	}
	// возвратить кривую
	*pec = _ec;
	mtMtxUnlock(_mtx);
	return ERR_OK;
}

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
	u32* t;
	// подготовить память
	ASSERT(memIsAligned(block, 4));
	t = (u32*)block;
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
Управление ключами
*******************************************************************************
*/

err_t bign96KeypairGen(octet privkey[24], octet pubkey[48], gen_i rng, 
	void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign96Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeypairGenEc(privkey, pubkey, ec, rng, rng_state);
}

err_t bign96KeypairVal(const octet privkey[24], const octet pubkey[48])
{
	err_t code;
	const ec_o* ec;
	code = bign96Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeypairValEc(ec, privkey, pubkey);
}

err_t bign96PubkeyVal(const octet pubkey[48])
{
	err_t code;
	const ec_o* ec;
	code = bign96Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignPubkeyValEc(ec, pubkey);
}

err_t bign96PubkeyCalc(octet pubkey[48], const octet privkey[24])
{
	err_t code;
	const ec_o* ec;
	code = bign96Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignPubkeyCalcEc(pubkey, ec, privkey);
}

/*
*******************************************************************************
Выработка ЭЦП

\remark DER(belt-hash) = 1.2.112.0.2.0.34.101.31.81
*******************************************************************************
*/

static const octet _oid_der[] = {
	0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
};

err_t bign96SignEc(octet sig[34], const ec_o* ec, const octet hash[24],
	const octet privkey[24], gen_i rng, void* rng_state)
{
	size_t n;
	void* state;			
	word* d;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ (|d) */
	word* R;				/* [2 * n] точка R */
	word* s0;				/* [W_OF_O(13)] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	void* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	n = ec->f->n;
	// входной контроль
	if (!memIsValid(hash, 24) || !memIsValid(privkey, 24) ||
		!memIsValid(sig, 34) || !memIsDisjoint2(hash, 24, sig, 34))
		return ERR_BAD_INPUT;
	if (rng == 0)
		return ERR_BAD_RNG;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		O_OF_W(n) | SIZE_HI,
		O_OF_W(n),
		O_OF_W(2 * n),
		O_OF_W(W_OF_O(13)),
		utilMax(4,
			beltHash_keep(),
			bignMulBase_deep(n, ec->d, ec->deep),
			zzMul_deep(W_OF_O(13), n),
			zzMod_deep(n + W_OF_O(13), n)),
		SIZE_MAX,
		&d, &s1, &k, &R, &s0, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
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
	if (!bignMulBase(R, ec, k, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 <- belt-hash(oid || R || H) mod 2^80 + 2^l
	beltHashStart(stack);
	beltHashStepH(_oid_der, sizeof(_oid_der), stack);
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
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bign96Sign(octet sig[34], const octet hash[24], const octet privkey[24], 
	gen_i rng, void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign96Ec(&ec);
	ERR_CALL_CHECK(code);
	return bign96SignEc(sig, ec, hash, privkey, rng, rng_state);
}

err_t bign96Sign2Ec(octet sig[34], const ec_o* ec, const octet hash[24],
	const octet privkey[24], const void* t, size_t t_len)
{
	size_t n;
	void* state;
	word* d;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ (|d) */
	word* R;				/* [2 * n] точка R */
	word* s0;				/* [W_OF_O(13)] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* hash_state;		/* [beltHash_keep()] состояние хэширования */
	void* stack;
	u32 round = 1;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	n = ec->f->n;
	// входной контроль
	if (!memIsValid(hash, 24) || !memIsValid(privkey, 24) ||
		!memIsValid(sig, 34) || !memIsDisjoint2(hash, 24, sig, 34))
		return ERR_BAD_INPUT;
	if (!memIsNullOrValid(t, t_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		O_OF_W(n) | SIZE_HI,
		O_OF_W(n),
		O_OF_W(2 * n),
		O_OF_W(W_OF_O(13)),
		beltHash_keep(),
		utilMax(6,
			beltHash_keep(),
			(size_t)32,
			beltKWP_keep(),
			bignMulA_deep(n, ec->d, ec->deep),
			zzMul_deep(W_OF_O(13), n),
			zzMod_deep(n + W_OF_O(13), n)),
	SIZE_MAX,
		&d, &s1, &k, &R, &s0, &hash_state, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// загрузить d
	wwFrom(d, privkey, 24);
	if (wwIsZero(d, n) || wwCmp(d, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// хэшировать oid
	beltHashStart(hash_state);
	beltHashStepH(_oid_der, sizeof(_oid_der), hash_state);
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
	if (!bignMulA(R, ec->base, ec, k, stack))
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
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bign96Sign2(octet sig[34], const octet hash[24], const octet privkey[24],
	const void* t, size_t t_len)
{
	err_t code;
	const ec_o* ec;
	code = bign96Ec(&ec);
	ERR_CALL_CHECK(code);
	return bign96Sign2Ec(sig, ec, hash, privkey, t, t_len);
}

/*
*******************************************************************************
Проверка ЭЦП
*******************************************************************************
*/

err_t bign96VerifyEc(const ec_o* ec, const octet hash[24], const octet sig[34],
	const octet pubkey[48])
{
	err_t code;
	size_t n;
	void* state;
	word* Q;			/* [2 * n] открытый ключ */
	word* R;			/* [2 * n] точка R (|Q) */
	word* H;			/* [n] хэш-значение */
	word* s0;			/* [W_OF_O(13)] первая часть подписи (|H) */
	word* s1;			/* [n] вторая часть подписи */
	void* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	n = ec->f->n;
	// входной контроль
	if (!memIsValid(hash, 24) || !memIsValid(sig, 34) ||
		!memIsValid(pubkey, 48))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		O_OF_W(2 * n),
		O_OF_W(2 * n) | SIZE_HI,
		O_OF_W(n),
		O_OF_W(W_OF_O(13)) | SIZE_HI,
		O_OF_W(n),
		utilMax(2,
			beltHash_keep(),
			ecAddMulA_deep(n, ec->d, ec->deep, 2, n, W_OF_O(13))),
		SIZE_MAX,
		&Q, &R, &H, &s0, &s1, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
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
	if (!ecAddMulA(R, ec, stack, 2, ec->base, s1, n, Q, s0, W_OF_O(13)))
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 == belt-hash(oid || R || H) mod 2^80?
	beltHashStart(stack);
	beltHashStepH(_oid_der, sizeof(_oid_der), stack);
	beltHashStepH(R, 24, stack);
	beltHashStepH(hash, 24, stack);
	code = beltHashStepV2(sig, 10, stack) ? ERR_OK : ERR_BAD_SIG;
	// завершение
	blobClose(state);
	return code;
}

err_t bign96Verify(const octet hash[24], const octet sig[34], 
	const octet pubkey[48])
{
	err_t code;
	const ec_o* ec;
	code = bign96Ec(&ec);
	ERR_CALL_CHECK(code);
	return bign96VerifyEc(ec, hash, sig, pubkey);
}
