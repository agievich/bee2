/*
*******************************************************************************
\file bign_misc.c
\brief STB 34.101.45 (bign): miscellaneous (OIDs, keys, DH)
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2025.09.26
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bign.h"
#include "bee2/math/ecp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "bign_lcl.h"

/*
*******************************************************************************
Идентификатор объекта
*******************************************************************************
*/

err_t bignOidToDER(octet der[], size_t* count, const char* oid)
{
	size_t len;
	if (!strIsValid(oid) || 
		!memIsValid(count, O_PER_S) ||
		!memIsNullOrValid(der, *count))
		return ERR_BAD_INPUT;
	len = oidToDER(0, oid);
	if (len == SIZE_MAX)
		return ERR_BAD_OID;
	if (der)
	{
		if (*count < len)
			return ERR_OUTOFMEMORY;
		len = oidToDER(der, oid);
		ASSERT(len != SIZE_MAX);
	}
	*count = len;
	return ERR_OK;
}

/*
*******************************************************************************
Генерация ключей
*******************************************************************************
*/

err_t bignKeypairGenEc(octet privkey[], octet pubkey[], const ec_o* ec,
	gen_i rng, void* rng_state)
{
	size_t no, n;
	void* state;
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2 * n] открытый ключ */
	void* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	// входной контроль
	if (!memIsValid(privkey, no) || !memIsValid(pubkey, 2 * no))
		return ERR_BAD_INPUT;
	if (rng == 0)
		return ERR_BAD_RNG;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		O_OF_W(2 * n),
		ecMulA_deep(n, ec->d, ec->deep, n),
		SIZE_MAX,
		&d, &Q, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// d <-R {1,2,..., q - 1}
	if (!zzRandNZMod(d, ec->f->mod, n, rng, rng_state))
	{
		blobClose(state);
		return ERR_BAD_RNG;
	}
	// Q <- d G
	if (!ecMulA(Q, ec->base, ec, d, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// выгрузить ключи
	wwTo(privkey, no, d);
	qrTo(pubkey, ecX(Q), ec->f, stack);
	qrTo(pubkey + no, ecY(Q, n), ec->f, stack);
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignKeypairGen(octet privkey[], octet pubkey[],
	const bign_params* params, gen_i rng, void* rng_state)
{
	err_t code;
	ec_o* ec;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignKeypairGenEc(privkey, pubkey, ec, rng, rng_state);
	bignEcClose(ec);
	return code;
}

/*
*******************************************************************************
Проверка пары ключей
*******************************************************************************
*/

err_t bignKeypairValEc(const ec_o* ec, const octet privkey[],
	const octet pubkey[])
{
	size_t no, n;
	void* state;
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2 * n] открытый ключ */
	void* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	// входной контроль
	if (!memIsValid(privkey, no) || !memIsValid(pubkey, 2 * no))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		O_OF_W(2 * n),
		ecMulA_deep(n, ec->d, ec->deep, n),
		SIZE_MAX,
		&d, &Q, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// d <- privkey
	wwFrom(d, privkey, no);
	// 0 < d < q?
	if (wwIsZero(d, n) || wwCmp(d, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// Q <- d G
	if (!ecMulA(Q, ec->base, ec, d, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// Q == pubkey?
	wwTo(Q, 2 * no, Q);
	if (!memEq(Q, pubkey, 2 * no))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignKeypairVal(const bign_params* params, const octet privkey[],
	const octet pubkey[])
{
	err_t code;
	ec_o* ec;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignKeypairValEc(ec, privkey, pubkey);
	bignEcClose(ec);
	return code;
}

/*
*******************************************************************************
Проверка открытого ключа
*******************************************************************************
*/

err_t bignPubkeyValEc(const ec_o* ec, const octet pubkey[])
{
	size_t no, n;
	void* state;
	word* Q;			/* [2 * n] открытый ключ */
	void* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	// входной контроль
	if (!memIsValid(pubkey, 2 * no))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		O_OF_W(2 * n),
		ecpIsOnA_deep(n, ec->f->deep),
		SIZE_MAX,
		&Q, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// загрузить pt
	// Q \in ec?
	if (!qrFrom(ecX(Q), pubkey, ec->f, stack) ||
		!qrFrom(ecY(Q, n), pubkey + no, ec->f, stack) ||
		!ecpIsOnA(Q, ec, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignPubkeyVal(const bign_params* params, const octet pubkey[])
{
	err_t code;
	ec_o* ec;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignPubkeyValEc(ec, pubkey);
	bignEcClose(ec);
	return code;
}

/*
*******************************************************************************
Вычисление открытого ключа по личному
*******************************************************************************
*/

err_t bignPubkeyCalcEc(octet pubkey[], const ec_o* ec, const octet privkey[])
{
	size_t no, n;
	void* state;
	word* d;				/* [n] личный ключ */
	word* Q;				/* [2 * n] открытый ключ */
	void* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	// входной контроль
	if (!memIsValid(privkey, no) || !memIsValid(pubkey, 2 * no))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		O_OF_W(2 * n),
		ecMulA_deep(n, ec->d, ec->deep, n),
		SIZE_MAX,
		&d, &Q, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// загрузить d
	wwFrom(d, privkey, no);
	if (wwIsZero(d, n) || wwCmp(d, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// Q <- d G
	if (!ecMulA(Q, ec->base, ec, d, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// выгрузить открытый ключ
	qrTo(pubkey, ecX(Q), ec->f, stack);
	qrTo(pubkey + no, ecY(Q, n), ec->f, stack);
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignPubkeyCalc(octet pubkey[], const bign_params* params,
	const octet privkey[])
{
	err_t code;
	ec_o* ec;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignPubkeyCalcEc(pubkey, ec, privkey);
	bignEcClose(ec);
	return code;
}

/*
*******************************************************************************
Ключ Диффи -- Хеллмана
*******************************************************************************
*/

err_t bignDHEc(octet key[], const ec_o* ec, const octet privkey[],
	const octet pubkey[], size_t key_len)
{
	size_t no, n;
	void* state;
	word* u;				/* [n] личный ключ */
	octet* K;				/* [no] координаты общего ключа (|u) */
	word* V;				/* [2 * n] открытый ключ */
	void* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	// входной контроль
	if (!memIsValid(privkey, no) || !memIsValid(pubkey, 2 * no) ||
		!memIsValid(key, key_len))
		return ERR_BAD_INPUT;
	if (key_len > 2 * no)
		return ERR_BAD_SHAREDKEY;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		no | SIZE_HI,
		O_OF_W(2 * n),
		utilMax(2,
			ecpIsOnA_deep(n, ec->f->deep),
			ecMulA_deep(n, ec->d, ec->deep, n)),
		SIZE_MAX,
		&u, &K, &V, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// загрузить u
	wwFrom(u, privkey, no);
	if (wwIsZero(u, n) || wwCmp(u, ec->order, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// загрузить V
	if (!qrFrom(ecX(V), pubkey, ec->f, stack) ||
		!qrFrom(ecY(V, n), pubkey + no, ec->f, stack) ||
		!ecpIsOnA(V, ec, stack))
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// V <- u V
	if (!ecMulA(V, V, ec, u, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// выгрузить общий ключ
	qrTo(K, ecX(V), ec->f, stack);
	memCopy(key, K, MIN2(key_len, no));
	if (key_len > no)
	{
		qrTo(K, ecY(V, n), ec->f, stack);
		memCopy(key + no, K, key_len - no);
	}
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignDH(octet key[], const bign_params* params, const octet privkey[],
	const octet pubkey[], size_t key_len)
{
	err_t code;
	ec_o* ec;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignDHEc(key, ec, privkey, pubkey, key_len);
	bignEcClose(ec);
	return code;
}
