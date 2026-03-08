/*
*******************************************************************************
\file bign128.c
\brief STB 34.101.45 (bign): Bign algorithms with bign-curve256v1 and belt-hash
\project bee2 [cryptographic library]
\created 2026.03.05
\version 2026.03.08
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/mt.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bign128.h"
#include "bee2/math/ww.h"
#include "bign_lcl.h"

/*
*******************************************************************************
Предвычисленные точки
*******************************************************************************
*/

#include "pre/bign128_pre_od7.c"

/*
*******************************************************************************
Кривая
*******************************************************************************
*/

static size_t _once;			/*< триггер однократности */
static mt_mtx_t _mtx[1];		/*< мьютекс */
static bool_t _inited;			/*< мьютекс создан? */
static ec_o* _ec;				/*< кривая */

static void bign128Destroy()
{
	mtMtxLock(_mtx);
	bignEcClose(_ec), _ec = 0;
	mtMtxUnlock(_mtx);
	mtMtxClose(_mtx);
}

static void bign128Init()
{
	ASSERT(!_inited);
	// создать мьютекс
	if (!mtMtxCreate(_mtx))
		return;
	// зарегистрировать деструктор
	if (!utilOnExit(bign128Destroy))
	{
		mtMtxClose(_mtx);
		return;
	}
	_inited = TRUE;
}

static err_t bign128Ec(const ec_o** pec)
{
	ASSERT(memIsValid(pec, sizeof(const ec_o*)));
	// инициализировать однократно
	if (!mtCallOnce(&_once, bign128Init) || !_inited)
		return ERR_FILE_CREATE;
	// заблокировать мьютекс
	mtMtxLock(_mtx);
	// кривая не создана?
	if (_ec == 0)
	{
		err_t code;
		bign_params params[1];
		// загрузить параметры
		code = bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1");
		ERR_CALL_HANDLE(code, mtMtxUnlock(_mtx));
		// создать кривую
		code = bignEcCreate(&_ec, params);
		ERR_CALL_HANDLE(code, mtMtxUnlock(_mtx));
		// настроить ec->pre
		_ec->pre = &_pre;
	}
	// возвратить кривую
	*pec = _ec;
	mtMtxUnlock(_mtx);
	return ERR_OK;
}

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

err_t bign128KeypairGen(octet privkey[32], octet pubkey[64], gen_i rng, 
	void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeypairGenEc(privkey, pubkey, ec, rng, rng_state);
}

err_t bign128KeypairVal(const octet privkey[32], const octet pubkey[64])
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeypairValEc(ec, privkey, pubkey);
}

err_t bign128PubkeyVal(const octet pubkey[64])
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignPubkeyValEc(ec, pubkey);
}

err_t bign128PubkeyCalc(octet pubkey[64], const octet privkey[32])
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignPubkeyCalcEc(pubkey, ec, privkey);
}

err_t bign128DH(octet key[], const octet privkey[32], const octet pubkey[64],
	size_t key_len)
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignDHEc(key, ec, privkey, pubkey, key_len);
}

/*
*******************************************************************************
ЭЦП

\remark DER(belt-hash) = 1.2.112.0.2.0.34.101.31.81
*******************************************************************************
*/

static const octet _oid_der[] = {
	0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
};

err_t bign128Sign(octet sig[48], const octet hash[32],
	const octet privkey[32], gen_i rng,	void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignSignEc(sig, ec, _oid_der, sizeof(_oid_der), hash, privkey, rng,
		rng_state);
}

err_t bign128Sign2(octet sig[48], const octet hash[32],
	const octet privkey[32], const void* t, size_t t_len)
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignSign2Ec(sig, ec, _oid_der, sizeof(_oid_der), hash, privkey, t, 
		t_len);
}

err_t bign128Verify(const octet hash[32], const octet sig[48], 
	const octet pubkey[64])
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignVerifyEc(ec, _oid_der, sizeof(_oid_der), hash, sig, pubkey);
}

/*
*******************************************************************************
Транспорт ключа
*******************************************************************************
*/

err_t bign128KeyWrap(octet token[], const octet key[], size_t len, 
	const octet header[16], const octet pubkey[64], gen_i rng, void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeyWrapEc(token, ec, key, len, header, pubkey, rng, rng_state);
}

err_t bign128KeyUnwrap(octet key[], const octet token[], size_t len,
	const octet header[16], const octet privkey[32])
{
	err_t code;
	const ec_o* ec;
	code = bign128Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeyUnwrapEc(key, ec, token, len, header, privkey);
}
