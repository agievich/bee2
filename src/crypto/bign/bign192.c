/*
*******************************************************************************
\file bign192.c
\brief STB 34.101.45 (bign): Bign algorithms with bign-curve256v1 and bash384
\project bee2 [cryptographic library]
\created 2026.03.06
\version 2026.03.06
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/mt.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bign192.h"
#include "bee2/math/ww.h"
#include "bign_lcl.h"

/*
*******************************************************************************
Предвычисленные точки
*******************************************************************************
*/

#include "pre/bign192_pre_si8.c"

/*
*******************************************************************************
Кривая
*******************************************************************************
*/

static size_t _once;			/*< триггер однократности */
static mt_mtx_t _mtx[1];		/*< мьютекс */
static bool_t _inited;			/*< мьютекс создан? */
static ec_o* _ec;				/*< кривая */

static void bign192EcDestroy()
{
	mtMtxLock(_mtx);
	bignEcClose(_ec), _ec = 0;
	mtMtxUnlock(_mtx);
	mtMtxClose(_mtx);
}

static void bign192EcInit()
{
	ASSERT(!_inited);
	// создать мьютекс
	if (!mtMtxCreate(_mtx))
		return;
	// зарегистрировать деструктор
	if (!utilOnExit(bign192EcDestroy))
	{
		mtMtxClose(_mtx);
		return;
	}
	_inited = TRUE;
}

static err_t bign192EcLock(const ec_o** pec)
{
	ASSERT(memIsValid(pec, sizeof(const ec_o*)));
	// инициализировать однократно
	if (!mtCallOnce(&_once, bign192EcInit) || !_inited)
		return ERR_FILE_CREATE;
	// заблокировать мьютекс
	mtMtxLock(_mtx);
	// кривая не создана?
	if (_ec == 0)
	{
		err_t code;
		bign_params params[1];
		// загрузить параметры
		code = bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.2");
		ERR_CALL_HANDLE(code, mtMtxUnlock(_mtx));
		// создать кривую
		code = bignEcCreate(&_ec, params);
		ERR_CALL_HANDLE(code, mtMtxUnlock(_mtx));
		// настроить ec->pre
		_ec->pre = &_pre;
	}
	// возвратить кривую
	*pec = _ec;
	return ERR_OK;
}

static void bign192EcUnlock()
{
	mtMtxUnlock(_mtx);
}

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

err_t bign192KeypairGen(octet privkey[48], octet pubkey[96], gen_i rng, 
	void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignKeypairGenEc(privkey, pubkey, ec, rng, rng_state);
	bign192EcUnlock(ec);
	return code;
}

err_t bign192KeypairVal(const octet privkey[48], const octet pubkey[96])
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignKeypairValEc(ec, privkey, pubkey);
	bign192EcUnlock(ec);
	return code;
}

err_t bign192PubkeyVal(const octet pubkey[96])
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignPubkeyValEc(ec, pubkey);
	bign192EcUnlock(ec);
	return code;
}

err_t bign192PubkeyCalc(octet pubkey[96], const octet privkey[48])
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignPubkeyCalcEc(pubkey, ec, privkey);
	bign192EcUnlock(ec);
	return code;
}

err_t bign192DH(octet key[], const octet privkey[48], const octet pubkey[96],
	size_t key_len)
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignDHEc(key, ec, privkey, pubkey, key_len);
	bign192EcUnlock(ec);
	return code;
}

/*
*******************************************************************************
ЭЦП
*******************************************************************************
*/

static const octet _oid_der[] = {
	0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x4D, 0x0C,
};

err_t bign192Sign(octet sig[72], const octet hash[48],
	const octet privkey[48], gen_i rng,	void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignSignEc(sig, ec, _oid_der, sizeof(_oid_der), hash, privkey, rng,
		rng_state);
	bign192EcUnlock(ec);
	return code;
}

err_t bign192Sign2(octet sig[72], const octet hash[48],
	const octet privkey[48], const void* t, size_t t_len)
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignSign2Ec(sig, ec, _oid_der, sizeof(_oid_der), hash, privkey, t, 
		t_len);
	bign192EcUnlock(ec);
	return code;
}

err_t bign192Verify(const octet hash[48], const octet sig[72], 
	const octet pubkey[96])
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignVerifyEc(ec, _oid_der, sizeof(_oid_der), hash, sig, pubkey);
	bign192EcUnlock(ec);
	return code;
}

/*
*******************************************************************************
Транспорт ключа
*******************************************************************************
*/

err_t bign192KeyWrap(octet token[], const octet key[], size_t len, 
	const octet header[16], const octet pubkey[96], gen_i rng, void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignKeyWrapEc(token, ec, key, len, header, pubkey, rng, rng_state);
	bign192EcUnlock(ec);
	return code;
}

err_t bign192KeyUnwrap(octet key[], const octet token[], size_t len,
	const octet header[16], const octet privkey[48])
{
	err_t code;
	const ec_o* ec;
	code = bign192EcLock(&ec);
	ERR_CALL_CHECK(code);
	code = bignKeyUnwrapEc(key, ec, token, len, header, privkey);
	bign192EcUnlock(ec);
	return code;
}
