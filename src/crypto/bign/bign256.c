/*
*******************************************************************************
\file bign256.c
\brief STB 34.101.45 (bign): Bign algorithms with bign-curve512v1 and bash512
\project bee2 [cryptographic library]
\created 2026.03.06
\version 2026.03.08
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/mt.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bign256.h"
#include "bee2/math/ww.h"
#include "bign_lcl.h"

/*
*******************************************************************************
Предвычисленные точки
*******************************************************************************
*/

#include "pre/bign256_pre_si8.c"

/*
*******************************************************************************
Кривая
*******************************************************************************
*/

static size_t _once;			/*< триггер однократности */
static mt_mtx_t _mtx[1];		/*< мьютекс */
static bool_t _inited;			/*< мьютекс создан? */
static ec_o* _ec;				/*< кривая */

static void bign256Destroy()
{
	mtMtxLock(_mtx);
	bignEcClose(_ec), _ec = 0;
	mtMtxUnlock(_mtx);
	mtMtxClose(_mtx);
}

static void bign256Init()
{
	ASSERT(!_inited);
	// создать мьютекс
	if (!mtMtxCreate(_mtx))
		return;
	// зарегистрировать деструктор
	if (!utilOnExit(bign256Destroy))
	{
		mtMtxClose(_mtx);
		return;
	}
	_inited = TRUE;
}

static err_t bign256Ec(const ec_o** pec)
{
	ASSERT(memIsValid(pec, sizeof(const ec_o*)));
	// инициализировать однократно
	if (!mtCallOnce(&_once, bign256Init) || !_inited)
		return ERR_FILE_CREATE;
	// заблокировать мьютекс
	mtMtxLock(_mtx);
	// кривая не создана?
	if (_ec == 0)
	{
		err_t code;
		bign_params params[1];
		// загрузить параметры
		code = bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.3");
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

err_t bign256KeypairGen(octet privkey[64], octet pubkey[128], gen_i rng, 
	void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeypairGenEc(privkey, pubkey, ec, rng, rng_state);
}

err_t bign256KeypairVal(const octet privkey[64], const octet pubkey[128])
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeypairValEc(ec, privkey, pubkey);
}

err_t bign256PubkeyVal(const octet pubkey[128])
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignPubkeyValEc(ec, pubkey);
}

err_t bign256PubkeyCalc(octet pubkey[128], const octet privkey[64])
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignPubkeyCalcEc(pubkey, ec, privkey);
}

err_t bign256DH(octet key[], const octet privkey[64], const octet pubkey[128],
	size_t key_len)
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignDHEc(key, ec, privkey, pubkey, key_len);
}

/*
*******************************************************************************
ЭЦП

\remark DER(bash512) = 1.2.112.0.2.0.34.101.77.13
*******************************************************************************
*/

static const octet _oid_der[] = {
	0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x4D, 0x0D,
};

err_t bign256Sign(octet sig[96], const octet hash[64],
	const octet privkey[64], gen_i rng,	void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignSignEc(sig, ec, _oid_der, sizeof(_oid_der), hash, privkey, rng,
		rng_state);
}

err_t bign256Sign2(octet sig[96], const octet hash[64],
	const octet privkey[64], const void* t, size_t t_len)
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignSign2Ec(sig, ec, _oid_der, sizeof(_oid_der), hash, privkey, t, 
		t_len);
}

err_t bign256Verify(const octet hash[64], const octet sig[96], 
	const octet pubkey[128])
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignVerifyEc(ec, _oid_der, sizeof(_oid_der), hash, sig, pubkey);
}

/*
*******************************************************************************
Транспорт ключа
*******************************************************************************
*/

err_t bign256KeyWrap(octet token[], const octet key[], size_t len, 
	const octet header[16], const octet pubkey[128], gen_i rng, 
	void* rng_state)
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeyWrapEc(token, ec, key, len, header, pubkey, rng, rng_state);
}

err_t bign256KeyUnwrap(octet key[], const octet token[], size_t len,
	const octet header[16], const octet privkey[64])
{
	err_t code;
	const ec_o* ec;
	code = bign256Ec(&ec);
	ERR_CALL_CHECK(code);
	return bignKeyUnwrapEc(key, ec, token, len, header, privkey);
}
