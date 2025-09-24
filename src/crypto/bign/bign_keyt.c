/*
*******************************************************************************
\file bign_keyt.c
\brief STB 34.101.45 (bign): key transport
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2025.09.24
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/obj.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign.h"
#include "bee2/math/ec.h"
#include "bee2/math/qr.h"
#include "bee2/math/ww.h"
#include "bee2/math/zm.h"
#include "bee2/math/zz.h"
#include "bign_lcl.h"

/*
*******************************************************************************
Создание токена
*******************************************************************************
*/

err_t bignKeyWrapEc(octet token[], const ec_o* ec, const octet key[],
	size_t len, const octet header[16], const octet pubkey[],
	gen_i rng, void* rng_state)
{
	size_t no, n;
	void* state;
	word* k;				/* [n] одноразовый личный ключ */
	word* R;				/* [2n] точка R */
	octet* theta;			/* [32] ключ защиты */
	void* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	// входной контроль
	if (!memIsValid(pubkey, 2 * no) || !memIsValid(token, 16 + no + len))
		return ERR_BAD_INPUT;
	if (rng == 0)
		return ERR_BAD_RNG;
	if (len < 16 || !memIsValid(key, len) || !memIsNullOrValid(header, 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		O_OF_W(2 * n),
		(size_t)32,
		utilMax(2,
			ecMulA_deep(n, ec->d, ec->deep, n),
			beltKWP_keep()),
		SIZE_MAX,
		&k, &R, &theta, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
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
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignKeyWrap(octet token[], const bign_params* params, const octet key[],
	size_t len, const octet header[16], const octet pubkey[], gen_i rng,
	void* rng_state)
{
	err_t code;
	ec_o* ec;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignKeyWrapEc(token, ec, key, len, header, pubkey, rng, rng_state);
	bignEcClose(ec);
	return code;
}

/*
*******************************************************************************
Разбор токена
*******************************************************************************
*/

err_t bignKeyUnwrapEc(octet key[], const ec_o* ec, const octet token[], 
	size_t len, const octet header[16], const octet privkey[])
{
	size_t no, n;
	void* state;
	word* d;				/* [n] личный ключ */
	word* R;				/* [2n] точка R */
	word* t1;				/* [n] вспомогательное число */
	word* t2;				/* [n] вспомогательное число */
	octet* theta;			/* [32] ключ защиты */
	octet* header2;			/* [16] заголовок2 */
	void* stack;			/* граница стека */
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	// входной контроль
	if (len < 32 + no)
		return ERR_BAD_KEYTOKEN;
	if (!memIsValid(token, len) || !memIsNullOrValid(header, 16) ||
		!memIsValid(privkey, no) || !memIsValid(key, len - 16 - no))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		(size_t)32,
		O_OF_W(2 * n),
		O_OF_W(n),
		O_OF_W(n),
		(size_t)16,
		utilMax(3,
			beltKWP_keep(),
			qrPower_deep(n, n, ec->f->deep),
			ecMulA_deep(n, ec->d, ec->deep, n)),
		SIZE_MAX,
		&d, &theta, &R, &t1, &t2, &header2, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
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
		return ERR_BAD_KEYTOKEN;
	}
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignKeyUnwrap(octet key[], const bign_params* params, const octet token[],
	size_t len, const octet header[16], const octet privkey[])
{
	err_t code;
	ec_o* ec;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignKeyUnwrapEc(key, ec, token, len, header, privkey);
	bignEcClose(ec);
	return code;
}
