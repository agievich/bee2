/*
*******************************************************************************
\file bign_ibs.c
\brief STB 34.101.45 (bign): identity-based signature
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2025.09.05
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign.h"
#include "bee2/math/ecp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "bign_lcl.h"

/*
*******************************************************************************
Извлечение ключей идентификационной ЭЦП
*******************************************************************************
*/

err_t bignIdExtractEc(octet id_privkey[], octet id_pubkey[], 
	const ec_o* ec, const octet oid_der[], size_t oid_len,
	const octet id_hash[], const octet sig[], octet pubkey[])
{
	size_t no, n;
	void* state;
	word* Q;			/* [2n] открытый ключ */
	word* R;			/* [2n] точка R */
	word* H;			/* [n] хэш-значение */
	word* s0;			/* [n / 2 + 1] первая часть подписи */
	word* s1;			/* [n] вторая часть подписи */
	octet* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	ASSERT(n % 2 == 0);
	// входной контроль
	if (!memIsValid(id_hash, no) || !memIsValid(sig, no + no / 2) ||
		!memIsValid(pubkey, 2 * no) || !memIsValid(id_privkey, no) ||
		!memIsValid(id_pubkey, 2 * no))
		return ERR_BAD_INPUT;
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// создать состояние
	state = blobCreate2(
		O_OF_W(2 * n),
		O_OF_W(2 * n) | SIZE_HI,
		O_OF_W(n),
		O_OF_W(n / 2 + 1) | SIZE_HI,
		O_OF_W(n),
		utilMax(2,
			beltHash_keep(),
			ecAddMulA_deep(n, ec->d, ec->deep, 2, n, n / 2 + 1)),
		SIZE_MAX,
		&Q, &R, &H, &s0, &s1, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
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
	// s0 == belt-hash(oid || R || H) mod 2^l?
	beltHashStart(stack);
	beltHashStepH(oid_der, oid_len, stack);
	beltHashStepH(R, no, stack);
	beltHashStepH(id_hash, no, stack);
	if (!beltHashStepV2(sig, no / 2, stack))
	{
		blobClose(state);
		return ERR_BAD_SIG;
	}
	wwTo(id_privkey, no, s1);
	memCopy(id_pubkey, R, no);
	qrTo(id_pubkey + no, ecY(R, n), ec->f, stack);
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignIdExtract(octet id_privkey[], octet id_pubkey[],
	const bign_params* params, const octet oid_der[], size_t oid_len,
	const octet id_hash[], const octet sig[], octet pubkey[])
{
	err_t code;
	ec_o* ec = 0;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignIdExtractEc(id_privkey, id_pubkey, ec, oid_der, oid_len,
		id_hash, sig, pubkey);
	bignEcClose(ec);
	return code;
}

/*
*******************************************************************************
Выработка идентификационной ЭЦП
*******************************************************************************
*/

err_t bignIdSignEc(octet id_sig[], const ec_o* ec, const octet oid_der[],
	size_t oid_len, const octet id_hash[], const octet hash[],
	const octet id_privkey[], gen_i rng, void* rng_state)
{
	size_t no, n;
	void* state;
	word* e;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ */
	word* V;				/* [2n] точка V */
	word* s0;				/* [n/2] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	ASSERT(n % 2 == 0);
	// входной контроль
	if (!memIsValid(id_hash, no) || !memIsValid(hash, no) ||
		!memIsValid(id_privkey, no) || !memIsValid(id_sig, no + no / 2))
		return ERR_BAD_INPUT;
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	if (rng == 0)
		return ERR_BAD_RNG;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		O_OF_W(n) | SIZE_HI,
		O_OF_W(n),
		O_OF_W(2 * n),
		O_OF_W(n / 2),
		utilMax(4,
			beltHash_keep(),
			ecMulA_deep(n, ec->d, ec->deep, n),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n)),
		SIZE_MAX,
		&e, &s1, &k, &V, &s0, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
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
	// s0 <- belt-hash(oid || V || H0 || H) mod 2^l
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
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignIdSign(octet id_sig[], const bign_params* params,
	const octet oid_der[], size_t oid_len, const octet id_hash[],
	const octet hash[], const octet id_privkey[], gen_i rng, void* rng_state)
{
	err_t code;
	ec_o* ec = 0;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignIdSignEc(id_sig, ec, oid_der, oid_len, id_hash, hash,
		id_privkey, rng, rng_state);
	bignEcClose(ec);
	return code;
}

/*
*******************************************************************************
Детерминированная выработка идентификационной ЭЦП
*******************************************************************************
*/

err_t bignIdSign2Ec(octet id_sig[], const ec_o* ec, const octet oid_der[],
	size_t oid_len, const octet id_hash[], const octet hash[],
	const octet id_privkey[], const void* t, size_t t_len)
{
	size_t no, n;
	void* state;
	word* e;				/* [n] личный ключ */
	word* k;				/* [n] одноразовый личный ключ */
	word* V;				/* [2n] точка V */
	word* s0;				/* [n/2] первая часть подписи */
	word* s1;				/* [n] вторая часть подписи */
	octet* hash_state;		/* [beltHash_keep] состояние хэширования */
	octet* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	ASSERT(n % 2 == 0);
	// входной контроль
	if (!memIsValid(id_hash, no) || !memIsValid(hash, no) ||
		!memIsValid(id_privkey, no) || !memIsValid(id_sig, no + no / 2))
		return ERR_BAD_INPUT;
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	if (!memIsNullOrValid(t, t_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		O_OF_W(n),
		O_OF_W(n) | SIZE_HI,
		O_OF_W(n),
		O_OF_W(2 * n),
		O_OF_W(n / 2),
		beltHash_keep(),
		utilMax(6,
			beltHash_keep(),
			32,
			beltWBL_keep(),
			ecMulA_deep(n, ec->d, ec->deep, n),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n)),
		SIZE_MAX,
		&e, &s1, &k, &V, &s0, &hash_state, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
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
		// инициализировать beltWBL ключом theta
		beltWBLStart(stack, stack, 32);
		// k <- H
		memCopy(k, hash, no);
		// k <- beltWBL(k, theta) пока k \notin {1,..., q - 1}
		while (1)
		{
			beltWBLStepE(k, no, stack);
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
	// s0 <- belt-hash(oid || V || H0 || H) mod 2^l
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
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t bignIdSign2(octet id_sig[], const bign_params* params,
	const octet oid_der[], size_t oid_len, const octet id_hash[],
	const octet hash[], const octet id_privkey[], const void* t, size_t t_len)
{
	err_t code;
	ec_o* ec = 0;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignIdSign2Ec(id_sig, ec, oid_der, oid_len, id_hash, hash,
		id_privkey, t, t_len);
	bignEcClose(ec);
	return code;
}

/*
*******************************************************************************
Проверка идентификационной ЭЦП
*******************************************************************************
*/

err_t bignIdVerifyEc(const ec_o* ec, const octet oid_der[], size_t oid_len,
	const octet id_hash[], const octet hash[], const octet id_sig[],
	const octet id_pubkey[], const octet pubkey[])
{
	err_t code;
	size_t no, n;
	void* state;
	word* R;			/* [2n] открытый ключ R */
	word* Q;			/* [2n] открытый ключ Q */
	word* V;			/* [2n] точка V (V == R) */
	word* s0;			/* [n / 2 + 1] первая часть подписи */
	word* s1;			/* [n] вторая часть подписи */
	word* t;			/* [n / 2] переменная t */
	word* t1;			/* [n + 1] произведение (s0 + 2^l)(t + 2^l) */
	octet* hash_state;	/* [beltHash_keep] состояние хэширования */
	octet* stack;
	// pre
	ASSERT(ecIsOperable(ec));
	// размерности
	no = ec->f->no, n = ec->f->n;
	ASSERT(n % 2 == 0);
	// входной контроль
	if (!memIsValid(id_hash, no) || !memIsValid(hash, no) ||
		!memIsValid(id_sig, no + no / 2) || !memIsValid(id_pubkey, 2 * no) ||
		!memIsValid(pubkey, 2 * no))
		return ERR_BAD_INPUT;
	if (oid_len == SIZE_MAX || oidFromDER(0, oid_der, oid_len)  == SIZE_MAX)
		return ERR_BAD_OID;
	// создать состояние
	state = blobCreate2(
		O_OF_W(2 * n),
		O_OF_W(2 * n) | SIZE_HI,
		O_OF_W(2 * n),
		O_OF_W(n / 2 + 1),
		O_OF_W(n),
		O_OF_W(n / 2),
		O_OF_W(n + 1),
		beltHash_keep(),
		utilMax(5,
			beltHash_keep(),
			ecpIsOnA_deep(n, ec->f->deep),
			zzMul_deep(n / 2, n / 2),
			zzMod_deep(n + 1, n),
			ecAddMulA_deep(n, ec->d, ec->deep, 3, n, n / 2 + 1, n)),
		SIZE_MAX,
		&R, &V, &Q, &s0, &s1, &t, &t1, &hash_state, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
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
	// t <- belt-hash(oid || R || H0) mod 2^l
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
	// s0 == belt-hash(oid || V || H0 || H) mod 2^l?
	beltHashStepH(V, no, hash_state);
	beltHashStepH(id_hash, no, hash_state);
	beltHashStepH(hash, no, hash_state);
	code = beltHashStepV2(id_sig, no / 2, hash_state) ? ERR_OK : ERR_BAD_SIG;
	// завершение
	blobClose(state);
	return code;
}

err_t bignIdVerify(const bign_params* params, const octet oid_der[],
	size_t oid_len, const octet id_hash[], const octet hash[],
	const octet id_sig[], const octet id_pubkey[], const octet pubkey[])
{
	err_t code;
	ec_o* ec = 0;
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	code = bignIdVerifyEc(ec, oid_der, oid_len, id_hash, hash, id_sig,
		id_pubkey, pubkey);
	bignEcClose(ec);
	return code;
}
