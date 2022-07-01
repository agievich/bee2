/*
*******************************************************************************
\file bign_sign.c
\brief STB 34.101.45 (bign): digital signature
\project bee2 [cryptographic library]
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.27
\version 2021.07.20
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign.h"
#include "crypto/bign_lcl.h"
#include "bee2/math/ecp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

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
			ecpMulA1_deep(n, f_deep, ec_d, ec_deep, n),
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
		return ERR_OUTOFMEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	ASSERT(n % 2 == 0);
	// проверить входные указатели
	if (!memIsValid(hash, no) ||
		!memIsValid(privkey, no) ||
		!memIsValid(sig, no + no / 2) ||
		!memIsDisjoint2(hash, no, sig, no + no / 2))
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
	if (!ecpMulA1(R, ec->base, ec, k, n, params->precomp.Gs, params->precomp.w, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 <- belt-hash(oid || R || H) mod 2^l
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
		utilMax(6,
			beltHash_keep(),
			32,
			beltWBL_keep(),
			ecpMulA1_deep(n, f_deep, ec_d, ec_deep, n),
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
		return ERR_OUTOFMEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	ASSERT(n % 2 == 0);
	// проверить входные указатели
	if (!memIsValid(hash, no) ||
		!memIsValid(privkey, no) ||
		!memIsValid(sig, no + no / 2) ||
		!memIsDisjoint2(hash, no, sig, no + no / 2))
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
	// сгенерировать k по алгоритму bign-genk
	{
		// theta <- belt-hash(oid || d || t)
		memCopy(stack, hash_state, beltHash_keep());
		beltHashStepH(privkey, no, stack);
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
	// R <- k G
	if (!ecpMulA1(R, ec->base, ec, k, n, params->precomp.Gs, params->precomp.w, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	qrTo((octet*)R, ecX(R), ec->f, stack);
	// s0 <- belt-hash(oid || R || H) mod 2^l
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
		return ERR_OUTOFMEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	ASSERT(n % 2 == 0);
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
	wwFrom(s1, sig + no / 2, no);
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
	// s0 == belt-hash(oid || R || H) mod 2^l?
	beltHashStart(stack);
	beltHashStepH(oid_der, oid_len, stack);
	beltHashStepH(R, no, stack);
	beltHashStepH(hash, no, stack);
	code = beltHashStepV2(sig, no / 2, stack) ? ERR_OK : ERR_BAD_SIG;
	// завершение
	blobClose(state);
	return code;
}

