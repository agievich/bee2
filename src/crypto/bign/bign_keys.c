/*
*******************************************************************************
\file bign_keys.c
\brief STB 34.101.45 (bign): key management
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
#include "bee2/crypto/bign.h"
#include "crypto/bign_lcl.h"
#include "bee2/math/ecp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

static size_t bignGenKeypair_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(n + 2 * n) +
		ecpMulA1_deep(n, f_deep, ec_d, ec_deep, n);
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
		return ERR_OUTOFMEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(privkey, no) || !memIsValid(pubkey, 2 * no))
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
	if (ecpMulA1(Q, ec->base, ec, d, n, params->precomp.Gs, params->precomp.w, stack))
	{
		// выгрузить ключи
		wwTo(privkey, no, d);
		qrTo(pubkey, ecX(Q), ec->f, stack);
		qrTo(pubkey + no, ecY(Q, n), ec->f, stack);
	}
	else
		code = ERR_BAD_PARAMS;
	// завершение
	blobClose(state);
	return code;
}

static size_t bignValKeypair_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(n + 2 * n) +
		ecpMulA1_deep(n, f_deep, ec_d, ec_deep, n);
}

err_t bignValKeypair(const bign_params* params, const octet privkey[],
	const octet pubkey[])
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
	state = blobCreate(bignStart_keep(params->l, bignValKeypair_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(privkey, no) || !memIsValid(pubkey, 2 * no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	Q = d + n;
	stack = Q + 2 * n;
	// d <- privkey
	wwFrom(d, privkey, no);
	// 0 < d < q?
	wwFrom(Q, params->q, no);
	if (wwIsZero(d, n) || wwCmp(d, Q, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// Q <- d G
	if (ecpMulA1(Q, ec->base, ec, d, n, params->precomp.Gs, params->precomp.w, stack))
	{
		// Q == pubkey?
		wwTo(Q, 2 * no, Q);
		if (!memEq(Q, pubkey, 2 * no))
			code = ERR_BAD_PUBKEY;
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
		return ERR_OUTOFMEMORY;
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
		ecpMulA1_deep(n, f_deep, ec_d, ec_deep, n);
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
		return ERR_OUTOFMEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить входные указатели
	if (!memIsValid(privkey, no) || !memIsValid(pubkey, 2 * no))
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
	if (ecpMulA1(Q, ec->base, ec, d, n, params->precomp.Gs, params->precomp.w, stack))
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
		return ERR_OUTOFMEMORY;
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
		return ERR_BAD_SHAREDKEY;
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

