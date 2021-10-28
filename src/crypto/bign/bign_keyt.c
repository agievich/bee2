/*
*******************************************************************************
\file bign_keyt.c
\brief STB 34.101.45 (bign): key transport
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
#include "bee2/math/gfp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Создание токена ключа
*******************************************************************************
*/

static size_t bignKeyWrap_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(3 * n) + 32 +
		utilMax(3,
			ecMulA_deep(n, ec_d, ec_deep, n),
			ecpMulA1_deep(n, f_deep, ec_d, ec_deep, n),
			beltKWP_keep());
}

err_t bignKeyWrap(octet token[], const bign_params* params, const octet key[],
	size_t len, const octet header[16], const octet pubkey[],
	gen_i rng, void* rng_state)
{
	err_t code;
	size_t no, n;
	// состояние
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* k;				/* [n] одноразовый личный ключ */
	word* R;				/* [2n] точка R */
	octet* theta;			/* [32] ключ защиты */
	octet* stack;
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// проверить header и key
	if (len < 16 ||
		!memIsValid(key, len) ||
		!memIsNullOrValid(header, 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignKeyWrap_deep));
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
	if (!memIsValid(pubkey, 2 * no) ||
		!memIsValid(token, 16 + no + len))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	k = objEnd(ec, word);
	R = k + n;
	theta = (octet*)(R + 2 * n);
	stack = theta + 32;
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
	if (!ecpMulA1(R, ec->base, ec, k, n, params->precomp.Gs, params->precomp.w, stack))
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
	// все нормально
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Разбор токена ключа
*******************************************************************************
*/

static size_t bignKeyUnwrap_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return MAX2(O_OF_W(5 * n), 32 + 16) +
		utilMax(3,
			beltKWP_keep(),
			qrPower_deep(n, n, f_deep),
			ecMulA_deep(n, ec_d, ec_deep, n));
}

err_t bignKeyUnwrap(octet key[], const bign_params* params, const octet token[], 
	size_t len, const octet header[16], const octet privkey[])
{
	err_t code;
	size_t no, n;
	// состояние (буферы могут пересекаться)
	void* state;
	ec_o* ec;				/* описание эллиптической кривой */
	word* d;				/* [n] личный ключ */
	word* R;				/* [2n] точка R */
	word* t1;				/* [n] вспомогательное число */
	word* t2;				/* [n] вспомогательное число */
	octet* theta;			/* [32] ключ защиты */
	octet* header2;			/* [16] заголовок2 */
	void* stack;			/* граница стека */
	// проверить params
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	// проверить token и header
	if (!memIsValid(token, len) ||
		!memIsNullOrValid(header, 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(bignStart_keep(params->l, bignKeyUnwrap_deep));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bignStart(state, params);
	ERR_CALL_HANDLE(code, blobClose(state));
	ec = (ec_o*)state;
	// размерности
	no  = ec->f->no;
	n = ec->f->n;
	// проверить длину токена
	if (len < 32 + no)
	{
		blobClose(state);
		return ERR_BAD_KEYTOKEN;
	}
	// проверить входные указатели
	if (!memIsValid(privkey, no) ||
		!memIsValid(key, len - 16 - no))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	R = d + n;
	t1 = R + 2 * n;
	t2 = t1 + n;
	theta = (octet*)d;
	header2 = theta + 32;
	if (5 * no >= 48)
		stack = t2 + n;
	else
		stack = header2 + 16;
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
		code = ERR_BAD_KEYTOKEN;
	}
	// завершение
	blobClose(state);
	return code;
}
