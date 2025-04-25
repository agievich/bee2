/*
*******************************************************************************
\file btok_bauth.c
\brief STB 34.101.79 (btok): BAUTH protocol
\project bee2 [cryptographic library]
\created 2022.02.22
\version 2025.04.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/obj.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bake.h"
#include "bee2/crypto/belt.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ecp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "crypto/bign/bign_lcl.h"

/*
*******************************************************************************
Состояния

ct:
- dct: 4
- Rct: 2, 4
- uct: 2, 4
- {Vct}: 2, 4
- K: 2
- {Zct}: 2
- K0: 4
- K1: 4
- [K2]: 4
- {Tt}: 4
- [{Rt}]: 4
- [t]: 4
- [sct]: 4
- [{Zct}]: 4
- [{Tct}]: 4

t:
- dt: 3
- {Vct}: 3, [5]
- K: 3
- {Zct}: 3
- Rct: 3
- {Rt}: [3], [5]
- K0: 3
- K1: 3, 5
- K2: [3], [5]
- {Tt}: 3
- [{Zct}]: 5
- [{Tct}]: 5
- sct: [5]

A=T
B=CT
*******************************************************************************
*/

typedef struct
{
	obj_hdr_t hdr;				/*< заголовок */
// ptr_table {
	ec_o* ec;					/*< описание эллиптической кривой */
	word* d;					/*< [ec->f->n] долговременный личный ключ */
	word* Vct;					/*< [2*ec->f->n] Vct */
	octet* R;					/*< [l/8] одноразовый секретный ключ */
// }
	bign_params params[1];		/*< параметры */
	bake_settings settings[1];	/*< настройки */
	bake_cert cert[1];			/*< сертификат */
	octet K0[32];				/*< ключ K0 */
	octet K1[32];				/*< ключ K1 */
	octet K2[32];				/*< ключ K2 */
	octet data[];				/*< данные */
} bake_bauth_t_o;

static size_t btokBAuthT_deep(
	size_t n, size_t f_deep, size_t ec_d, size_t ec_deep);

size_t btokBAuthT_keep(size_t l)
{
	const size_t n = W_OF_B(2 * l);
	const size_t no = O_OF_B(2 * l);
	return sizeof(bake_bauth_t_o) +
		bignStart_keep(l, btokBAuthT_deep) +
		3 * O_OF_W(n) + no / 2;
}

typedef struct
{
	obj_hdr_t hdr;				/*< заголовок */
// ptr_table {
	ec_o* ec;					/*< описание эллиптической кривой */
	word* d;					/*< [ec->f->n] долговременный личный ключ */
	word* u;					/*< [ec->f->n] одноразовый личный ключ */
	octet* V;					/*< [ec->f->no] ecX(V) */
	octet* R;					/*< [l/8] одноразовый секретный ключ */
// }
	bign_params params[1];		/*< параметры */
	bake_settings settings[1];	/*< настройки */
	bake_cert cert[1];			/*< сертификат */
	octet K0[32];				/*< ключ K0 */
	octet data[];				/*< данные */
} bake_bauth_ct_o;

static size_t btokBAuthCT_deep(
	size_t n, size_t f_deep, size_t ec_d, size_t ec_deep);

size_t btokBAuthCT_keep(size_t l)
{
	const size_t n = W_OF_B(2 * l);
	const size_t no = O_OF_B(2 * l);
	return sizeof(bake_bauth_ct_o) +
		bignStart_keep(l, btokBAuthCT_deep) +
		2 * O_OF_W(n) + no + no / 2;
}

/*
*******************************************************************************
Запуск
*******************************************************************************
*/

err_t btokBAuthTStart(void* state, const bign_params* params,
	const bake_settings* settings, const octet privkey[],
	const bake_cert* cert)
{
	err_t code;
	bake_bauth_t_o* s = (bake_bauth_t_o*)state;
	size_t n, no;
	// стек
	word* Q;
	void* stack;
	// проверить входные данные
	if (!memIsValid(params, sizeof(bign_params)) ||
		!memIsValid(settings, sizeof(bake_settings)) ||
		settings->kca != TRUE ||
		!memIsNullOrValid(settings->helloa, settings->helloa_len) ||
		!memIsNullOrValid(settings->hellob, settings->hellob_len))
		return ERR_BAD_INPUT;
	if (!bignIsOperable(params))
		return ERR_BAD_PARAMS;
	if (settings->rng == 0)
		return ERR_BAD_RNG;
	if (!memIsValid(privkey, params->l / 4) ||
		!memIsValid(cert, sizeof(bake_cert)) ||
		!memIsValid(cert->data, cert->len) ||
		cert->val == 0)
		return ERR_BAD_INPUT;
	// загрузить параметры
	code = bignStart(s->data, params);
	ERR_CALL_CHECK(code);
	s->ec = (ec_o*)s->data;
	n = s->ec->f->n, no = s->ec->f->no;
	// сохранить параметры
	memCopy(s->params, params, sizeof(bign_params));
	// сохранить настройки
	memCopy(s->settings, settings, sizeof(bake_settings));
	// настроить указатели
	s->d = objEnd(s->ec, word);
	s->Vct = s->d + n;
	s->R = (octet*)(s->Vct + 2 * n);
	// настроить заголовок
	s->hdr.keep = sizeof(bake_bauth_t_o) + objKeep(s->ec) +
		3 * O_OF_W(n) + no / 2;
	s->hdr.p_count = 3;
	s->hdr.o_count = 1;
	// загрузить личный ключ
	wwFrom(s->d, privkey, no);
	// раскладка стека
	Q = objEnd(s, word);
	stack = Q + 2 * n;
	// проверить сертификат и его открытый ключ
	code = cert->val((octet*)Q, params, cert->data, cert->len);
	ERR_CALL_CHECK(code);
	if (!qrFrom(ecX(Q), (octet*)Q, s->ec->f, stack) ||
		!qrFrom(ecY(Q, n), (octet*)Q + no, s->ec->f, stack) ||
		!ecpIsOnA(Q, s->ec, stack))
		return ERR_BAD_CERT;
	// сохранить сертификат
	memCopy(s->cert, cert, sizeof(bake_cert));
	// все нормально
	return code;
}

static size_t btokBAuthTStart_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(2 * n) +
		utilMax(2,
			f_deep,
			ecpIsOnA_deep(n, f_deep));
}

err_t btokBAuthCTStart(void* state, const bign_params* params,
	const bake_settings* settings, const octet privkey[],
	const bake_cert* cert)
{
	err_t code;
	bake_bauth_ct_o* s = (bake_bauth_ct_o*)state;
	size_t n, no;
	// стек
	word* Q;
	void* stack;
	// проверить входные данные
	if (!memIsValid(params, sizeof(bign_params)) ||
		!memIsValid(settings, sizeof(bake_settings)) ||
		settings->kca != TRUE ||
		!memIsNullOrValid(settings->helloa, settings->helloa_len) ||
		!memIsNullOrValid(settings->hellob, settings->hellob_len))
		return ERR_BAD_INPUT;
	if (!bignIsOperable(params))
		return ERR_BAD_PARAMS;
	if (settings->rng == 0)
		return ERR_BAD_RNG;
	if (!memIsValid(privkey, params->l / 4) ||
		!memIsValid(cert, sizeof(bake_cert)) ||
		!memIsValid(cert->data, cert->len) ||
		cert->val == 0)
		return ERR_BAD_INPUT;
	// загрузить параметры
	code = bignStart(s->data, params);
	ERR_CALL_CHECK(code);
	s->ec = (ec_o*)s->data;
	n = s->ec->f->n, no = s->ec->f->no;
	// сохранить параметры
	memCopy(s->params, params, sizeof(bign_params));
	// сохранить настройки
	memCopy(s->settings, settings, sizeof(bake_settings));
	// настроить указатели
	s->d = objEnd(s->ec, word);
	s->u = s->d + n;
	s->V = (octet*)(s->u + n);
	s->R = s->V + no;
	// настроить заголовок
	s->hdr.keep = sizeof(bake_bauth_ct_o) + objKeep(s->ec) +
		3 * O_OF_W(n) + no + no / 2;
	s->hdr.p_count = 4;
	s->hdr.o_count = 1;
	// загрузить личный ключ
	wwFrom(s->d, privkey, no);
	// раскладка стека
	Q = objEnd(s, word);
	stack = Q + 2 * n;
	// проверить сертификат и его открытый ключ
	code = cert->val((octet*)Q, params, cert->data, cert->len);
	ERR_CALL_CHECK(code);
	if (!qrFrom(ecX(Q), (octet*)Q, s->ec->f, stack) ||
		!qrFrom(ecY(Q, n), (octet*)Q + no, s->ec->f, stack) ||
		!ecpIsOnA(Q, s->ec, stack))
		return ERR_BAD_CERT;
	// сохранить сертификат
	memCopy(s->cert, cert, sizeof(bake_cert));
	// все нормально
	return code;
}

static size_t btokBAuthCTStart_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(2 * n) +
		utilMax(2,
			f_deep,
			ecpIsOnA_deep(n, f_deep));
}

/*
*******************************************************************************
Шаги
*******************************************************************************
*/

err_t btokBAuthCTStep2(octet out[], const bake_cert* certt, void* state)
{
  err_t code;
	bake_bauth_ct_o* s = (bake_bauth_ct_o*)state;
	size_t n, no;
  octet hdr[16];
	// стек
	word* Vct;		/* [2 * n] */
	word* Qt;		/* [2 * n] */
	word* K;		/* [2 * n] */
	void* stack;
	// обработать входные данные
	if (!objIsOperable(s))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(out, 2 * no + no / 2 + 16))
		return ERR_BAD_INPUT;
	ASSERT(memIsDisjoint2(out, 2 * no + no / 2 + 16, s, objKeep(s)));
	// раскладка стека
	Vct = objEnd(s, word);
	Qt = Vct + 2 * n;
	K = Qt + 2 * n;
	stack = K + 2 * n;
	ASSERT(32 <= no);
	// проверить certT
	code = certt->val((octet*)Qt, s->params, certt->data, certt->len);
	ERR_CALL_CHECK(code);
	if (!qrFrom(ecX(Qt), (octet*)Qt, s->ec->f, stack) ||
		!qrFrom(ecY(Qt, n), (octet*)Qt + no, s->ec->f, stack) ||
		!ecpIsOnA(Qt, s->ec, stack))
		return ERR_BAD_CERT;
	// Rct <-R {0, 1}^l
	s->settings->rng(s->R, no / 2, s->settings->rng_state);
	// uct <-R {1, 2, ..., q - 1}
	if (!zzRandNZMod(s->u, s->ec->order, n, s->settings->rng,
		s->settings->rng_state))
		return ERR_BAD_RNG;
	// Vct <- uct G
	if (!ecMulA(Vct, s->ec->base, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	// K <- uct Qt
	if (!ecMulA(K, Qt, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	// сохранить ecX(Vct)
	qrTo(s->V, ecX(Vct), s->ec->f, stack);
	// out <- <Vct> || belt-keywrap(Rct, 0^16, K)
	memCopy(out, s->V, no);
	qrTo(out + no, ecY(Vct, n), s->ec->f, stack);
	memSetZero(hdr, 16);
	qrTo((octet*)K, ecX(K), s->ec->f, stack);
	beltKWPWrap(out + 2 * no, s->R, no / 2, hdr, (octet*)K, 32);
	// все нормально
	return ERR_OK;
}

static size_t btokBAuthCTStep2_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(6 * n) +
		utilMax(2,
			f_deep,
			ecMulA_deep(n, ec_d, ec_deep, n));
}

err_t btokBAuthTStep3(octet out[], const octet in[], void* state)
{
	bake_bauth_t_o* s = (bake_bauth_t_o*)state;
	size_t n, no;
	octet hdr[16];
	// стек
	word* K;		/* [2 * n] общий ключ */
	octet* Rct;		/* [l/8] одноразовый секретный ключ (совпадает с K, Y) */
	octet* Y;		/* [32] (совпадает c Y) */
	octet* block0;	/* [16] (следует за Y) */
	octet* block1;	/* [16] (следует за block0) */
	void* stack;
	// проверить входные данные
	if (!objIsOperable(s))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(in, 2 * no + no / 2 + 16) ||
		!memIsValid(out, (8u + s->settings->kcb) ? no / 2 : 0))
		return ERR_BAD_INPUT;
	ASSERT(memIsDisjoint2(out, (8u + s->settings->kcb) ?
		no / 2 : 0, s, objKeep(s)));
	// раскладка стека [Y || block0 || block1 должны умещаться в 3 * n слов]
	K = objEnd(s, word);
	Y = Rct = (octet*)K;
	block0 = Y + 32;
	block1 = block0 + 16;
	stack = Y + MAX2(O_OF_W(2 * n), 32 + 16 + 16);
	// сохранить <Vct>
	memCopy(s->Vct, in, 2 * no);
	// Vb <- in ||..., Vb \in E*?
	if (!qrFrom(ecX(s->Vct), in, s->ec->f, stack) ||
		!qrFrom(ecY(s->Vct, n), in + no, s->ec->f, stack) ||
		!ecpIsOnA(s->Vct, s->ec, stack))
		return ERR_BAD_POINT;
	// K <- dt Vct
	if (!ecMulA(K, s->Vct, s->ec, s->d, n, stack))
		return ERR_BAD_PARAMS;
	memSetZero(hdr, 16);
	qrTo((octet*)K, ecX(K), s->ec->f, stack);
	// Rct <- belt-keyunwrap(Zct, 0^16, K)
	if (beltKWPUnwrap(Rct, in + 2 * no, O_OF_B(s->params->l + 128), hdr,
		(octet*)K, 32) != ERR_OK)
		return ERR_AUTH;
	// Y <- beltHash(<Rct>_l || [<Rt>_l ||] helloa || hellob)
	beltHashStart(stack);
	beltHashStepH(Rct, no / 2, stack);
	if (s->settings->kcb)
	{
  		// Rt <-R {0, 1}^128
		s->settings->rng(s->R, 16, s->settings->rng_state);
		beltHashStepH(s->R, 16, stack);
	}
	if (s->settings->helloa)
		beltHashStepH(s->settings->helloa, s->settings->helloa_len, stack);
	if (s->settings->hellob)
		beltHashStepH(s->settings->hellob, s->settings->hellob_len, stack);
	ASSERT(no >= 32);
	beltHashStepG(Y, stack);
	// K0 <- beltKRP(Y, 1^96, 0)
	memSetZero(block0, 16);
	memSet(block1, 0xFF, 16);
	beltKRPStart(stack, Y, 32, block1);
	beltKRPStepG(s->K0, 32, block0, stack);
	if (s->settings->kcb)
	{
		// K2 <- beltKRP(Y, 1^96, 2)
		block0[0] = 2;
		beltKRPStepG(s->K2, 32, block0, stack);
	}
	// K1 <- beltKRP(Y, 1^96, 1)
	block0[0] = 1;
	beltKRPStepG(s->K1, 32, block0, stack);
	// Tt <- beltMAC(0^128, K1)
	block0[0] = 0;
	beltMACStart(stack, s->K1, 32);
	beltMACStepA(block0, 16, stack);
	// out <- Tt
	beltMACStepG(out, stack);
	if (s->settings->kcb)
	{
		// out <- Tt || Rt
		memCopy(out + 8, s->R, 16);
	}
	// все нормально
	return ERR_OK;
}

static size_t btokBAuthTStep3_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return MAX2(O_OF_W(2 * n), 32 + 16 + 16) +
		utilMax(5,
			f_deep,
			ecMulA_deep(n, ec_d, ec_deep, n),
			beltHash_keep(),
			beltKRP_keep(),
			beltMAC_keep());
}

err_t btokBAuthCTStep4(octet out[], const octet in[], void* state)
{
	bake_bauth_ct_o* s = (bake_bauth_ct_o*)state;
	size_t n, no;
	// стек
	octet* Y;		/* [32] (совпадает c t, sct) */
	octet* block0;	/* [16] (следует перед Y) */
	octet* block1;	/* [16] (следует за Y) */
	octet* K1;		/* [32] общий ключ (совпадает с Y) */
	octet* K2;		/* [32] общий ключ */
	word* t;		/* [n / 2 + 1] (совпадает c Y, sct) */
	word* sct;		/* [n + n / 2 + 1] (совпадает c Y, t) */
	void* stack;
	// проверить входные данные
	if (!objIsOperable(s))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(in, (8u + s->settings->kcb) ? no / 2 : 0) ||
		!memIsValid(out, s->settings->kcb ? (8u + no + s->cert->len) : 0))
		return ERR_BAD_INPUT;
	ASSERT(memIsDisjoint2(out, s->settings->kcb ?
		(8u + O_OF_B(2 * s->params->l) + s->cert->len) : 0, s, objKeep(s)));
	block0 = objEnd(s, octet);
	K1 = block0 + 16;
	Y = K1 + 32;
	t = (word*)Y;
	sct = t + n / 2;
	block1 = Y + 32;
	K2 = (octet*)(sct + n + n / 2 + 1);
	stack = K2 + 32;
	// Y <- beltHash(<Rct>_l || [<Rt>_l ||] helloa || hellob)
	beltHashStart(stack);
	beltHashStepH(s->R, no / 2, stack);
	if (s->settings->kcb)
  	beltHashStepH(in + 8, no / 2, stack);
	if (s->settings->helloa)
		beltHashStepH(s->settings->helloa, s->settings->helloa_len, stack);
	if (s->settings->hellob)
		beltHashStepH(s->settings->hellob, s->settings->hellob_len, stack);
	ASSERT(no >= 32);
	beltHashStepG(Y, stack);
	// K0 <- beltKRP(Y, 1^96, 0)
	memSetZero(block0, 16);
	memSet(block1, 0xFF, 16);
	beltKRPStart(stack, Y, 32, block1);
	beltKRPStepG(s->K0, 32, block0, stack);
	// K1 <- beltKRP(Y, 1^96, 1)
	block0[0] = 1;
	beltKRPStepG(K1, 32, block0, stack);
	// K2 <- beltKRP(Y, 1^96, 2)
	if (s->settings->kcb)
	{
		block0[0] = 2;
		beltKRPStepG(K2, 32, block0, stack);
	}
	// Tt == beltMAC(0^128, K1)?
	block0[0] = 0;
	beltMACStart(stack, K1, 32);
	beltMACStepA(block0, 16, stack);
	if (!beltMACStepV(in, stack))
		return ERR_AUTH;
	if (s->settings->kcb)
	{
		// t <- <beltHash(<Vct>_2l || Rt)>_l
		beltHashStart(stack);
		beltHashStepH(s->V, no, stack);
		beltHashStepH(in + 8, 16, stack);
		beltHashStepG2((octet*)t, no / 2, stack);
		wwFrom(t, t, no / 2);
		// sct <- (uct - (2^l + t)dct) \mod q
		zzMul(sct, t, n / 2, s->d, n, stack);
		sct[n + n / 2] = zzAdd2(sct + n / 2, s->d, n);
		zzMod(sct, sct, n + n / 2 + 1, s->ec->order, n, stack);
		zzSubMod(sct, s->u, sct, s->ec->order, n);
  		// out ||.. <- sct || cert_ct
		wwTo(out, no, sct);
		memCopy(out + no, s->cert->data, s->cert->len);
		// out ||.. <- beltCFBEncr(sct || cert_ct, K2, 0^128)
		block0[0] = 0;
		beltCFBStart(stack, K2, 32, block0);
		beltCFBStepE(out, no + s->cert->len, stack);
		// ..|| out <- beltMAC(beltCFBEncr(sct || cert_ct))
		beltMACStart(stack, K1, 32);
		beltMACStepA(out, no + s->cert->len, stack);
		beltMACStepG(out + no + s->cert->len, stack);
	}
	// все нормально
	return ERR_OK;
}

static size_t btokBAuthCTStep4_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return 16 + 32 + 32 + O_OF_W(2 * n + 1) +
		utilMax(5,
			f_deep,
			ecMulA_deep(n, ec_d, ec_deep, n),
			beltHash_keep(),
			beltKRP_keep(),
			beltMAC_keep());
}

err_t btokBAuthTStep5(const octet in[], size_t in_len, bake_certval_i val_ct,
	void* state)
{
	err_t code;
	bake_bauth_t_o* s = (bake_bauth_t_o*)state;
	size_t n, no;
	// стек
	word* Qct;			/* [2 * n] */
	word* sct;			/* [n] */
	octet* V;			/* [no] */
	word* t;			/* [n / 2 + 1] (совпадает с V) */
	octet* block0;		/* [16] (совпадает с Qct) */
	void* stack;
	octet mac[8];
	// проверить входные данные
	if (!objIsOperable(s))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!s->settings->kcb)
		return ERR_BAD_LOGIC;
	if (in_len < 8 + no || !memIsValid(in, in_len) || val_ct == 0)
		return ERR_BAD_INPUT;
	// раскладка стека
	Qct = objEnd(s, word);
	block0 = (octet*)Qct;
	sct = Qct + 2 * n;
	V = (octet*)(sct + n);
	t = (word*)V;
	stack = V + no;
	// Tct == beltMAC(Zct, K1)?
	beltMACStart(stack, s->K1, 32);
	beltMACStepA(in, in_len - 8, stack);
	beltMACStepG(mac, stack);
	if (!beltMACStepV(in + in_len - 8, stack))
		return ERR_AUTH;
	// обработать Zct = [in_len - 8]in
	in_len -= 8;
	{
		blob_t Zct;
		// sct || cert_ct <- beltCFBDecr(Zct, K2, 0^128)
		if ((Zct = blobCreate(in_len)) == 0)
			return ERR_OUTOFMEMORY;
		memCopy(Zct, in, in_len);
		memSet(block0, 0, 16);
		beltCFBStart(stack, s->K2, 32, block0);
		beltCFBStepD(Zct, in_len, stack);
		// sct \in {0, 1,..., q - 1}?
		wwFrom(sct, Zct, no);
		if (wwCmp(sct, s->ec->order, n) >= 0)
		{
			blobClose(Zct);
			return ERR_AUTH;
		}
		// проверить cert_ct
		code = val_ct((octet*)Qct, s->params, (octet*)Zct + no, in_len - no);
		ERR_CALL_HANDLE(code, blobClose(Zct));
		if (!qrFrom(ecX(Qct), (octet*)Qct, s->ec->f, stack) ||
			!qrFrom(ecY(Qct, n), (octet*)Qct + no, s->ec->f, stack) ||
			!ecpIsOnA(Qct, s->ec, stack))
			code = ERR_BAD_CERT;
		blobClose(Zct);
		ERR_CALL_CHECK(code);
	}
	// t <- <beltHash(<Vct>_2l || <Rt>)>_l
	beltHashStart(stack);
	qrTo(V, ecX(s->Vct), s->ec->f, stack);
	beltHashStepH(V, no, stack);
	beltHashStepH(s->R, 16, stack);
	beltHashStepG2((octet*)t, no / 2, stack);
	wwFrom(t, t, no / 2);
	// sct G + (2^l + t)Qct == Vct?
	t[n / 2] = 1;
	if (!ecAddMulA(Qct, s->ec, stack, 2, s->ec->base, sct, n, Qct, t,
		n / 2 + 1))
		return ERR_BAD_PARAMS;
	if (!wwEq(Qct, s->Vct, 2 * n))
		return ERR_AUTH;
	// все нормально
	return ERR_OK;
}

static size_t btokBAuthTStep5_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(3 * n + n / 2 + 1) +
		utilMax(6,
			beltHash_keep(),
			beltMAC_keep(),
			beltCFB_keep(),
			f_deep,
			ecpIsOnA_deep(n, f_deep),
			ecAddMulA_deep(n, ec_d, ec_deep, 2, n, n / 2 + 1));
}

static size_t btokBAuthCT_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return utilMax(3,
		btokBAuthCTStart_deep(n, f_deep, ec_d, ec_deep),
		btokBAuthCTStep2_deep(n, f_deep, ec_d, ec_deep),
		btokBAuthCTStep4_deep(n, f_deep, ec_d, ec_deep));
}

static size_t btokBAuthT_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return utilMax(3,
		btokBAuthTStart_deep(n, f_deep, ec_d, ec_deep),
		btokBAuthTStep3_deep(n, f_deep, ec_d, ec_deep),
		btokBAuthTStep5_deep(n, f_deep, ec_d, ec_deep));
}

/*
*******************************************************************************
Выгрузка ключа
*******************************************************************************
*/

err_t btokBAuthCTStepG(octet key[32], void* state)
{
	bake_bauth_ct_o* s = (bake_bauth_ct_o*)state;
	// проверить входные данные
	if (!objIsOperable(s) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// key <- K0
	memCopy(key, s->K0, 32);
	// все нормально
	return ERR_OK;
}

err_t btokBAuthTStepG(octet key[32], void* state)
{
	bake_bauth_t_o* s = (bake_bauth_t_o*)state;
	// проверить входные данные
	if (!objIsOperable(s) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// key <- K0
	memCopy(key, s->K0, 32);
	// все нормально
	return ERR_OK;
}
