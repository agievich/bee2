/*
*******************************************************************************
\file bake_bmqv.c
\brief STB 34.101.66 (bake): the BMQV protocol
\project bee2 [cryptographic library]
\created 2014.04.14
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
#include "bee2/crypto/bake.h"
#include "bee2/crypto/belt.h"
#include "bee2/math/qr.h"
#include "bee2/math/ecp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "../bign/bign_lcl.h"

/*
*******************************************************************************
Шаги протокола BMQV

\todo Оптимизировать вычисление s(V - (2^l + t)Q):
	--	вычислить проективную кратную точку (2^l + t)Q и вычесть из нее 
		аффинную (пока нет функции вычисления проективной кратной точки);
	--	находить сумму кратных точек sV + (- s(2^l + t))Q (ecAddMulAA).
[В последнем случае теряется малость t].

\todo Контроль последовательности выполнения шагов?
*******************************************************************************
*/

typedef struct
{
	bign_params params[1];		/*< параметры */
	bake_settings settings[1];	/*< настройки */
	bake_cert cert[1];			/*< сертификат */
	octet K0[32];				/*< ключ K0 */
	octet K1[32];				/*< ключ K1 */
	ec_o* ec;					/*< эллиптическая кривая */
	word* d;					/*< [n] долговременный личный ключ */
	word* u;					/*< [n] одноразовый личный ключ */
	octet* Vb;					/*< [no] ecX(Vb) */
	void* stack;				/*< [bakeBMQV_deep] стек */
	mem_align_t data[];			/*< данные */
} bake_bmqv_st;

static size_t bakeBMQV_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep);

#define bakeBMQV_state(n, no)\
/* d */			O_OF_W(n),\
/* u */			O_OF_W(n),\
/* Vb */		no

size_t bakeBMQV_keep(size_t l)
{
	const size_t n = W_OF_B(2 * l);
	const size_t no = O_OF_B(2 * l);
	return sizeof(bake_bmqv_st) +
		memSliceSize(
			bignStart_keep(l, bakeBMQV_deep),
			bakeBMQV_state(n, no),
			SIZE_MAX);
}

#define bakeBMQVStart_local(n)\
/* Q */			O_OF_W(2 * n)

err_t bakeBMQVStart(void* state, const bign_params* params,
	const bake_settings* settings, const octet privkey[],
	const bake_cert* cert)
{
	err_t code;
	bake_bmqv_st* s = (bake_bmqv_st*)state;
	size_t n, no;
	word* Q;				/* [2n] */
	void* stack;
	// входной контроль
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	if (!memIsValid(settings, sizeof(bake_settings)) ||
		!memIsNullOrValid(settings->helloa, settings->helloa_len) ||
		!memIsNullOrValid(settings->hellob, settings->hellob_len) ||
		!memIsValid(privkey, params->l / 4) ||
		!memIsValid(cert, sizeof(bake_cert)) ||
		!memIsValid(cert->data, cert->len) ||
		cert->val == 0)
		return ERR_BAD_INPUT;
	if (settings->rng == 0)
		return ERR_BAD_RNG;
	// развернуть кривую
	code = bignStart(s->data, params);
	ERR_CALL_CHECK(code);
	memSlice(s->data,
		objKeep(s->data), SIZE_0, SIZE_MAX,
		&s->ec, &stack);
	n = s->ec->f->n, no = s->ec->f->no;
	// разметить состояние и стек
	memSlice(stack,
		bakeBMQV_state(n, no), SIZE_0,
		bakeBMQVStart_local(n), SIZE_0, SIZE_MAX,
		&s->d, &s->u, &s->Vb, &s->stack,
		&Q, &stack);
	// сохранить параметры
	memCopy(s->params, params, sizeof(bign_params));
	// сохранить настройки
	memCopy(s->settings, settings, sizeof(bake_settings));
	// загрузить личный ключ
	wwFrom(s->d, privkey, no);
	// проверить сертификат и его открытый ключ
	code = cert->val((octet*)Q, params, cert->data, cert->len);
	ERR_CALL_CHECK(code);
	if (!qrFrom(ecX(Q), (octet*)Q, s->ec->f, stack) ||
		!qrFrom(ecY(Q, n), (octet*)Q + no, s->ec->f, stack) ||
		!ecpIsOnA(Q, s->ec, stack))
		return ERR_BAD_CERT;
	// сохранить сертификат
	memCopy(s->cert, cert, sizeof(bake_cert));
	// завершение
	return code;
}

static size_t bakeBMQVStart_deep(size_t n, size_t f_deep)
{
	return memSliceSize(
		bakeBMQVStart_local(n),
		utilMax(2,
			f_deep,
			ecpIsOnA_deep(n, f_deep)),
		SIZE_MAX);
}

#define bakeBMQVStep2_local(n)\
/* Vb */		O_OF_W(2 * n)

err_t bakeBMQVStep2(octet out[], void* state)
{
	bake_bmqv_st* s = (bake_bmqv_st*)state;
	size_t n, no;
	word* Vb;			/* [2n] */
	void* stack;
	// обработать входные данные
	if (!memIsValid(s, sizeof(bake_bmqv_st)) || !ecIsOperable(s->ec))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(out, 2 * no))
		return ERR_BAD_INPUT;
	// разметить стек
	memSlice(s->stack,
		bakeBMQVStep2_local(n), SIZE_0, SIZE_MAX,
		&Vb, &stack);
	// ub <-R {1, 2, ..., q - 1}
	if (!zzRandNZMod(s->u, s->ec->order, n, s->settings->rng,
		s->settings->rng_state))
		return ERR_BAD_RNG;
	// Vb <- ub G
	if (!ecMulA(Vb, s->ec->base, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	// out <- <Vb>
	qrTo(out, ecX(Vb), s->ec->f, stack);
	qrTo(out + no, ecY(Vb, n), s->ec->f, stack);
	// сохранить ecX(Vb)
	memCopy(s->Vb, out, no);
	// завершение
	return ERR_OK;
}

static size_t bakeBMQVStep2_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return memSliceSize(
		bakeBMQVStep2_local(n),
		utilMax(2,
			f_deep,
			ecMulA_deep(n, ec_d, ec_deep, n)),
		SIZE_MAX);
}

#define bakeBMQVStep3_local(n, no)\
/* Qb */		O_OF_W(2 * n),\
/* K */			no | SIZE_HI,\
/* Va */		O_OF_W(2 * n),\
/* Vb */		O_OF_W(2 * n),\
/* t */			O_OF_W(n / 2 + 1),\
/* block0 */	(size_t)16 | SIZE_HI,\
/* sa */		O_OF_W(n + n / 2 + 1),\
/* block1 */	(size_t)16 | SIZE_HI

err_t bakeBMQVStep3(octet out[], const octet in[], const bake_cert* certb,
	void* state)
{
	err_t code;
	bake_bmqv_st* s = (bake_bmqv_st*)state;
	size_t n, no;
	word* Qb;				/* [2n] */
	word* Va;				/* [2n] */
	word* Vb;				/* [2n] */
	word* t;				/* [n / 2 + 1] */
	word* sa;				/* [n + n / 2 + 1] */
	octet* K;				/* [no] */
	octet* block0;			/* [16] */
	octet* block1;			/* [16] */
	void* stack;
	// проверить входные данные
	if (!memIsValid(s, sizeof(bake_bmqv_st)) || !ecIsOperable(s->ec))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(in, 2 * no) ||
		!memIsValid(out, 2 * no + (s->settings->kca ? 8u : 0)) ||
		!memIsValid(certb, sizeof(bake_cert)) ||
		!memIsValid(certb->data, certb->len) ||
		certb->val == 0)
		return ERR_BAD_INPUT;
	// разметить стек
	memSlice(s->stack,
		bakeBMQVStep3_local(n, no), SIZE_0, SIZE_MAX,
		&Qb, &K, &Va, &Vb, &t, &block0, &sa, &block1, &stack);
	// проверить certb
	code = certb->val((octet*)Qb, s->params, certb->data, certb->len);
	ERR_CALL_CHECK(code);
	if (!qrFrom(ecX(Qb), (octet*)Qb, s->ec->f, stack) ||
		!qrFrom(ecY(Qb, n), (octet*)Qb + no, s->ec->f, stack) ||
		!ecpIsOnA(Qb, s->ec, stack))
		return ERR_BAD_CERT;
	// Vb <- in, Vb \in E*?
	if (!qrFrom(ecX(Vb), in, s->ec->f, stack) ||
		!qrFrom(ecY(Vb, n), in + no, s->ec->f, stack) ||
		!ecpIsOnA(Vb, s->ec, stack))
		return ERR_BAD_POINT;
	// ua <-R {1, 2, ..., q - 1}
	if (!zzRandNZMod(s->u, s->ec->order, n, s->settings->rng,
		s->settings->rng_state))
		return ERR_BAD_RNG;
	// Va <- ua G
	if (!ecMulA(Va, s->ec->base, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	qrTo((octet*)Va, ecX(Va), s->ec->f, stack);
	qrTo((octet*)Va + no, ecY(Va, n), s->ec->f, stack);
	// t <- <beltHash(<Va>_2l || <Vb>_2l)>_l
	beltHashStart(stack);
	beltHashStepH(Va, no, stack);
	beltHashStepH(in, no, stack);
	beltHashStepG2((octet*)t, no / 2, stack);
	wwFrom(t, t, no / 2);
	// out <- <Va>_4l
	memCopy(out, Va, 2 * no);
	// sa <- (ua - (2^l + t)da) \mod q
	zzMul(sa, t, n / 2, s->d, n, stack);
	sa[n + n / 2] = zzAdd2(sa + n / 2, s->d, n);
	zzMod(sa, sa, n + n / 2 + 1, s->ec->order, n, stack);
	zzSubMod(sa, s->u, sa, s->ec->order, n);
	// K <- sa(Vb - (2^l + t)Qb), K == O => K <- G
	t[n / 2] = 1;
	if (!ecMulA(Qb, Qb, s->ec, t, n / 2 + 1, stack))
		return ERR_BAD_PARAMS;
	if (!ecpSubAA(Vb, Vb, Qb, s->ec, stack))
		qrTo(K, s->ec->base, s->ec->f, stack);
	else
	{
		if (!ecMulA(Vb, Vb, s->ec, sa, n, stack))
			return ERR_BAD_PARAMS;
		qrTo(K, ecX(Vb), s->ec->f, stack);
	}
	// K <- beltHash(<K>_2l || certa || certb || helloa || hellob)
	beltHashStart(stack);
	beltHashStepH(K, no, stack);
	beltHashStepH(s->cert->data, s->cert->len, stack);
	beltHashStepH(certb->data, certb->len, stack);
	if (s->settings->helloa)
		beltHashStepH(s->settings->helloa, s->settings->helloa_len, stack);
	if (s->settings->hellob)
		beltHashStepH(s->settings->hellob, s->settings->hellob_len, stack);
	beltHashStepG(K, stack);
	// K0 <- beltKRP(K, 1^96, 0)
	memSetZero(block0, 16);
	memSet(block1, 0xFF, 16);
	beltKRPStart(stack, K, 32, block1);
	beltKRPStepG(s->K0, 32, block0, stack);
	// K1 <- beltKRP(K, 1^96, 1)
	if (s->settings->kca || s->settings->kcb)
	{
		block0[0] = 1;
		beltKRPStepG(s->K1, 32, block0, stack);
	}
	// Ta <- beltMAC(0^128, K1), ...|| out <- Ta
	if (s->settings->kca)
	{
		block0[0] = 0;
		beltMACStart(stack, s->K1, 32);
		beltMACStepA(block0, 16, stack);
		beltMACStepG(out + 2 * no, stack);
	}
	// завершение
	return ERR_OK;
}

static size_t bakeBMQVStep3_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return memSliceSize(
		bakeBMQVStep3_local(n, O_OF_W(n)),
		utilMax(9,
			f_deep,
			ecpIsOnA_deep(n, f_deep),
			ecMulA_deep(n, ec_d, ec_deep, n),
			beltHash_keep(),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n),
			ecpSubAA_deep(n, f_deep),
			beltKRP_keep(),
			beltMAC_keep()),
		SIZE_MAX);
}

#define bakeBMQVStep4_local(n, no)\
/* Qa */		O_OF_W(2 * n),\
/* K */			no | SIZE_HI,\
/* Va */		O_OF_W(2 * n),\
/* t */			O_OF_W(n / 2 + 1),\
/* block0 */	(size_t)16 | SIZE_HI,\
/* sb */		O_OF_W(n + n / 2 + 1),\
/* block1 */	(size_t)16 | SIZE_HI

err_t bakeBMQVStep4(octet out[], const octet in[], const bake_cert* certa,
	void* state)
{
	err_t code;
	bake_bmqv_st* s = (bake_bmqv_st*)state;
	size_t n, no;
	word* Qa;				/* [2 * n] */
	word* Va;				/* [2 * n] */
	word* t;				/* [n / 2 + 1] */
	word* sb;				/* [n + n / 2 + 1] */
	octet* K;				/* [no] */
	octet* block0;			/* [16] */
	octet* block1;			/* [16] */
	void* stack;
	// проверить входные данные
	if (!memIsValid(s, sizeof(bake_bmqv_st)) || !ecIsOperable(s->ec))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(in, 2 * no + (s->settings->kca ? 8u : 0)) ||
		!memIsValid(out, s->settings->kcb ? 8u : 0) ||
		!memIsValid(certa, sizeof(bake_cert)) ||
		!memIsValid(certa->data, certa->len) ||
		certa->val == 0)
		return ERR_BAD_INPUT;
	// разметить стек
	memSlice(s->stack,
		bakeBMQVStep4_local(n, no), SIZE_0, SIZE_MAX,
		&Qa, &K, &Va, &t, &block0, &sb, &block1, &stack);
	// проверить certa
	code = certa->val((octet*)Qa, s->params, certa->data, certa->len);
	ERR_CALL_CHECK(code);
	if (!qrFrom(ecX(Qa), (octet*)Qa, s->ec->f, stack) ||
		!qrFrom(ecY(Qa, n), (octet*)Qa + no, s->ec->f, stack) ||
		!ecpIsOnA(Qa, s->ec, stack))
		return ERR_BAD_CERT;
	// Va <- in, Va \in E*?
	if (!qrFrom(ecX(Va), in, s->ec->f, stack) ||
		!qrFrom(ecY(Va, n), in + no, s->ec->f, stack) ||
		!ecpIsOnA(Va, s->ec, stack))
		return ERR_BAD_POINT;
	// t <- <beltHash(<Va>_2l || <Vb>_2l)>_l
	beltHashStart(stack);
	beltHashStepH(in, no, stack);
	beltHashStepH(s->Vb, no, stack);
	beltHashStepG2((octet*)t, no / 2, stack);
	wwFrom(t, t, no / 2);
	// sb <- (ub - (2^l + t)db) \mod q
	zzMul(sb, t, n / 2, s->d, n, stack);
	sb[n + n / 2] = zzAdd2(sb + n / 2, s->d, n);
	zzMod(sb, sb, n + n / 2 + 1, s->ec->order, n, stack);
	zzSubMod(sb, s->u, sb, s->ec->order, n);
	// K <- sb(Va - (2^l + t)Qa), K == O => K <- G
	t[n / 2] = 1;
	if (!ecMulA(Qa, Qa, s->ec, t, n / 2 + 1, stack))
		return ERR_BAD_PARAMS;
	if (!ecpSubAA(Va, Va, Qa, s->ec, stack))
		qrTo(K, s->ec->base, s->ec->f, stack);
	else
	{
		if (!ecMulA(Va, Va, s->ec, sb, n, stack))
			return ERR_BAD_PARAMS;
		qrTo(K, ecX(Va), s->ec->f, stack);
	}
	// K <- beltHash(<K>_2l || certa || certb || helloa || hellob)
	beltHashStart(stack);
	beltHashStepH(K, no, stack);
	beltHashStepH(certa->data, certa->len, stack);
	beltHashStepH(s->cert->data, s->cert->len, stack);
	if (s->settings->helloa)
		beltHashStepH(s->settings->helloa, s->settings->helloa_len, stack);
	if (s->settings->hellob)
		beltHashStepH(s->settings->hellob, s->settings->hellob_len, stack);
	beltHashStepG(K, stack);
	// K0 <- beltKRP(K, 1^96, 0)
	memSetZero(block0, 16);
	memSet(block1, 0xFF, 16);
	beltKRPStart(stack, K, 32, block1);
	beltKRPStepG(s->K0, 32, block0, stack);
	// K1 <- beltKRP(K, 1^96, 1)
	if (s->settings->kca || s->settings->kcb)
	{
		block0[0] = 1;
		beltKRPStepG(s->K1, 32, block0, stack);
	}
	// Ta == beltMAC(0^128, K1)?
	if (s->settings->kca)
	{
		block0[0] = 0;
		beltMACStart(stack, s->K1, 32);
		beltMACStepA(block0, 16, stack);
		if (!beltMACStepV(in + 2 * no, stack))
			return ERR_AUTH;
	}
	// Tb <- beltMAC(1^128, K1)?
	if (s->settings->kcb)
	{
		beltMACStart(stack, s->K1, 32);
		beltMACStepA(block1, 16, stack);
		beltMACStepG(out, stack);
	}
	// завершение
	return ERR_OK;
}

static size_t bakeBMQVStep4_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return memSliceSize(
		bakeBMQVStep4_local(n, O_OF_W(n)),
		utilMax(9,
				f_deep,
				ecpIsOnA_deep(n, f_deep),
				ecMulA_deep(n, ec_d, ec_deep, n),
				beltHash_keep(),
				zzMul_deep(n / 2, n),
				zzMod_deep(n + n / 2 + 1, n),
				ecpSubAA_deep(n, f_deep),
				beltKRP_keep(),
				beltMAC_keep()),
		SIZE_MAX);
}

#define bakeBMQVStep5_local()\
/* block1 */	(size_t)16

err_t bakeBMQVStep5(const octet in[8], void* state)
{
	bake_bmqv_st* s = (bake_bmqv_st*)state;
	octet* block1;			/* [16] */
	void* stack;
	// проверить входные данные
	if (!memIsValid(s, sizeof(bake_bmqv_st)) || !memIsValid(in, 8))
		return ERR_BAD_INPUT;
	if (!s->settings->kcb)
		return ERR_BAD_LOGIC;
	// разметить стек
	memSlice(s->stack,
		bakeBMQVStep5_local(), SIZE_0, SIZE_MAX,
		&block1, &stack);
	// Tb == beltMAC(1^128, K1)?
	memSet(block1, 0xFF, 16);
	beltMACStart(stack, s->K1, 32);
	beltMACStepA(block1, 16, stack);
	if (!beltMACStepV(in, stack))
		return ERR_AUTH;
	// завершение
	return ERR_OK;
}

static size_t bakeBMQVStep5_deep()
{
	return memSliceSize(
		bakeBMQVStep5_local(),
		beltMAC_keep(),
		SIZE_MAX);
}

err_t bakeBMQVStepG(octet key[32], void* state)
{
	bake_bmqv_st* s = (bake_bmqv_st*)state;
	// проверить входные данные
	if (!memIsValid(s, sizeof(bake_bmqv_st)) || !ecIsOperable(s->ec) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// key <- K0
	memCopy(key, s->K0, 32);
	// завершение
	return ERR_OK;
}

static size_t bakeBMQV_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return utilMax(5,
		bakeBMQVStart_deep(n, f_deep),
		bakeBMQVStep2_deep(n, f_deep, ec_d, ec_deep),
		bakeBMQVStep3_deep(n, f_deep, ec_d, ec_deep),
		bakeBMQVStep4_deep(n, f_deep, ec_d, ec_deep),
		bakeBMQVStep5_deep());
}

/*
*******************************************************************************
Выполнение BMQV
*******************************************************************************
*/

err_t bakeBMQVRunB(octet key[32], const bign_params* params,
	const bake_settings* settings, const octet privkeyb[],
	const bake_cert* certb, const bake_cert* certa,
	read_i read, write_i write, void* file)
{
	err_t code;
	size_t len;
	// блоб
	blob_t blob;
	octet* in;			/* [l / 2 + 8] */
	octet* out;			/* [l / 2] */
	void* state;		/* [bakeBMQV_keep(l)] */
	// проверить key
	if (!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// создать блоб
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	blob = blobCreate2(
		params->l / 2 + 8,
		params->l / 2,
		bakeBMQV_keep(params->l),
		SIZE_MAX,
		&in, &out, &state);
	if (blob == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bakeBMQVStart(state, params, settings, privkeyb, certb);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 2
	code = bakeBMQVStep2(out, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = write(&len, out, params->l / 2, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 4
	code = read(&len, in, params->l / 2 + (settings->kca ? 8u : 0), file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = bakeBMQVStep4(out, in, certa, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	if (settings->kcb)
	{
		code = write(&len, out, 8, file);
		ERR_CALL_HANDLE(code, blobClose(blob));
	}
	// завершение
	code = bakeBMQVStepG(key, state);
	blobClose(blob);
	return code;
}

err_t bakeBMQVRunA(octet key[32], const bign_params* params,
	const bake_settings* settings, const octet privkeya[],
	const bake_cert* certa, const bake_cert* certb,
	read_i read, write_i write, void* file)
{
	err_t code;
	size_t len;
	// блоб
	blob_t blob;
	octet* in;			/* [l / 2] */
	octet* out;			/* [l / 2 + 8] */
	void* state;		/* [bakeBMQV_keep(l)] */
	// проверить key
	if (!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// создать блоб
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	blob = blobCreate2(
		params->l / 2,
		params->l / 2 + 8,
		bakeBMQV_keep(params->l),
		SIZE_MAX,
		&in, &out, &state);
	if (blob == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bakeBMQVStart(state, params, settings, privkeya, certa);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 3
	code = read(&len, in, params->l / 2, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = bakeBMQVStep3(out, in, certb, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = write(&len, out, params->l / 2 + (settings->kca ? 8u : 0), file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 5
	if (settings->kcb)
	{
		code = read(&len, in, 8, file);
		ERR_CALL_HANDLE(code, blobClose(blob));
		code = bakeBMQVStep5(in, state);
		ERR_CALL_HANDLE(code, blobClose(blob));
	}
	// завершение
	code = bakeBMQVStepG(key, state);
	blobClose(blob);
	return code;
}
