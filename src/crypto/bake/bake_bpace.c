/*
*******************************************************************************
\file bake_bpace.c
\brief STB 34.101.66 (bake): the BPACE protocol
\project bee2 [cryptographic library]
\created 2014.04.14
\version 2025.10.22
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
#include "bake_lcl.h"

/*
*******************************************************************************
Алгоритм bakeSWU
*******************************************************************************
*/

#define bakeSWUEc_local(n, no)\
/* H */		no + 16,\
/* s */		O_OF_W(n + W_OF_O(16)) | SIZE_HI

static void bakeSWUEc(word W[], const ec_o* ec, const octet X[], void* stack)
{
	octet* H;	/* [no + 16] */
	word* s;	/* [n + W_OF_O(16)] (|H) */
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(memIsValid(X, ec->f->no));
	ASSERT(wwIsValid(W, 2 * ec->f->n));
	// разметить стек
	memSlice(stack,
		bakeSWUEc_local(ec->f->n, ec->f->no), SIZE_0, SIZE_MAX,
		&H, &s, &stack);
	// H <- beltWBL(X, 0, 0)
	memSetZero(H + ec->f->no, 16);
	beltWBLStart(stack, H + ec->f->no, 16);
	memCopy(H, X, ec->f->no);
	beltWBLStepE(H, ec->f->no + 16, stack);
	// s <- \bar H mod p
	wwFrom(s, H, ec->f->no + 16);
	zzMod(s, s, ec->f->n + W_OF_O(16), ec->f->mod, ec->f->n, stack);
	// W <- ecpSWU(s)
	wwTo(H, ec->f->no, s);
	qrFrom(s, H, ec->f, stack);
	ecpSWU(W, s, ec, stack);
}

static size_t bakeSWUEc_deep(size_t n, size_t f_deep)
{
	return memSliceSize(
		bakeSWUEc_local(n, O_OF_W(n)),
		utilMax(2,
			zzMod_deep(n + W_OF_O(16), n),
			ecpSWU_deep(n, f_deep)),
		SIZE_MAX);
}

err_t bakeSWU(octet pt[], const bign_params* params, const octet msg[])
{
	err_t code;
	ec_o* ec;
	void* state;
	word* W;			/* [2 * n] */
	void* stack;
	// входной контроль
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	if (!memIsValid(msg, params->l / 4) || !memIsValid(pt, params->l / 2))
		return ERR_BAD_INPUT;
	// создать кривую
	code = bignEcCreate(&ec, params);
	ERR_CALL_CHECK(code);
	// создать состояние
	state = blobCreate2(
		O_OF_W(2 * ec->f->n),
		bakeSWUEc_deep(ec->f->n, ec->f->deep),
		SIZE_MAX,
		&W, &stack);
	if (state == 0)
	{
		bignEcClose(ec);
		return ERR_OUTOFMEMORY;
	}
	// вычислить точку
	bakeSWUEc(W, ec, msg, stack);
	wwTo(pt, 2 * ec->f->no, W);
	// завершение
	blobClose(state);
	bignEcClose(ec);
	return ERR_OK;
}

/*
*******************************************************************************
Шаги протокола BPACE

\todo Контроль последовательности выполнения шагов?
*******************************************************************************
*/

typedef struct
{
	bake_settings settings[1];	/*< настройки */
	octet K0[32];				/*< ключ K0 */
	octet K1[32];				/*< ключ K1 */
	octet K2[32];				/*< ключ K2 */
	ec_o* ec;					/*< эллиптическая кривая */
	octet* R;					/*< [no] (Ra || Rb или ecX(Va)) */
	word* W;					/*< [2 * n] точка W */
	word* u;					/*< [n] ua или ub */
	void* stack;				/*< [bakeBPACE_deep] стек */
	mem_align_t data[];			/*< данные */
} bake_bpace_st;

static size_t bakeBPACE_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep); 

#define bakeBPACE_state(n, no)\
/* R */			no,\
/* W */			O_OF_W(2 * n),\
/* u */			O_OF_W(n)

size_t bakeBPACE_keep(size_t l)
{
	const size_t n = W_OF_B(2 * l);
	const size_t no = O_OF_B(2 * l);
	return sizeof(bake_bpace_st) +
		memSliceSize(
			bakeEcStart_keep(l, bakeBPACE_deep),
			bakeBPACE_state(n, no),
			SIZE_MAX);
}

err_t bakeBPACEStart(void* state, const bign_params* params,
	const bake_settings* settings, const octet pwd[], size_t pwd_len)
{
	err_t code;
	bake_bpace_st* s = (bake_bpace_st*)state;
	size_t n, no;
	void* stack;
	// входной контроль
	code = bignParamsCheck(params);
	ERR_CALL_CHECK(code);
	if (!memIsValid(settings, sizeof(bake_settings)) ||
		!memIsNullOrValid(settings->helloa, settings->helloa_len) ||
		!memIsNullOrValid(settings->hellob, settings->hellob_len) ||
		!memIsValid(pwd, pwd_len))
		return ERR_BAD_INPUT;
	if (settings->rng == 0)
		return ERR_BAD_RNG;
	// развернуть кривую
	code = bakeEcStart(s->data, params);
	ERR_CALL_CHECK(code);
	memSlice(s->data,
		objKeep(s->data), SIZE_0, SIZE_MAX,
		&s->ec, &stack);
	n = s->ec->f->n, no = s->ec->f->no;
	// разметить состояние
	memSlice(stack,
		bakeBPACE_state(n, no), SIZE_0, SIZE_0, SIZE_MAX,
		&s->R, &s->W, &s->u, &s->stack, &stack);
	// загрузить настройки
	memCopy(s->settings, settings, sizeof(bake_settings));
	// K2 <- beltHash(pwd)
	beltHashStart(stack);
	beltHashStepH(pwd, pwd_len, stack);
	beltHashStepG(s->K2, stack);
	// завершение
	return code;
}

static size_t bakeBPACEStart_deep()
{
	return beltHash_keep();
}

err_t bakeBPACEStep2(octet out[], void* state)
{
	bake_bpace_st* s = (bake_bpace_st*)state;
	size_t no;
	void* stack;
	// обработать входные данные
	if (!memIsValid(s, sizeof(bake_bpace_st)) || !ecIsOperable(s->ec))
		return ERR_BAD_INPUT;
	no = s->ec->f->no;
	if (!memIsValid(out, no / 2))
		return ERR_BAD_INPUT;
	// разметить стек
	stack = s->stack;
	// Rb <-R {0, 1}^l
	s->settings->rng(out, no / 2, s->settings->rng_state);
	memCopy(s->R + no / 2, out, no / 2);
	// out <- beltECB(Rb, K2)
	beltECBStart(stack, s->K2, 32);
	beltECBStepE(out, no / 2, stack);
	// завершение
	return ERR_OK;
}

static size_t bakeBPACEStep2_deep()
{
	return beltECB_keep();
}

#define bakeBPACEStep3_local(n)\
/* Va */		O_OF_W(2 * n)

err_t bakeBPACEStep3(octet out[], const octet in[], void* state)
{
	bake_bpace_st* s = (bake_bpace_st*)state;
	size_t n, no;
	word* Va;				/* [2 * n] */
	void* stack;
	// обработать входные данные
	if (!memIsValid(s, sizeof(bake_bpace_st)) || !ecIsOperable(s->ec))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(in, no / 2) ||
		!memIsValid(out, 5 * no / 2))
		return ERR_BAD_INPUT;
	// разметить стек
	memSlice(s->stack,
		bakeBPACEStep3_local(n), SIZE_0, SIZE_MAX,
		&Va, &stack);
	// Rb <- beltECBDecr(Yb, K2)
	memCopy(s->R + no / 2, in, no / 2);
	beltECBStart(stack, s->K2, 32);
	beltECBStepD(s->R + no / 2, no / 2, stack);
	// Ra <-R {0, 1}^l
	s->settings->rng(out, no / 2, s->settings->rng_state);
	memCopy(s->R, out, no / 2);
	// out ||... <- beltECBEncr(Ra, K2)
	beltECBStart(stack, s->K2, 32);
	beltECBStepE(out, no / 2, stack);
	// W <- bakeSWU(Ra || Rb)
	bakeSWUEc(s->W, s->ec, s->R, stack);
	// ua <-R {1, 2, ..., q - 1}
	if (!zzRandNZMod(s->u, s->ec->order, n, s->settings->rng,
		s->settings->rng_state))
		return ERR_BAD_RNG;
	// Va <- ua W
	if (!ecMulA(Va, s->W, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	// ...|| out <- <Va>
	qrTo(out + no / 2, ecX(Va), s->ec->f, stack);
	qrTo(out + 3 * no / 2, ecY(Va, n), s->ec->f, stack);
	// сохранить x-координату Va
	memCopy(s->R, out + no / 2, no);
	// завершение
	return ERR_OK;
}

static size_t bakeBPACEStep3_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return memSliceSize(
		bakeBPACEStep3_local(n),
		utilMax(4,
			beltECB_keep(),
			bakeSWUEc_deep(n, f_deep),
			ecMulA_deep(n, ec_d, ec_deep, n),
			f_deep),
		SIZE_MAX);
}

#define bakeBPACEStep4_local(n)\
/* Va */		O_OF_W(2 * n),\
/* K */			O_OF_W(2 * n) | SIZE_HI,\
/* Y */			(size_t)32 | SIZE_HI,\
/* Vb */		O_OF_W(2 * n),\
/* block0 */	(size_t)16 | SIZE_HI,\
/* block1 */	(size_t)16

err_t bakeBPACEStep4(octet out[], const octet in[], void* state)
{
	bake_bpace_st* s = (bake_bpace_st*)state;
	size_t n, no;
	word* Va;			/* [2 * n] */
	word* K;			/* [2 * n] (|Va) */
	octet* Y;			/* [32] (|K) */
	word* Vb;			/* [2 * n] */
	octet* block0;		/* [16] (|Vb) */
	octet* block1;		/* [16] */
	void* stack;
	// обработать входные данные
	if (!memIsValid(s, sizeof(bake_bpace_st)) || !ecIsOperable(s->ec))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(in, 5 * no / 2) ||
		!memIsValid(out, 2 * no + (s->settings->kcb ? 8u : 0)))
		return ERR_BAD_INPUT;
	// разметить стек
	memSlice(s->stack,
		bakeBPACEStep4_local(n), SIZE_0, SIZE_MAX,
		&Va, &K, &Y, &Vb, &block0, &block1, &stack);
	// Va <- ... || in, Va \in E*?
	if (!qrFrom(ecX(Va), in + no / 2, s->ec->f, stack) ||
		!qrFrom(ecY(Va, n), in + no / 2 + no, s->ec->f, stack) ||
		!ecpIsOnA(Va, s->ec, stack))
		return ERR_BAD_POINT;
	// Ra <- beltECBDecr(in ||..., K2)
	memCopy(s->R, in, no / 2);
	beltECBStart(stack, s->K2, 32);
	beltECBStepD(s->R, no / 2, stack);
	// W <- bakeSWU(Ra || Rb)
	bakeSWUEc(s->W, s->ec, s->R, stack);
	// ub <-R {1, 2, ..., q - 1}
	if (!zzRandNZMod(s->u, s->ec->order, n, s->settings->rng,
		s->settings->rng_state))
		return ERR_BAD_RNG;
	// K <- ub Va
	if (!ecMulA(K, Va, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	qrTo((octet*)K, ecX(K), s->ec->f, stack);
	// Vb <- ub W
	if (!ecMulA(Vb, s->W, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	qrTo((octet*)ecX(Vb), ecX(Vb), s->ec->f, stack);
	qrTo((octet*)ecY(Vb, n), ecY(Vb, n), s->ec->f, stack);
	// Y <- beltHash(<K>_2l || <Va>_2l || <Vb>_2l || helloa || hellob)
	beltHashStart(stack);
	beltHashStepH(K, no, stack);
	beltHashStepH(in + no / 2, no, stack);
	beltHashStepH(Vb, no, stack);
	if (s->settings->helloa)
		beltHashStepH(s->settings->helloa, s->settings->helloa_len, stack);
	if (s->settings->hellob)
		beltHashStepH(s->settings->hellob, s->settings->hellob_len, stack);
	beltHashStepG(Y, stack);
	// out ||... <- <Vb>
	memCopy(out, ecX(Vb), no);
	memCopy(out + no, ecY(Vb, n), no);
	// K0 <- beltKRP(Y, 1^96, 0)
	memSetZero(block0, 16);
	memSet(block1, 0xFF, 16);
	beltKRPStart(stack, Y, 32, block1);
	beltKRPStepG(s->K0, 32, block0, stack);
	// K1 <- beltKRP(Y, 1^96, 1)
	if (s->settings->kca || s->settings->kcb)
	{
		block0[0] = 1;
		beltKRPStepG(s->K1, 32, block0, stack);
	}
	// Tb <- beltMAC(1^128, K1), ...|| out <- Tb
	if (s->settings->kcb)
	{
		beltMACStart(stack, s->K1, 32);
		beltMACStepA(block1, 16, stack);
		beltMACStepG(out + 2 * no, stack);
	}
	// завершение
	return ERR_OK;
}

static size_t bakeBPACEStep4_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return memSliceSize(
		bakeBPACEStep4_local(n),
		utilMax(7,
			f_deep,
			beltECB_keep(),
			bakeSWUEc_deep(n, f_deep),
			ecMulA_deep(n, ec_d, ec_deep, n),
			beltHash_keep(),
			beltKRP_keep(),
			beltMAC_keep()),
		SIZE_MAX);
}

#define bakeBPACEStep5_local(n)\
/* Vb */		O_OF_W(2 * n),\
/* K */			O_OF_W(2 * n),\
/* Y */			(size_t)32,\
/* block0 */	(size_t)16,\
/* block1 */	(size_t)16

err_t bakeBPACEStep5(octet out[], const octet in[], void* state)
{
	bake_bpace_st* s = (bake_bpace_st*)state;
	size_t n, no;
	word* Vb;			/* [2 * n] */
	word* K;			/* [2 * n] */
	octet* Y;			/* [32] */
	octet* block0;		/* [16] */
	octet* block1;		/* [16] */
	void* stack;
	// обработать входные данные
	if (!memIsValid(s, sizeof(bake_bpace_st)) || !ecIsOperable(s->ec))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(in, 2 * no + (s->settings->kcb ? 8u : 0)) ||
		!memIsValid(out, s->settings->kca ? 8u : 0))
		return ERR_BAD_INPUT;
	// разметить стек
	memSlice(s->stack,
		bakeBPACEStep5_local(n), SIZE_0, SIZE_MAX,
		&Vb, &K, &Y, &block0, &block1, &stack);
	// Vb <- in ||..., Vb \in E*?
	if (!qrFrom(ecX(Vb), in, s->ec->f, stack) ||
		!qrFrom(ecY(Vb, n), in + no, s->ec->f, stack) ||
		!ecpIsOnA(Vb, s->ec, stack))
		return ERR_BAD_POINT;
	// K <- ua Vb
	if (!ecMulA(K, Vb, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	qrTo((octet*)K, ecX(K), s->ec->f, stack);
	qrTo((octet*)Vb, ecX(Vb), s->ec->f, stack);
	// Y <- beltHash(<K>_2l || <Va>_2l || <Vb>_2l || helloa || hellob)
	beltHashStart(stack);
	beltHashStepH(K, no, stack);
	beltHashStepH(s->R, no, stack);
	beltHashStepH(Vb, no, stack);
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
	if (s->settings->kca || s->settings->kcb)
	{
		block0[0] = 1;
		beltKRPStepG(s->K1, 32, block0, stack);
	}
	// Tb == beltMAC(1^128, K1)?
	if (s->settings->kcb)
	{
		beltMACStart(stack, s->K1, 32);
		beltMACStepA(block1, 16, stack);
		if (!beltMACStepV(in + 2 * no, stack))
			return ERR_AUTH;
	}
	// Ta <- beltMAC(0^128, K1)
	if (s->settings->kca)
	{
		block0[0] = 0;
		beltMACStart(stack, s->K1, 32);
		beltMACStepA(block0, 16, stack);
		beltMACStepG(out, stack);
	}
	// завершение
	return ERR_OK;
}

static size_t bakeBPACEStep5_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return memSliceSize(
		bakeBPACEStep5_local(n),
		utilMax(5,
			f_deep,
			ecMulA_deep(n, ec_d, ec_deep, n),
			beltHash_keep(),
			beltKRP_keep(),
			beltMAC_keep()),
		SIZE_MAX);
}

#define bakeBPACEStep6_local()\
/* block0 */	(size_t)16

err_t bakeBPACEStep6(const octet in[8], void* state)
{
	bake_bpace_st* s = (bake_bpace_st*)state;
	octet* block0;	/* [16] */
	void* stack;
	// обработать входные данные
	if (!memIsValid(s, sizeof(bake_bpace_st)) || !ecIsOperable(s->ec))
		return ERR_BAD_INPUT;
	if (!s->settings->kca)
		return ERR_BAD_LOGIC;
	if (!memIsValid(in, 8))
		return ERR_BAD_INPUT;
	// разметить стек
	memSlice(s->stack,
		bakeBPACEStep6_local(), SIZE_0, SIZE_MAX,
		&block0, &stack);
	// Ta == beltMAC(0^128, K1)?
	memSetZero(block0, 16);
	beltMACStart(stack, s->K1, 32);
	beltMACStepA(block0, 16, stack);
	if (!beltMACStepV(in, stack))
		return ERR_AUTH;
	// завершение
	return ERR_OK;
}

static size_t bakeBPACEStep6_deep()
{
	return memSliceSize(
		bakeBPACEStep6_local(),
		beltMAC_keep(),
		SIZE_MAX);
}

err_t bakeBPACEStepG(octet key[32], void* state)
{
	bake_bpace_st* s = (bake_bpace_st*)state;
	// проверить входные данные
	if (!memIsValid(s, sizeof(bake_bpace_st)) || !ecIsOperable(s->ec) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// key <- K0
	memCopy(key, s->K0, 32);
	// завершение
	return ERR_OK;
}

static size_t bakeBPACE_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return utilMax(6,
		bakeBPACEStart_deep(),
		bakeBPACEStep2_deep(),
		bakeBPACEStep3_deep(n, f_deep, ec_d, ec_deep),
		bakeBPACEStep4_deep(n, f_deep, ec_d, ec_deep),
		bakeBPACEStep5_deep(n, f_deep, ec_d, ec_deep),
		bakeBPACEStep6_deep());
}

/*
*******************************************************************************
Выполнение BPACE
*******************************************************************************
*/

err_t bakeBPACERunB(octet key[32], const bign_params* params,
	const bake_settings* settings, const octet pwd[], size_t pwd_len,
	read_i read, write_i write, void* file)
{
	err_t code;
	size_t len;
	// блоб
	blob_t blob;
	octet* in;			/* [5 * l / 8] */
	octet* out;			/* [l / 2 + 8] */
	void* state;		/* [bakeBPACE_keep(l)] */
	// проверить key
	if (!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// создать блоб
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	blob = blobCreate2( 
		5 * params->l / 8,
		params->l / 2 + 8,
		bakeBPACE_keep(params->l),
		SIZE_MAX,
		&in, &out, &state);
	if (blob == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bakeBPACEStart(state, params, settings, pwd, pwd_len);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 2
	code = bakeBPACEStep2(out, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = write(&len, out, params->l / 8, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 4
	code = read(&len, in, 5 * params->l / 8, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = bakeBPACEStep4(out, in, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = write(&len, out, params->l / 2 + (settings->kcb ? 8u : 0), file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 6
	if (settings->kca)
	{
		code = read(&len, in, 8, file);
		ERR_CALL_HANDLE(code, blobClose(blob));
		code = bakeBPACEStep6(in, state);
		ERR_CALL_HANDLE(code, blobClose(blob));
	}
	// завершение
	code = bakeBPACEStepG(key, state);
	blobClose(blob);
	return code;
}

err_t bakeBPACERunA(octet key[32], const bign_params* params,
	const bake_settings* settings, const octet pwd[], size_t pwd_len,
	read_i read, write_i write, void* file)
{
	err_t code;
	size_t len;
	// блоб
	blob_t blob;
	octet* in;			/* [l / 2 + 8] */
	octet* out;			/* [5 * l / 8] */
	void* state;		/* [bakeBPACE_keep(l)] */
	// проверить key
	if (!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// создать блоб
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	blob = blobCreate2(
		params->l / 2 + 8,
		5 * params->l / 8,
		bakeBPACE_keep(params->l),
		SIZE_MAX,
		&in, &out, &state);
	if (blob == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bakeBPACEStart(state, params, settings, pwd, pwd_len);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 3
	code = read(&len, in, params->l / 8, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = bakeBPACEStep3(out, in, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = write(&len, out, 5 * params->l / 8, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 5
	code = read(&len, in, params->l / 2 + (settings->kcb ? 8u : 0), file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = bakeBPACEStep5(out, in, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	if (settings->kca)
	{
		code = write(&len, out, 8, file);
		ERR_CALL_HANDLE(code, blobClose(blob));
	}
	// завершение
	code = bakeBPACEStepG(key, state);
	blobClose(blob);
	return code;
}
