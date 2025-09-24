/*
*******************************************************************************
\file bake_bsts.c
\brief STB 34.101.66 (bake): the BSTS protocol
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
Шаги протокола BSTS

\todo Контроль последовательности выполнения шагов?
*******************************************************************************
*/

typedef struct
{
	obj_hdr_t hdr;				/*< заголовок */
// ptr_table {
	ec_o* ec;					/*< описание эллиптической кривой */
	word* d;					/*< [ec->f->n] долговременный личный ключ */
	word* u;					/*< [ec->f->n] одноразовый личный ключ */
	word* t;					/*< [ec->f->n / 2 + 1] t (совпадает с u) */
	word* Vb;					/*< [2 * ec->f->n] Vb */
// }
	bign_params params[1];		/*< параметры */
	bake_settings settings[1];	/*< настройки */
	bake_cert cert[1];			/*< сертификат */
	octet K0[32];				/*< ключ K0 */
	octet K1[32];				/*< ключ K1 */
	octet K2[32];				/*< ключ K2 */
	octet data[];				/*< данные */
} bake_bsts_o;

static size_t bakeBSTS_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep);

size_t bakeBSTS_keep(size_t l)
{
	const size_t n = W_OF_B(2 * l);
	return sizeof(bake_bsts_o) +
		bignStart_keep(l, bakeBSTS_deep) +
		O_OF_W(4 * n);
}

err_t bakeBSTSStart(void* state, const bign_params* params,
	const bake_settings* settings, const octet privkey[],
	const bake_cert* cert)
{
	err_t code;
	bake_bsts_o* s = (bake_bsts_o*)state;
	size_t n, no;
	word* Q;
	// стек
	void* stack;
	// проверить входные данные
	if (!memIsValid(params, sizeof(bign_params)) ||
		!memIsValid(settings, sizeof(bake_settings)) ||
		settings->kca != TRUE || settings->kcb != TRUE ||
		!memIsNullOrValid(settings->helloa, settings->helloa_len) ||
		!memIsNullOrValid(settings->hellob, settings->hellob_len))
		return ERR_BAD_INPUT;
	if (bignParamsCheck(params) != ERR_OK)
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
	s->t = s->u;
	s->Vb = s->u + n;
	// настроить заголовок
	s->hdr.keep = sizeof(bake_bsts_o) + objKeep(s->ec) + O_OF_W(4 * n);
	s->hdr.p_count = 5;
	s->hdr.o_count = 1;
	// загрузить личный ключ
	wwFrom(s->d, privkey, no);
	// раскладка стека
	stack = objEnd(s, void);
	// проверить сертификат и его открытый ключ
	Q = s->Vb;
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

static size_t bakeBSTSStart_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return utilMax(2,
			f_deep,
			ecpIsOnA_deep(n, f_deep));
}

err_t bakeBSTSStep2(octet out[], void* state)
{
	bake_bsts_o* s = (bake_bsts_o*)state;
	size_t n, no;
	// стек
	void* stack;
	// обработать входные данные
	if (!objIsOperable(s))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(out, 2 * no))
		return ERR_BAD_INPUT;
	// раскладка стека
	stack = objEnd(s, void);
	// ub <-R {1, 2, ..., q - 1}
	if (!zzRandNZMod(s->u, s->ec->order, n, s->settings->rng,
		s->settings->rng_state))
		return ERR_BAD_RNG;
	// Vb <- ub G
	if (!ecMulA(s->Vb, s->ec->base, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	// out <- <Vb>
	qrTo(out, ecX(s->Vb), s->ec->f, stack);
	qrTo(out + no, ecY(s->Vb, n), s->ec->f, stack);
	// завершение
	return ERR_OK;
}

static size_t bakeBSTSStep2_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return utilMax(2,
			f_deep,
			ecMulA_deep(n, ec_d, ec_deep, n));
}

err_t bakeBSTSStep3(octet out[], const octet in[], void* state)
{
	bake_bsts_o* s = (bake_bsts_o*)state;
	size_t n, no;
	// стек
	word* Va;			/* [2 * n] */
	word* t;			/* [n / 2 + 1] */
	word* sa;			/* [n + n / 2 + 1] */
	octet* K;			/* [no] (совпадает с Va) */
	octet* block0;		/* [16] (следует за sa) */
	octet* block1;		/* [16] (следует за block0) */
	void* stack;
	// проверить входные данные
	if (!objIsOperable(s))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (!memIsValid(in, 2 * no) ||
		!memIsValid(out, 3 * no + s->cert->len + 8))
		return ERR_BAD_INPUT;
	ASSERT(memIsDisjoint2(out, 3 * no + s->cert->len + 8, s, objKeep(s)));
	// раскладка стека
	Va = objEnd(s, word);
	t = Va + 2 * n;
	sa = t + n / 2 + 1;
	K = (octet*)Va;
	block0 = (octet*)(sa + n + n / 2 + 1);
	block1 = block0 + 16;
	stack = block1 + 16;
	// Vb <- in, Vb \in E*?
	if (!qrFrom(ecX(s->Vb), in, s->ec->f, stack) ||
		!qrFrom(ecY(s->Vb, n), in + no, s->ec->f, stack) ||
		!ecpIsOnA(s->Vb, s->ec, stack))
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
	// out ||.. <- <Va>_4l
	memCopy(out, Va, 2 * no);
	// sa <- (ua - (2^l + t)da) \mod q
	zzMul(sa, t, n / 2, s->d, n, stack);
	sa[n + n / 2] = zzAdd2(sa + n / 2, s->d, n);
	zzMod(sa, sa, n + n / 2 + 1, s->ec->order, n, stack);
	zzSubMod(sa, s->u, sa, s->ec->order, n);
	// ..|| out ||.. <- sa || certa
	wwTo(out + 2 * no, no, sa);
	memCopy(out + 3 * no, s->cert->data, s->cert->len);
	// K <- beltHash(<ua Vb>_2l || helloa || hellob)
	if (!ecMulA(Va, s->Vb, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	qrTo(K, ecX(Va), s->ec->f, stack);
	beltHashStart(stack);
	beltHashStepH(K, no, stack);
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
	block0[0] = 1;
	beltKRPStepG(s->K1, 32, block0, stack);
	// K2 <- beltKRP(K, 1^96, 2)
	block0[0] = 2;
	beltKRPStepG(s->K2, 32, block0, stack);
	// ..|| out ||.. <- beltCFBEncr(sa || certa)
	block0[0] = 0;
	beltCFBStart(stack, s->K2, 32, block0);
	beltCFBStepE(out + 2 * no, no + s->cert->len, stack);
	// ..|| out <- beltMAC(beltCFBEncr(sa || certa) || 0^128)
	beltMACStart(stack, s->K1, 32);
	beltMACStepA(out + 2 * no, no + s->cert->len, stack);
	beltMACStepA(block0, 16, stack);
	beltMACStepG(out + 3 * no + s->cert->len, stack);
	// сохранить t
	wwCopy(s->t, t, n / 2);
	s->t[n / 2] = 1;
	// завершение
	return ERR_OK;
}

static size_t bakeBSTSStep3_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(4 * n + 2) + 32 +
		utilMax(9,
			f_deep,
			ecpIsOnA_deep(n, f_deep),
			ecMulA_deep(n, ec_d, ec_deep, n),
			beltHash_keep(),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n),
			beltKRP_keep(),
			beltCFB_keep(),
			beltMAC_keep());
}

err_t bakeBSTSStep4(octet out[], const octet in[], size_t in_len,
	bake_certval_i vala, void* state)
{
	err_t code;
	bake_bsts_o* s = (bake_bsts_o*)state;
	size_t n, no;
	// стек
	word* Va;			/* [2 * n] */
	word* Qa;			/* [2 * n] */
	word* t;			/* [n / 2 + 1] */
	word* sa;			/* [n] */
	word* sb;			/* [n + n / 2 + 1] (совпадает с sa) */
	octet* K;			/* [no] (совпадает с Qa) */
	octet* block0;		/* [16] (следует за sb) */
	octet* block1;		/* [16] (следует за block0) */
	void* stack;
	// проверить входные данные
	if (!objIsOperable(s))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (in_len <= 3 * no + 8 ||
		!memIsValid(in, in_len) ||
		vala == 0 ||
		!memIsValid(out, no + s->cert->len + 8))
		return ERR_BAD_INPUT;
	ASSERT(memIsDisjoint2(out, no + s->cert->len + 8, s, objKeep(s)));
	// раскладка стека
	Va = objEnd(s, word);
	Qa = Va + 2 * n;
	t = Qa + 2 * n;
	sa = sb = t + n / 2 + 1;
	K = (octet*)Qa;
	block0 = (octet*)(sb + n + n / 2 + 1);
	block1 = block0 + 16;
	stack = block1 + 16;
	// Va <- in, Va \in E*?
	if (!qrFrom(ecX(Va), in, s->ec->f, stack) ||
		!qrFrom(ecY(Va, n), in + no, s->ec->f, stack) ||
		!ecpIsOnA(Va, s->ec, stack))
		return ERR_BAD_POINT;
	// K <- beltHash(<ub Va>_2l || helloa || hellob)
	if (!ecMulA(Qa, Va, s->ec, s->u, n, stack))
		return ERR_BAD_PARAMS;
	qrTo(K, ecX(Qa), s->ec->f, stack);
	beltHashStart(stack);
	beltHashStepH(K, no, stack);
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
	block0[0] = 1;
	beltKRPStepG(s->K1, 32, block0, stack);
	// K2 <- beltKRP(K, 1^96, 2)
	block0[0] = 2;
	beltKRPStepG(s->K2, 32, block0, stack);
	// Ta == beltMAC(Ya || 0^128, K1)?
	block0[0] = 0;
	beltMACStart(stack, s->K1, 32);
	beltMACStepA(in + 2 * no, in_len - 2 * no - 8, stack);
	beltMACStepA(block0, 16, stack);
	if (!beltMACStepV(in + in_len - 8, stack))
		return ERR_AUTH;
	// обработать Ya = [in_len - 2 * no - 8]in
	in_len -= 2 * no + 8;
	{
		blob_t Ya;
		// sa || certa <- beltCFBDecr(Ya, K2, 0^128)
		if ((Ya = blobCreate(in_len)) == 0)
			return ERR_OUTOFMEMORY;
		memCopy(Ya, in + 2 * no, in_len);
		beltCFBStart(stack, s->K2, 32, block0);
		beltCFBStepD(Ya, in_len, stack);
		// sa \in {0, 1,..., q - 1}?
		wwFrom(sa, Ya, no);
		if (wwCmp(sa, s->ec->order, n) >= 0)
		{
			blobClose(Ya);
			return ERR_AUTH;
		}
		// проверить certa
		code = vala((octet*)Qa, s->params, (octet*)Ya + no, in_len - no);
		ERR_CALL_HANDLE(code, blobClose(Ya));
		if (!qrFrom(ecX(Qa), (octet*)Qa, s->ec->f, stack) ||
			!qrFrom(ecY(Qa, n), (octet*)Qa + no, s->ec->f, stack) ||
			!ecpIsOnA(Qa, s->ec, stack))
			code = ERR_BAD_CERT;
		blobClose(Ya);
		ERR_CALL_CHECK(code);
	}
	// t <- <beltHash(<Va>_2l || <Vb>_2l)>_l
	beltHashStart(stack);
	beltHashStepH(in, no, stack);
	qrTo((octet*)s->Vb, s->Vb, s->ec->f, stack);
	beltHashStepH(s->Vb, no, stack);
	beltHashStepG2((octet*)t, no / 2, stack);
	wwFrom(t, t, no / 2);
	// sa G + (2^l + t)Qa == Va?
	t[n / 2] = 1;
	if (!ecAddMulA(Qa, s->ec, stack, 2, s->ec->base, sa, n, Qa, t, n / 2 + 1))
		return ERR_BAD_PARAMS;
	if (!wwEq(Qa, Va, 2 * n))
		return ERR_AUTH;
	// sb <- (ub - (2^l + t)db) \mod q
	zzMul(sb, t, n / 2, s->d, n, stack);
	sb[n + n / 2] = zzAdd2(sb + n / 2, s->d, n);
	zzMod(sb, sb, n + n / 2 + 1, s->ec->order, n, stack);
	zzSubMod(sb, s->u, sb, s->ec->order, n);
	// out ||.. <- beltCFBEncr(sb || certb)
	wwTo(out, no, sb);
	memCopy(out + no, s->cert->data, s->cert->len);
	beltCFBStart(stack, s->K2, 32, block1);
	beltCFBStepE(out, no + s->cert->len, stack);
	// .. || out <- beltMAC(beltCFBEncr(sb || certb) || 1^128)
	beltMACStart(stack, s->K1, 32);
	beltMACStepA(out, no + s->cert->len, stack);
	beltMACStepA(block1, 16, stack);
	beltMACStepG(out + no + s->cert->len, stack);
	// завершение
	return ERR_OK;
}

static size_t bakeBSTSStep4_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(6 * n + 2) + 32 +
		utilMax(10,
			f_deep,
			ecpIsOnA_deep(n, f_deep),
			ecMulA_deep(n, ec_d, ec_deep, n),
			beltHash_keep(),
			zzMul_deep(n / 2, n),
			zzMod_deep(n + n / 2 + 1, n),
			ecAddMulA_deep(n, ec_d, ec_deep, 2, n, n / 2 + 1),
			beltKRP_keep(),
			beltCFB_keep(),
			beltMAC_keep());
}

err_t bakeBSTSStep5(const octet in[], size_t in_len, bake_certval_i valb,
	void* state)
{
	err_t code;
	bake_bsts_o* s = (bake_bsts_o*)state;
	size_t n, no;
	// стек
	word* Qb;			/* [2 * n] */
	word* sb;			/* [n] */
	octet* block1;		/* [16] (совпадает с Qb) */
	void* stack;
	// проверить входные данные
	if (!objIsOperable(s))
		return ERR_BAD_INPUT;
	n = s->ec->f->n, no = s->ec->f->no;
	if (in_len <= no + 8 ||
		!memIsValid(in, in_len) ||
		valb == 0)
		return ERR_BAD_INPUT;
	// раскладка стека
	Qb = objEnd(s, word);
	sb = Qb + 2 * n;
	stack = sb + n;
	block1 = (octet*)Qb;
	// Tb == beltMAC(Yb || 1^128, K1)?
	memSet(block1, 0xFF, 16);
	beltMACStart(stack, s->K1, 32);
	beltMACStepA(in, in_len - 8, stack);
	beltMACStepA(block1, 16, stack);
	if (!beltMACStepV(in + in_len - 8, stack))
		return ERR_AUTH;
	// обработать Yb = [in_len - 8]in
	in_len -= 8;
	{
		blob_t Yb;
		// sb || certb <- beltCFBDecr(Yb, K2, 1^128)
		if ((Yb = blobCreate(in_len)) == 0)
			return ERR_OUTOFMEMORY;
		memCopy(Yb, in, in_len);
		beltCFBStart(stack, s->K2, 32, block1);
		beltCFBStepD(Yb, in_len, stack);
		// sb \in {0, 1,..., q - 1}?
		wwFrom(sb, Yb, no);
		if (wwCmp(sb, s->ec->order, n) >= 0)
		{
			blobClose(Yb);
			return ERR_AUTH;
		}
		// проверить certa
		code = valb((octet*)Qb, s->params, (octet*)Yb + no, in_len - no);
		ERR_CALL_HANDLE(code, blobClose(Yb));
		if (!qrFrom(ecX(Qb), (octet*)Qb, s->ec->f, stack) ||
			!qrFrom(ecY(Qb, n), (octet*)Qb + no, s->ec->f, stack) ||
			!ecpIsOnA(Qb, s->ec, stack))
			code = ERR_BAD_CERT;
		blobClose(Yb);
		ERR_CALL_CHECK(code);
	}
	// sb G + (2^l + t)Qa == Vb?
	if (!ecAddMulA(Qb, s->ec, stack, 2, s->ec->base, sb, n,
		Qb, s->t, n / 2 + 1))
		return ERR_BAD_PARAMS;
	if (!wwEq(Qb, s->Vb, 2 * n))
		return ERR_AUTH;
	// завершение
	return ERR_OK;
}

static size_t bakeBSTSStep5_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return O_OF_W(3 * n) +
		utilMax(5,
			beltMAC_keep(),
			beltCFB_keep(),
			f_deep,
			ecpIsOnA_deep(n, f_deep),
			ecAddMulA_deep(n, ec_d, ec_deep, 2, n, n / 2 + 1));
}

err_t bakeBSTSStepG(octet key[32], void* state)
{
	bake_bsts_o* s = (bake_bsts_o*)state;
	// проверить входные данные
	if (!objIsOperable(s) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// key <- K0
	memCopy(key, s->K0, 32);
	// завершение
	return ERR_OK;
}

static size_t bakeBSTS_deep(size_t n, size_t f_deep, size_t ec_d,
	size_t ec_deep)
{
	return utilMax(5,
		bakeBSTSStart_deep(n, f_deep, ec_d, ec_deep),
		bakeBSTSStep2_deep(n, f_deep, ec_d, ec_deep),
		bakeBSTSStep3_deep(n, f_deep, ec_d, ec_deep),
		bakeBSTSStep4_deep(n, f_deep, ec_d, ec_deep),
		bakeBSTSStep5_deep(n, f_deep, ec_d, ec_deep));
}

/*
*******************************************************************************
Выполнение BSTS
*******************************************************************************
*/

err_t bakeBSTSRunB(octet key[32], const bign_params* params,
	const bake_settings* settings, const octet privkeyb[],
	const bake_cert* certb, bake_certval_i vala,
	read_i read, write_i write, void* file)
{
	err_t code;
	size_t len;
	// блоб
	blob_t blob;
	octet* in;			/* [512] */
	octet* out;			/* [MAX2(l / 2, l / 4 + certb->len + 8)] */
	void* state;		/* [bakeBSTS_keep()] */
	// проверить входные данные
	if (!memIsValid(key, 32) ||
		!memIsValid(certb, sizeof(bake_cert)))
		return ERR_BAD_INPUT;
	// создать блоб
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	blob = blobCreate2( 
		(size_t)512, 
		MAX2(params->l / 2, params->l / 4 + certb->len + 8),
		bakeBSTS_keep(params->l),
		SIZE_MAX,
		&in, &out, &state);
	if (blob == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bakeBSTSStart(state, params, settings, privkeyb, certb);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 2
	code = bakeBSTSStep2(out, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = write(&len, out, params->l / 2, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 4: прочитать блок M2
	code = read(&len, in, 512, file);
	// шаг 4: M2 из одного блока?
	if (code == ERR_MAX)
	{
		code = bakeBSTSStep4(out, in, len, vala, state);
		ERR_CALL_HANDLE(code, blobClose(blob));
		code = write(&len, out, params->l / 4 + certb->len + 8, file);
		ERR_CALL_HANDLE(code, blobClose(blob));
	}
	// шаг 4: ошибка при чтении
	else if (code != ERR_OK)
	{
		blobClose(blob);
		return code;
	}
	// шаг 4: обработать M2 из нескольких блоков
	else
	{
		blob_t M2 = 0;
		while (code == ERR_OK)
		{
			if ((M2 = blobResize(M2, blobSize(M2) + len)) == 0)
			{
				blobClose(blob);
				return ERR_OUTOFMEMORY;
			}
			memCopy((octet*)M2 + blobSize(M2) - len, in, len);
			code = read(&len, in, 512, file);
		}
		if (code != ERR_MAX)
		{
			blobClose(M2);
			blobClose(blob);
			return code;
		}
		if ((M2 = blobResize(M2, blobSize(M2) + len)) == 0)
		{
			blobClose(blob);
			return ERR_OUTOFMEMORY;
		}
		memCopy((octet*)M2 + blobSize(M2) - len, in, len);
		code = bakeBSTSStep4(out, M2, blobSize(M2), vala, state);
		blobClose(M2);
		ERR_CALL_HANDLE(code, blobClose(blob));
		code = write(&len, out, params->l / 4 + certb->len + 8, file);
		ERR_CALL_HANDLE(code, blobClose(blob));
	}
	// завершение
	code = bakeBSTSStepG(key, state);
	blobClose(blob);
	return code;
}

err_t bakeBSTSRunA(octet key[32], const bign_params* params,
	const bake_settings* settings, const octet privkeya[],
	const bake_cert* certa, bake_certval_i valb,
	read_i read, write_i write, void* file)
{
	err_t code;
	size_t len;
	// блоб
	blob_t blob;
	octet* in;			/* [MAX2(512, l / 2)] */
	octet* out;			/* [3 * l / 4 + certa->len + 8] */
	void* state;		/* [bakeBSTS_keep()] */
	// проверить входные данные
	if (!memIsValid(key, 32) ||
		!memIsValid(certa, sizeof(bake_cert)))
		return ERR_BAD_INPUT;
	// создать блоб
	if (params->l != 128 && params->l != 192 && params->l != 256)
		return ERR_BAD_PARAMS;
	blob = blobCreate2( 
		MAX2(512, params->l / 2),
		3 * params->l / 4 + certa->len + 8,
		bakeBSTS_keep(params->l),
		SIZE_MAX,
		&in, &out, &state);
	if (blob == 0)
		return ERR_OUTOFMEMORY;
	// старт
	code = bakeBSTSStart(state, params, settings, privkeya, certa);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 3
	code = read(&len, in, params->l / 2, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = bakeBSTSStep3(out, in, state);
	ERR_CALL_HANDLE(code, blobClose(blob));
	code = write(&len, out, 3 * params->l / 4 + certa->len + 8, file);
	ERR_CALL_HANDLE(code, blobClose(blob));
	// шаг 5: прочитать блок M3
	code = read(&len, in, 512, file);
	// шаг 5: M3 из одного блока?
	if (code == ERR_MAX)
	{
		code = bakeBSTSStep5(in, len, valb, state);
		ERR_CALL_HANDLE(code, blobClose(blob));
	}
	// шаг 5: ошибка при чтении
	else if (code != ERR_OK)
	{
		blobClose(blob);
		return code;
	}
	// шаг 5: обработать M3 из нескольких блоков
	else
	{
		blob_t M3 = 0;
		while (code == ERR_OK)
		{
			if ((M3 = blobResize(M3, blobSize(M3) + len)) == 0)
			{
				blobClose(blob);
				return ERR_OUTOFMEMORY;
			}
			memCopy((octet*)M3 + blobSize(M3) - len, in, len);
			code = read(&len, in, 512, file);
		}
		if (code != ERR_MAX)
		{
			blobClose(M3);
			blobClose(blob);
			return code;
		}
		if ((M3 = blobResize(M3, blobSize(M3) + len)) == 0)
		{
			blobClose(blob);
			return ERR_OUTOFMEMORY;
		}
		memCopy((octet*)M3 + blobSize(M3) - len, in, len);
		code = bakeBSTSStep5(M3, blobSize(M3), valb, state);
		blobClose(M3);
		ERR_CALL_HANDLE(code, blobClose(blob));
	}
	// завершение
	code = bakeBSTSStepG(key, state);
	blobClose(blob);
	return code;
}
