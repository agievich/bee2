/*
*******************************************************************************
\file bign96_test.c
\brief Tests for bign96 signatures
\project bee2/test
\created 2021.01.20
\version 2025.09.28
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign96.h>
#include <bee2/crypto/brng.h>

/*
*******************************************************************************
brngCTRX: Расширение brngCTR

При инициализации можно передать дополнительное слово X.
*******************************************************************************
*/
typedef struct
{
	const octet* X;		/*< дополнительное слово */
	size_t count;		/*< размер X в октетах */
	size_t offset;		/*< текущее смещение в X */
	octet state_ex[];	/*< состояние brngCTR */
} brng_ctrx_st;

static size_t brngCTRX_keep()
{
	return sizeof(brng_ctrx_st) + brngCTR_keep();
}

static void brngCTRXStart(const octet theta[32], const octet iv[32],
	const void* X, size_t count, void* state)
{
	brng_ctrx_st* s = (brng_ctrx_st*)state;
	ASSERT(memIsValid(s, sizeof(brng_ctrx_st)));
	ASSERT(count > 0);
	ASSERT(memIsValid(s->state_ex, brngCTR_keep()));
	brngCTRStart(s->state_ex, theta, iv);
	s->X = (const octet*)X;
	s->count = count;
	s->offset = 0;
}

static void brngCTRXStepR(void* buf, size_t count, void* stack)
{
	brng_ctrx_st* s = (brng_ctrx_st*)stack;
	octet* buf1 = (octet*)buf;
	size_t count1 = count;
	ASSERT(memIsValid(s, sizeof(brng_ctrx_st)));
	// заполнить buf
	while (count1)
		if (count1 < s->count - s->offset)
		{
			memCopy(buf1, s->X + s->offset, count1);
			s->offset += count1;
			count1 = 0;
		}
		else
		{
			memCopy(buf1, s->X + s->offset, s->count - s->offset);
			buf1 += s->count - s->offset;
			count1 -= s->count - s->offset;
			s->offset = 0;
		}
	// сгенерировать
	brngCTRStepR(buf, count, s->state_ex);
}

/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

bool_t bign96Test()
{
	bign_params params[1];
	octet oid_der[128];
	size_t oid_len;
	octet privkey[24];
	octet pubkey[48];
	octet hash[32];
	octet sig[34];
	mem_align_t brng_state[1024 / sizeof(mem_align_t)];
	// подготовить память
	if (sizeof(brng_state) < brngCTRX_keep())
		return FALSE;
	// проверить параметры
	if (bign96ParamsStd(params, "1.2.112.0.2.0.34.101.45.3.0") != ERR_OK ||
		bign96ParamsVal(params) != ERR_OK)
		return FALSE;
	// идентификатор объекта
	oid_len = sizeof(oid_der);
	if (bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81")
		!= ERR_OK || oid_len != 11)
		return FALSE;
	// инициализировать ГПСЧ
	brngCTRXStart(beltH() + 128, beltH() + 128 + 64,
		beltH(), 8 * 32, brng_state);	
	// управление ключами
	if (bign96KeypairGen(privkey, pubkey, params, brngCTRXStepR, 
			brng_state) != ERR_OK)
		return FALSE;
	if (!hexEq(privkey,
		"B1E1CDDFCF5DD7BA278390F292EEB72B"
		"661B79922933BFB9") || 
		!hexEq(pubkey,
		"4CED8FBBA1842BE58B4C0444F359CB14"
		"C6F2CE13B710F1172D2C962F53D13115"
		"DE14E56D9EB2628C9A884F668059EEA5"))
		return FALSE;
	if (bign96KeypairVal(params, privkey, pubkey) != ERR_OK)
		return FALSE;
	if (bign96PubkeyVal(params, pubkey) != ERR_OK)
		return FALSE;
	if (bign96PubkeyCalc(pubkey, params, privkey) != ERR_OK)
		return FALSE;
	if (!hexEq(pubkey,
		"4CED8FBBA1842BE58B4C0444F359CB14"
		"C6F2CE13B710F1172D2C962F53D13115"
		"DE14E56D9EB2628C9A884F668059EEA5"))
		return FALSE;
	// выработка и проверка подписи
	if (beltHash(hash, beltH(), 13) != ERR_OK)
		return FALSE;
	if (bign96Sign(sig, params, oid_der, oid_len, hash, privkey,
		brngCTRXStepR, brng_state) != ERR_OK)
		return FALSE;
	if (!hexEq(sig, 
		"4981BBDD8721C08FA347B89BD16FDDE6"
		"47D310F55474C4182C1CC5BBD5642CC7"
		"E1B2"))
		return FALSE;
	if (bign96Verify(params, oid_der, oid_len, hash, sig, pubkey) != ERR_OK)
		return FALSE;
	sig[0] ^= 1;
	if (bign96Verify(params, oid_der, oid_len, hash, sig, pubkey) == ERR_OK)
		return FALSE;
	sig[0] ^= 1, pubkey[0] ^= 1;
	if (bign96Verify(params, oid_der, oid_len, hash, sig, pubkey) == ERR_OK)
		return FALSE;
	pubkey[0] ^= 1;
	// детерминированная подпись
	if (beltHash(hash, beltH(), 13) != ERR_OK)
		return FALSE;
	if (bign96Sign2(sig, params, oid_der, oid_len, hash, privkey, 0, 0) !=
		ERR_OK)
		return FALSE;
	if (!hexEq(sig, 
		"D95DEF43F36A4C73D19399B79FB0C692"
		"CF44D615CCE5F45D474E7593D30E70B9"
		"B0C3"))
		return FALSE;
	if (bign96Verify(params, oid_der, oid_len, hash, sig, pubkey) != ERR_OK)
		return FALSE;
	sig[0] ^= 1;
	if (bign96Verify(params, oid_der, oid_len, hash, sig, pubkey) == ERR_OK)
		return FALSE;
	sig[0] ^= 1, pubkey[0] ^= 1;
	if (bign96Verify(params, oid_der, oid_len, hash, sig, pubkey) == ERR_OK)
		return FALSE;
	pubkey[0] ^= 1;
	// все нормально
	return TRUE;
}
