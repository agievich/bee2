/*
*******************************************************************************
\file bign128_test.c
\brief Tests for Bign128
\project bee2/test
\created 2026.03.06
\version 2026.03.06
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign128.h>
#include <bee2/crypto/brng.h>

/*
*******************************************************************************
brngCTRX: Расширение brngCTR

При инициализации можно передать дополнительное слово X.
*******************************************************************************
*/
typedef struct
{
	const octet* X;			/*< дополнительное слово */
	size_t count;			/*< размер X в октетах */
	size_t offset;			/*< текущее смещение в X */
	mem_align_t state_ex[];	/*< состояние brngCTR */
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

bool_t bign128Test()
{
	bign_params params[1];
	octet privkey[32];
	octet pubkey[64];
	octet hash[32];
	octet sig[48];
	octet token[80];
	mem_align_t state[1024 / sizeof(mem_align_t)];
	// подготовить память
	if (sizeof(state) < brngCTRX_keep())
		return FALSE;
	// инициализировать ГПСЧ
	brngCTRXStart(beltH() + 128, beltH() + 128 + 64, beltH(), 8 * 32, state);
	// загрузить параметры
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK)
		return FALSE;
	// тест Г.1
	if (bign128KeypairGen(privkey, pubkey, brngCTRXStepR, state) != ERR_OK ||
		!hexEq(privkey,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269") || 
		!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90") ||
		bign128KeypairVal(privkey, pubkey) != ERR_OK ||
		bign128PubkeyVal(pubkey) != ERR_OK ||
		bign128PubkeyCalc(pubkey, privkey) != ERR_OK ||
		!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return FALSE;
	memSetZero(pubkey, 32);
	memCopy(pubkey + 32, params->yG, 32);
	if (bign128DH(pubkey, privkey, pubkey, 64) != ERR_OK ||
		!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return FALSE;
	// тест Г.2
	if (beltHash(hash, beltH(), 13) != ERR_OK ||
		bign128Sign(sig, hash, privkey, brngCTRXStepR, state) != ERR_OK ||
		!hexEq(sig, 
		"E36B7F0377AE4C524027C387FADF1B20"
		"CE72F1530B71F2B5FD3A8C584FE2E1AE"
		"D20082E30C8AF65011F4FB54649DFD3D") ||
		bign128Verify(hash, sig, pubkey) != ERR_OK)
		return FALSE;
	// детерминированная подпись
	if (bign128Sign2(sig, hash, privkey, 0, 0) != ERR_OK ||
		bign128Verify(hash, sig, pubkey) != ERR_OK)
		return FALSE;
	// тест Г.4
	if (bign128KeyWrap(token, beltH(), 18, beltH() + 32, pubkey, brngCTRXStepR,
		state) != ERR_OK ||
		!hexEq(token,
		"9B4EA669DABDF100A7D4B6E6EB76EE52"
		"51912531F426750AAC8A9DBB51C54D8D"
		"EB9289B50A46952D0531861E45A8814B"
		"008FDC65DE9FF1FA2A1F16B6A280E957"
		"A814") ||
		bign128KeyUnwrap(token, token, 18 + 16 + 32, beltH() + 32, 
		privkey) != ERR_OK ||
		!memEq(token, beltH(), 18))
		return FALSE;
	// тест Г.3
	if (beltHash(hash, beltH(), 48) != ERR_OK ||
		bign128Sign(sig, hash, privkey, brngCTRXStepR, state) != ERR_OK ||
		!hexEq(sig, 
		"47A63C8B9C936E94B5FAB3D9CBD78366"
		"290F3210E163EEC8DB4E921E8479D413"
		"8F112CC23E6DCE65EC5FF21DF4231C28") ||
		bign128Verify(hash, sig, pubkey) != ERR_OK)
		return FALSE;
	// тест Г.5
	if (bignKeyWrap(token, params, beltH(), 32, beltH() + 64,
		pubkey, brngCTRXStepR, state) != ERR_OK ||
		!hexEq(token,
		"4856093A0F6C13015FC8E15F1B23A762"
		"02D2F4BA6E5EC52B78658477F6486DE6"
		"87AFAEEA0EF7BC1326A7DCE7A10BA10E"
		"3F91C0126044B22267BF30BD6F1DA29E"
		"0647CF39C1D59A56BB0194E0F4F8A2BB") ||
		bign128KeyUnwrap(token, token, 32 + 16 + 32, beltH() + 64, 
		privkey) != ERR_OK ||
		!memEq(token, beltH(), 32))
		return FALSE;
	// все нормально
	return TRUE;
}
