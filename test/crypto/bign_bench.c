/*
*******************************************************************************
\file bign_bench.c
\brief Benchmarks for STB 34.101.45 (bign)
\project bee2/test
\created 2026.03.09
\version 2026.03.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bign128.h>
#include <bee2/crypto/bign192.h>
#include <bee2/crypto/bign256.h>

/*
*******************************************************************************
Оценка производительности алгоритмов Bign на определеннном уровне

Оценивается производительность функций bignXXXKeypairGen(), bignXXXSign(),
bignXXXSign2(), bignXXXVerify(), bignXXXKeyWrap(), bignXXXKeyUnwrap().

\warning При оценке производительности не проверяются коды возврата функций.
Предполагается, что функции завершаются успешно.

\warning Замеряется среднее время выполнения bignXXXVerify() и минимальное
время остальных функции. Предполагается, что последние функции регулярны.

\remark Оценивается время транспорта ключа из 32 октетов.
*******************************************************************************
*/

typedef err_t (*bign_keypairgen_i)(octet privkey[], octet pubkey[],
	gen_i rng, void* rng_state);
typedef err_t (*bign_sign_i)(octet sig[], const octet hash[],
	const octet privkey[], gen_i rng, void* rng_state);
typedef err_t (*bign_sign2_i)(octet sig[], const octet hash[],
	const octet privkey[], const void* t, size_t t_len);
typedef err_t (*bign_verify_i)(const octet hash[], const octet sig[],
	const octet pubkey[]);
typedef err_t (*bign_keywrap_i)(octet token[], const octet key[],
	size_t len, const octet header[16], const octet pubkey[],
	gen_i rng, void* rng_state);
typedef err_t(*bign_keyunwrap_i)(octet key[], const octet token[], 
	size_t len, const octet header[16], const octet privkey[]);

static bool_t bignBench_internal(size_t l)
{	
	const size_t reps = 50;
	bign_keypairgen_i keypairgen;
	bign_sign_i sign;
	bign_sign2_i sign2;
	bign_verify_i verify;
	bign_keywrap_i keywrap;
	bign_keyunwrap_i keyunwrap;
	mem_align_t combo_state[64 / sizeof(mem_align_t)];
	octet privkey[64];
	octet pubkey[128];
	octet hash[64];
	octet sig[96];
	octet key[32];
	octet token[32 + 64 + 16];
	tm_ticks_t ticks;
	size_t i;
	// pre
	ASSERT(l == 128 || l == 192 || l == 256);
	ASSERT(sizeof(combo_state) >= prngCOMBO_keep());
	// настройка
	if (l == 128)
	{
		keypairgen = bign128KeypairGen;
		sign = bign128Sign;
		sign2 = bign128Sign2;
		verify = bign128Verify;
		keywrap = bign128KeyWrap;
		keyunwrap = bign128KeyUnwrap;
	}
	else if (l == 192)
	{
		keypairgen = bign192KeypairGen;
		sign = bign192Sign;
		sign2 = bign192Sign2;
		verify = bign192Verify;
		keywrap = bign192KeyWrap;
		keyunwrap = bign192KeyUnwrap;
	}
	else
	{
		keypairgen = bign256KeypairGen;
		sign = bign256Sign;
		sign2 = bign256Sign2;
		verify = bign256Verify;
		keywrap = bign256KeyWrap;
		keyunwrap = bign256KeyUnwrap;
	}
	// создать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// разогрев
	if (keypairgen(privkey, pubkey, prngCOMBOStepR, combo_state) != ERR_OK)
		return FALSE;
	// подготовка
	prngCOMBOStepR(hash, sizeof(hash), combo_state);
	prngCOMBOStepR(key, sizeof(key), combo_state);
	// keypairgen
	for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
	{
		tm_ticks_t t = tmTicks();
		(void)keypairgen(privkey, pubkey, prngCOMBOStepR, combo_state);
		if ((t = tmTicks() - t) < ticks)
			ticks = t;
	}
	printf("bign%uBench::KeypairGen:  %u cycles/kp [%u kps/sec]\n",
		(unsigned)l,
		(unsigned)ticks,
		(unsigned)tmSpeed(1, ticks));
	// sign
	for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
	{
		tm_ticks_t t = tmTicks();
		(void)sign(sig, hash, privkey, prngCOMBOStepR, combo_state);
		if ((t = tmTicks() - t) < ticks)
			ticks = t;
	}
	printf("bign%uBench::Sign:        %u cycles/sig [%u sigs/sec]\n",
		(unsigned)l,
		(unsigned)ticks,
		(unsigned)tmSpeed(1, ticks));
	// sign2
	for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
	{
		tm_ticks_t t = tmTicks();
		(void)sign2(sig, hash, privkey, 0, 0);
		if ((t = tmTicks() - t) < ticks)
			ticks = t;
	}
	printf("bign%uBench::Sign2:       %u cycles/sig [%u sigs/sec]\n",
		(unsigned)l,
		(unsigned)ticks,
		(unsigned)tmSpeed(1, ticks));
	// verify
	for (i = 0, ticks = 0; i < reps; ++i)
	{
		tm_ticks_t t;
		(void)sign(sig, hash, privkey, 0, 0);
		t = tmTicks();
		(void)verify(hash, sig, pubkey);
		ticks += tmTicks() - t;
	}
	printf("bign%uBench::Verify:      %u cycles/sig [%u sigs/sec]\n",
		(unsigned)l,
		(unsigned)(ticks / reps),
		(unsigned)tmSpeed(reps, ticks));
	// keywrap
	for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
	{
		tm_ticks_t t = tmTicks();
		(void)keywrap(token, key, sizeof(key), 0, pubkey,
			prngCOMBOStepR, combo_state);
		if ((t = tmTicks() - t) < ticks)
			ticks = t;
	}
	printf("bign%uBench::KeyWrap:     %u cycles/key [%u keys/sec]\n",
		(unsigned)l,
		(unsigned)ticks,
		(unsigned)tmSpeed(1, ticks));
	// keyunwrap
	for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
	{
		tm_ticks_t t = tmTicks();
		(void)keyunwrap(key, token, sizeof(key) + l / 4 + 16, 0, privkey);
		if ((t = tmTicks() - t) < ticks)
			ticks = t;
	}
	printf("bign%uBench::KeyUnwrap:   %u cycles/key [%u keys/sec]\n",
		(unsigned)l,
		(unsigned)ticks,
		(unsigned)tmSpeed(1, ticks));
	// завершение
	return TRUE;
}

/*
*******************************************************************************
Оценка производительности алгоритмов Bign
*******************************************************************************
*/

bool_t bignBench()
{
	return bignBench_internal(128) &&
		bignBench_internal(192) &&
		bignBench_internal(256);
}
