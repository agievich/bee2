/*
*******************************************************************************
\file brng.c
\brief STB 34.101.47 (brng): algorithms of pseudorandom number generation
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.01.31
\version 2018.07.09
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/brng.h"

/*
*******************************************************************************
Ускорители: быстрые операции над блоками brng
*******************************************************************************
*/

static void brngBlockNeg(octet dest[32], const octet src[32])
{
	register size_t i = W_OF_O(32);
	while (i--)
		((word*)dest)[i] = ~((const word*)src)[i];
}

static void brngBlockXor2(octet dest[32], const octet src[32])
{
	register size_t i = W_OF_O(32);
	while (i--)
		((word*)dest)[i] ^= ((const word*)src)[i];
}

static void brngBlockInc(octet block[32])
{
	register size_t i = 0;
	word* w = (word*)block;
	do
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		w[i] = wordRev(w[i]);
		++w[i];
		w[i] = wordRev(w[i]);
#else
		++w[i];
#endif
	}
	while (w[i] == 0 && i++ < W_OF_O(32));
	i = 0;
}

/*
*******************************************************************************
Генерация в режиме CTR

В brng_ctr_st::state_ex размещаются два beltHash-состояния:
-	вспомогательное состояние;
-	состояние beltHash(key ||....).
*******************************************************************************
*/
typedef struct
{
	octet s[32];		/*< переменная s */
	octet r[32];		/*< переменная r */
	octet block[32];	/*< блок выходных данных */
	size_t reserved;	/*< резерв выходных октетов */
	octet state_ex[];	/*< [2 beltHash_keep()] хэш-состояния */
} brng_ctr_st;

size_t brngCTR_keep()
{
	return sizeof(brng_ctr_st) + 2 * beltHash_keep();
}

void brngCTRStart(void* state, const octet key[32], const octet iv[32])
{
	brng_ctr_st* s = (brng_ctr_st*)state;
	ASSERT(memIsDisjoint2(s, brngCTR_keep(), key, 32));
	ASSERT(iv == 0 || memIsDisjoint2(s, brngCTR_keep(), iv, 32));
	// обработать key
	beltHashStart(s->state_ex + beltHash_keep());
	beltHashStepH(key, 32, s->state_ex + beltHash_keep());
	//	сохранить iv
	if (iv)
		memCopy(s->s, iv, 32);
	else
		memSetZero(s->s, 32);
	//	r <- ~s
	brngBlockNeg(s->r, s->s);
	// нет выходных данных
	s->reserved = 0;
}

void brngCTRStepR(void* buf, size_t count, void* state)
{
	brng_ctr_st* s = (brng_ctr_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, brngCTR_keep()));
	// есть резерв данных?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memCopy(buf, s->block + 32 - s->reserved, count);
			s->reserved -= count;
			return;
		}
		memCopy(buf, s->block + 32 - s->reserved, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		// Y_t <- belt-hash(key || s || X_t || r)
		memCopy(s->state_ex, s->state_ex + beltHash_keep(), beltHash_keep());
		beltHashStepH(s->s, 32, s->state_ex);
		beltHashStepH(buf, 32, s->state_ex);
		beltHashStepH(s->r, 32, s->state_ex);
		beltHashStepG(buf, s->state_ex);
		// next
		brngBlockInc(s->s);
		brngBlockXor2(s->r, buf);
		buf = (octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
	{
		// block <- beltHash(key || s || zero_pad(X_t) || r)
		memSetZero(s->block + count, 32 - count);
		memCopy(s->state_ex, s->state_ex + beltHash_keep(), beltHash_keep());
		beltHashStepH(s->s, 32, s->state_ex);
		beltHashStepH(buf, count, s->state_ex);
		beltHashStepH(s->block + count, 32 - count, s->state_ex);
		beltHashStepH(s->r, 32, s->state_ex);
		beltHashStepG(s->block, s->state_ex);
		// Y_t <- left(block)
		memCopy(buf, s->block, count);
		// next
		brngBlockInc(s->s);
		brngBlockXor2(s->r, s->block);
		s->reserved = 32 - count;
	}
}

void brngCTRStepG(octet iv[32], void* state)
{
	brng_ctr_st* s = (brng_ctr_st*)state;
	ASSERT(memIsDisjoint2(s, brngCTR_keep(), iv, 32));
	memCopy(iv, s->s, 32);
}

err_t brngCTRRand(void* buf, size_t count, const octet key[32], octet iv[32])
{
	void* state;
	// проверить входные данные
	if (!memIsValid(key, 32) ||
		!memIsValid(iv, 32) ||
		!memIsValid(buf, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(brngCTR_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// сгенерировать данные
	brngCTRStart(state, key, iv);
	brngCTRStepR(buf, count, state);
	brngCTRStepG(iv, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Генерация в режиме HMAC

В brng_hmac_st::state_ex размещаются два beltHMAC-состояния:
-	вспомогательное состояние;
-	состояние beltHMAC(key, ...).

\remark Учитывается инкрементальность beltHMAC
*******************************************************************************
*/
typedef struct
{
	const octet* iv;			/*< указатель на синхропосылку */
	octet iv_buf[64];			/*< синхропосылка (если укладывается) */
	size_t iv_len;				/*< длина синхропосылки в октетах */
	octet r[32];				/*< переменная r */
	octet block[32];			/*< блок выходных данных */
	size_t reserved;			/*< резерв выходных октетов */
	octet state_ex[];			/*< [2 * beltHMAC_keep()] hmac-состояния */
} brng_hmac_st;

size_t brngHMAC_keep()
{
	return sizeof(brng_hmac_st) + 2 * beltHMAC_keep();
}

void brngHMACStart(void* state, const octet key[], size_t key_len, 
	const octet iv[], size_t iv_len)
{
	brng_hmac_st* s = (brng_hmac_st*)state;
	ASSERT(memIsDisjoint2(s, brngHMAC_keep(), key, key_len));
	ASSERT(memIsDisjoint2(s, brngHMAC_keep(), iv, iv_len));
	// запомнить iv
	if ((s->iv_len = iv_len) <= 64) 
	{
		memCopy(s->iv_buf, iv, iv_len);
		s->iv = s->iv_buf;
	}
	else
		s->iv = iv;
	// обработать key
	beltHMACStart(s->state_ex + beltHMAC_keep(), key, key_len);
	// r <- beltHMAC(key, iv)
	memCopy(s->state_ex, s->state_ex + beltHMAC_keep(), beltHMAC_keep());
	beltHMACStepA(iv, iv_len, s->state_ex);
	beltHMACStepG(s->r, s->state_ex);
	// нет выходных данных
	s->reserved = 0;
}

void brngHMACStepR(void* buf, size_t count, void* state)
{
	brng_hmac_st* s = (brng_hmac_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, brngHMAC_keep()));
	// есть резерв данных?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memCopy(buf, s->block + 32 - s->reserved, count);
			s->reserved -= count;
			return;
		}
		memCopy(buf, s->block + 32 - s->reserved, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		// r <- beltHMAC(key, r) 
		memCopy(s->state_ex, s->state_ex + beltHMAC_keep(), beltHMAC_keep());
		beltHMACStepA(s->r, 32, s->state_ex);
		beltHMACStepG(s->r, s->state_ex);
		// Y_t <- beltHMAC(key, r || iv)
		beltHMACStepA(s->iv, s->iv_len, s->state_ex);
		beltHMACStepG(buf, s->state_ex);
		// next
		buf = (octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
	{
		// r <- beltHMAC(key, r) 
		memCopy(s->state_ex, s->state_ex + beltHMAC_keep(), beltHMAC_keep());
		beltHMACStepA(s->r, 32, s->state_ex);
		beltHMACStepG(s->r, s->state_ex);
		// Y_t <- left(beltHMAC(key, r || iv))
		beltHMACStepA(s->iv, s->iv_len, s->state_ex);
		beltHMACStepG(s->block, s->state_ex);
		memCopy(buf, s->block, count);
		// next
		s->reserved = 32 - count;
	}
}

err_t brngHMACRand(void* buf, size_t count, const octet key[], size_t key_len,
	const octet iv[], size_t iv_len)
{
	void* state;
	// проверить входные данные
	if (!memIsValid(key, key_len) ||
		!memIsValid(iv, iv_len) ||
		!memIsValid(buf, count) ||
		!memIsDisjoint2(buf, count, iv, iv_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(brngHMAC_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// сгенерировать данные
	brngHMACStart(state, key, key_len, iv, iv_len);
	brngHMACStepR(buf, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
