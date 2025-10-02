/*
*******************************************************************************
\file belt_ecb.c
\brief STB 34.101.31 (belt): ECB encryption
\project bee2 [cryptographic library]
\created 2012.12.18
\version 2025.10.02
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Шифрование в режиме ECB

\remark Чтобы соблюсти предусловия выравнивания в функциях beltBlockEncr() и 
beltBlockDecr(), перед обращениями к ним блок данных переписывается в поле 
block структуры belt_ecb_st. Код будет компактнее и эффективнее, если 
потребовать, чтобы обрабатываемый буфер buf был выровнен на границу u32. 
Например вот так будет выглядеть основная часть  beltECBStepE():
\code
	while(count >= 16)
	{
		beltBlockDecr(buf, st->key);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	if (count)
	{
		memSwap((octet*)buf - 16, buf, count);
		beltBlockDecr((octet*)buf - 16, st->key);
	}
\endcode
*******************************************************************************
*/
typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	octet block[16];	/*< вспомогательный блок */
} belt_ecb_st;

size_t beltECB_keep()
{
	return sizeof(belt_ecb_st);
}

void beltECBStart(void* state, const octet key[], size_t len)
{
	belt_ecb_st* st = (belt_ecb_st*)state;
	ASSERT(memIsValid(state, beltECB_keep()));
	beltKeyExpand2(st->key, key, len);
}

void beltECBStepE(void* buf, size_t count, void* state)
{
	belt_ecb_st* st = (belt_ecb_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltECB_keep()));
	// цикл по полным блокам
	while(count >= 16)
	{
		beltBlockCopy(st->block, buf);
		beltBlockEncr(st->block, st->key);
		beltBlockCopy(buf, st->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		memCopy(st->block, buf, count);
		memCopy(st->block + count, (octet*)buf - 16 + count, 16 - count);
		beltBlockEncr(st->block, st->key);
		memCopy(buf, (octet*)buf - 16, count);
		beltBlockCopy((octet*)buf - 16, st->block);
	}
}

void beltECBStepD(void* buf, size_t count, void* state)
{
	belt_ecb_st* st = (belt_ecb_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltECB_keep()));
	// цикл по полным блокам
	while(count >= 16)
	{
		beltBlockCopy(st->block, buf);
		beltBlockDecr(st->block, st->key);
		beltBlockCopy(buf, st->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		memCopy(st->block, buf, count);
		memCopy(st->block + count, (octet*)buf - 16 + count, 16 - count);
		beltBlockDecr(st->block, st->key);
		memCopy(buf, (octet*)buf - 16, count);
		beltBlockCopy((octet*)buf - 16, st->block);
	}
}

err_t beltECBEncr(void* dest, const void* src, size_t count,
	const octet key[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltECB_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltECBStart(state, key, len);
	memMove(dest, src, count);
	beltECBStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltECBDecr(void* dest, const void* src, size_t count,
	const octet key[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltECB_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// расшифровать
	beltECBStart(state, key, len);
	memMove(dest, src, count);
	beltECBStepD(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

