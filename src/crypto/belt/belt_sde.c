/*
*******************************************************************************
\file belt_sde.c
\brief STB 34.101.31 (belt): SDE (Sectorwise Disk Encryption)
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2018.09.01
\version 2020.03.24
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Шифрование в режиме SDE
*******************************************************************************
*/
typedef struct
{
	belt_wbl_st wbl[1];	/*< состояние механизма WBL */
	octet s[16];		/*< переменная s */
} belt_sde_st;

size_t beltSDE_keep()
{
	return sizeof(belt_sde_st);
}

void beltSDEStart(void* state, const octet key[], size_t len)
{
	belt_sde_st* st = (belt_sde_st*)state;
	ASSERT(memIsValid(state, beltSDE_keep()));
	beltWBLStart(st->wbl, key, len);
}

void beltSDEStepE(void* buf, size_t count, const octet iv[16], void* state)
{
	belt_sde_st* st = (belt_sde_st*)state;
	ASSERT(count % 16 == 0 && count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltSDE_keep()));
	ASSERT(memIsValid(iv, 16));
	// зашифровать синхропосылку
	memCopy(st->s, iv, 16);
	beltBlockEncr(st->s, st->wbl->key);
	// каскад XEX
	beltBlockXor2(buf, st->s);
	beltWBLStepE(buf, count, st->wbl);
	beltBlockXor2(buf, st->s);
}

void beltSDEStepD(void* buf, size_t count, const octet iv[16], void* state)
{
	belt_sde_st* st = (belt_sde_st*)state;
	ASSERT(count % 16 == 0 && count >= 32);
	ASSERT(memIsDisjoint2(buf, count, state, beltSDE_keep()));
	ASSERT(memIsValid(iv, 16));
	// зашифровать синхропосылку
	memCopy(st->s, iv, 16);
	beltBlockEncr(st->s, st->wbl->key);
	// каскад XEX
	beltBlockXor2(buf, st->s);
	beltWBLStepD(buf, count, st->wbl);
	beltBlockXor2(buf, st->s);
}

err_t beltSDEEncr(void* dest, const void* src, size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count % 16 != 0 || count < 32 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltSDE_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltSDEStart(state, key, len);
	memMove(dest, src, count);
	beltSDEStepE(dest, count, iv, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltSDEDecr(void* dest, const void* src, size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count % 16 != 0 || count < 32 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltSDE_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// расшифровать
	beltSDEStart(state, key, len);
	memMove(dest, src, count);
	beltSDEStepD(dest, count, iv, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
