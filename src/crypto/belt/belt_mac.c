/*
*******************************************************************************
\file belt_mac.c
\brief STB 34.101.31 (belt): MAC (message authentication)
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
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
Имитозащита (MAC)

Для ускорения работы текущая имитовставка s хранится в виде [4]u32.
Это позволяет зашифровывать s с помощью функции beltBlockEncr2(),
в которой не используется реверс октетов даже на платформах BIG_ENDIAN.
Реверс применяется только перед сложением накопленного блока данных
с текущей имитовставкой.
*******************************************************************************
*/
typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	u32 s[4];			/*< переменная s */
	u32 r[4];			/*< переменная r */
	u32 mac[4];			/*< окончательная имитовставка */
	octet block[16];	/*< блок данных */
	size_t filled;		/*< накоплено октетов в блоке */
} belt_mac_st;

size_t beltMAC_keep()
{
	return sizeof(belt_mac_st);
}

void beltMACStart(void* state, const octet key[], size_t len)
{
	belt_mac_st* st = (belt_mac_st*)state;
	ASSERT(memIsValid(state, beltMAC_keep()));
	beltKeyExpand2(st->key, key, len);
	beltBlockSetZero(st->s);
	beltBlockSetZero(st->r);
	beltBlockEncr2(st->r, st->key);
	st->filled = 0;
}

void beltMACStepA(const void* buf, size_t count, void* state)
{
	belt_mac_st* st = (belt_mac_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltMAC_keep()));
	// накопить полный блок
	if (st->filled < 16)
	{
		if (count <= 16 - st->filled)
		{
			memCopy(st->block + st->filled, buf, count);
			st->filled += count;
			return;
		}
		memCopy(st->block + st->filled, buf, 16 - st->filled);
		count -= 16 - st->filled;
		buf = (const octet*)buf + 16 - st->filled;
		st->filled = 16;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
#endif
		beltBlockXor2(st->s, st->block);
		beltBlockEncr2(st->s, st->key);
		beltBlockCopy(st->block, buf);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
#endif
		beltBlockXor2(st->s, st->block);
		beltBlockEncr2(st->s, st->key);
		memCopy(st->block, buf, count);
		st->filled = count;
	}
}

static void beltMACStepG_internal(void* state)
{
	belt_mac_st* st = (belt_mac_st*)state;
	ASSERT(memIsValid(state, beltMAC_keep()));
	// полный блок?
	if (st->filled == 16)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
#endif
		beltBlockXor(st->mac, st->s, st->block);
		st->mac[0] ^= st->r[1];
		st->mac[1] ^= st->r[2];
		st->mac[2] ^= st->r[3];
		st->mac[3] ^= st->r[0] ^ st->r[1];
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
#endif
	}
	// неполный (в т.ч. пустой) блок?
	else
	{
		st->block[st->filled] = 0x80;
		memSetZero(st->block + st->filled + 1, 16 - st->filled - 1);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
#endif
		beltBlockXor(st->mac, st->s, st->block);
		st->mac[0] ^= st->r[0] ^ st->r[3];
		st->mac[1] ^= st->r[0];
		st->mac[2] ^= st->r[1];
		st->mac[3] ^= st->r[2];
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(st->block);
#endif
	}
	beltBlockEncr2(st->mac, st->key);
}

void beltMACStepG(octet mac[8], void* state)
{
	belt_mac_st* st = (belt_mac_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltMACStepG_internal(state);
	u32To(mac, 8, st->mac);
}

void beltMACStepG2(octet mac[], size_t mac_len, void* state)
{
	belt_mac_st* st = (belt_mac_st*)state;
	ASSERT(mac_len <= 8);
	ASSERT(memIsValid(mac, mac_len));
	beltMACStepG_internal(state);
	u32To(mac, mac_len, st->mac);
}

bool_t beltMACStepV(const octet mac[8], void* state)
{
	belt_mac_st* st = (belt_mac_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltMACStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	st->mac[0] = u32Rev(st->mac[0]);
	st->mac[1] = u32Rev(st->mac[1]);
#endif
	return memEq(mac, st->mac, 8);
}

bool_t beltMACStepV2(const octet mac[], size_t mac_len, void* state)
{
	belt_mac_st* st = (belt_mac_st*)state;
	ASSERT(mac_len <= 8);
	ASSERT(memIsValid(mac, mac_len));
	beltMACStepG_internal(st);
#if (OCTET_ORDER == BIG_ENDIAN)
	st->mac[0] = u32Rev(st->mac[0]);
	st->mac[1] = u32Rev(st->mac[1]);
#endif
	return memEq(mac, st->mac, mac_len);
}

err_t beltMAC(octet mac[8], const void* src, size_t count,
	const octet key[], size_t len)
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(key, len) ||
		!memIsValid(mac, 8))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltMAC_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// выработать имитовставку
	beltMACStart(state, key, len);
	beltMACStepA(src, count, state);
	beltMACStepG(mac, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
