/*
*******************************************************************************
\file belt_mac.c
\brief STB 34.101.31 (belt): MAC (message authentication)
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2019.06.26
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
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsValid(state, beltMAC_keep()));
	beltKeyExpand2(s->key, key, len);
	beltBlockSetZero(s->s);
	beltBlockSetZero(s->r);
	beltBlockEncr2(s->r, s->key);
	s->filled = 0;
}

void beltMACStepA(const void* buf, size_t count, void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltMAC_keep()));
	// накопить полный блок
	if (s->filled < 16)
	{
		if (count <= 16 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 16 - s->filled);
		count -= 16 - s->filled;
		buf = (const octet*)buf + 16 - s->filled;
		s->filled = 16;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltBlockEncr2(s->s, s->key);
		beltBlockCopy(s->block, buf);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltBlockEncr2(s->s, s->key);
		memCopy(s->block, buf, count);
		s->filled = count;
	}
}

static void beltMACStepG_internal(void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsValid(state, beltMAC_keep()));
	// полный блок?
	if (s->filled == 16)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor(s->mac, s->s, s->block);
		s->mac[0] ^= s->r[1];
		s->mac[1] ^= s->r[2];
		s->mac[2] ^= s->r[3];
		s->mac[3] ^= s->r[0] ^ s->r[1];
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
	}
	// неполный (в т.ч. пустой) блок?
	else
	{
		s->block[s->filled] = 0x80;
		memSetZero(s->block + s->filled + 1, 16 - s->filled - 1);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor(s->mac, s->s, s->block);
		s->mac[0] ^= s->r[0] ^ s->r[3];
		s->mac[1] ^= s->r[0];
		s->mac[2] ^= s->r[1];
		s->mac[3] ^= s->r[2];
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
	}
	beltBlockEncr2(s->mac, s->key);
}

void beltMACStepG(octet mac[8], void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltMACStepG_internal(s);
	u32To(mac, 8, s->mac);
}

void beltMACStepG2(octet mac[], size_t mac_len, void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(mac_len <= 8);
	ASSERT(memIsValid(mac, mac_len));
	beltMACStepG_internal(s);
	u32To(mac, mac_len, s->mac);
}

bool_t beltMACStepV(const octet mac[8], void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltMACStepG_internal(s);
#if (OCTET_ORDER == BIG_ENDIAN)
	s->mac[0] = u32Rev(s->mac[0]);
	s->mac[1] = u32Rev(s->mac[1]);
#endif
	return memEq(mac, s->mac, 8);
}

bool_t beltMACStepV2(const octet mac[], size_t mac_len, void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(mac_len <= 8);
	ASSERT(memIsValid(mac, mac_len));
	beltMACStepG_internal(s);
#if (OCTET_ORDER == BIG_ENDIAN)
	s->mac[0] = u32Rev(s->mac[0]);
	s->mac[1] = u32Rev(s->mac[1]);
#endif
	return memEq(mac, s->mac, mac_len);
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

