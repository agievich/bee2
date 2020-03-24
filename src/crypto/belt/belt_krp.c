/*
*******************************************************************************
\file belt_krp.c
\brief STB 34.101.31 (belt): KRP (keyrep = key diversification + meshing)
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
Преобразование ключа
*******************************************************************************
*/

typedef struct {
	u32 key[8];			/*< форматированный первоначальный ключ */
	size_t len;			/*< длина первоначального ключа */
	u32 block[8];		/*< блок r || level || header */
	u32 key_new[8];		/*< форматированный преобразованный ключ */
	octet stack[];		/*< стек beltCompr */
} belt_krp_st;

size_t beltKRP_keep()
{
	return sizeof(belt_krp_st) + beltCompr_deep();
}

void beltKRPStart(void* state, const octet key[], size_t len, 
	const octet level[12])
{
	belt_krp_st* st = (belt_krp_st*)state;
	ASSERT(memIsDisjoint2(level, 12, state, beltKRP_keep()));
	// block <- ... || level || ...
	u32From(st->block + 1, level, 12);
	// сохранить ключ
	beltKeyExpand2(st->key, key, st->len = len);
}

void beltKRPStepG(octet key_[], size_t key_len, const octet header[16],
	void* state)
{
	belt_krp_st* st = (belt_krp_st*)state;
	// pre
	ASSERT(memIsValid(state, beltKRP_keep()));
	ASSERT(key_len == 16 || key_len == 24 || key_len == 32);
	ASSERT(key_len <= st->len);
	ASSERT(memIsDisjoint2(key_, key_len, state, beltKRP_keep()));
	ASSERT(memIsDisjoint2(header, 16, state, beltKRP_keep()));
	// полностью определить st->block
	u32From(st->block, beltH() + 4 * (st->len - 16) + 2 * (key_len - 16), 4);
	u32From(st->block + 4, header, 16);
	// применить belt-compr2
	beltBlockCopy(st->key_new, st->key);
	beltBlockCopy(st->key_new + 4, st->key + 4);
	beltCompr(st->key_new, st->block, st->stack);
	// выгрузить ключ
	u32To(key_, key_len, st->key_new);
}

err_t beltKRP(octet dest[], size_t m, const octet src[], size_t n,
	const octet level[12], const octet header[16])
{
	void* state;
	// проверить входные данные
	if (m > n ||
		m != 16 && m != 24 && m != 32 ||
		n != 16 && n != 24 && n != 32 ||
		!memIsValid(src, n) ||
		!memIsValid(level, 12) ||
		!memIsValid(header, 16) ||
		!memIsValid(dest, m))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltKRP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// преобразовать ключ
	beltKRPStart(state, src, n, level);
	beltKRPStepG(dest, m, header, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
