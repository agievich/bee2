/*
*******************************************************************************
\file btok_sm.c
\brief STB 34.101.79 (btok): Secure Messaging
\project bee2 [cryptographic library]
\created 2022.10.31
\version 2022.11.01
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/apdu.h"
#include "bee2/core/blob.h"
#include "bee2/core/der.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/btok.h"

/*
*******************************************************************************
Базовая криптография
*******************************************************************************
*/

typedef struct {
	octet key1[32];		/*!< ключ belt-mac */
	octet key2[32];		/*!< ключ belt-cfb */
	octet ctr[16];		/*!< счетчик */
	octet stack[];		/*!< стек */
} btok_sm_st;

size_t btokSM_keep()
{
	return sizeof(btok_sm_st) + utilMax(3,
		beltKRP_keep(), beltMAC_keep(), beltCFB_keep());
}

void btokSMStart(void* state, const octet key[32])
{
	btok_sm_st* st = (btok_sm_st*)state;
	// pre
	ASSERT(memIsDisjoint2(key, 32, state, btokSM_keep()));
	// key_i <- belt-keyrep(key, 0, <i>, 32);
	memSetZero(st->ctr, 16);
	beltKRPStart(st->stack, key, 32, st->ctr);
	st->ctr[0] = 1;
	beltKRPStepG(st->key1, 32, st->ctr, st->stack);
	st->ctr[1] = 2;
	beltKRPStepG(st->key2, 32, st->ctr, st->stack);
	// ctr <- 0
	st->ctr[0] = 0;
}

static void btokSMCtrInc(octet ctr[16])
{
	register word carry = 1;
	size_t pos;
	// pre
	ASSERT(memIsValid(ctr, 16));
	// инкремент
	for (pos = 0; pos < 16; ++pos)
		carry += ctr[pos], ctr[pos] = (octet)carry, carry >>= 8;
	carry = 0;
}

/*
*******************************************************************************
APDU
*******************************************************************************
*/

static size_t apduCmdCDFLenLen(const apdu_cmd_t* cmd)
{
	ASSERT(apduCmdIsValid(cmd));
	if (cmd->cdf_len == 0)
		return 0;
	if (cmd->cdf_len < 256 && cmd->rdf_len <= 256)
		return 1;
	return 3;
}

static size_t apduCmdCDFLenLen2(size_t cdf_len)
{
	if (cdf_len >= 65536)
		return SIZE_MAX;
	if (cdf_len == 0)
		return 0;
	if (cdf_len < 256)
		return 1;
	return 3;
}

static size_t apduCmdRDFLenLen(const apdu_cmd_t* cmd)
{
	ASSERT(apduCmdIsValid(cmd));
	if (cmd->rdf_len == 0)
		return 0;
	if (cmd->cdf_len < 256 && cmd->rdf_len <= 256)
		return 1;
	if (cmd->cdf_len == 0)
		return 2;
	return 3;
}

/*
*******************************************************************************
Кодирование и защита команды

Установка защиты:
  CLA INS P1 P2 Lc CDF Le -> CLA* INS P1 P2 Lc* CDF* Le*:
    CLA* = CLA | 0x04
	Lc* = len(CDF*)
	CDF* = [der(0x87, 0x02 || encr(CDF)) ||] [der(0x97, Le) ||] der(0x8E, tag)
	Le* = 0x00 (len(Lc*) == 1) или 0x000000 (len(Lc*) == 3) 
*******************************************************************************
*/

err_t btokSMCmdWrap(octet apdu[], size_t* count, const apdu_cmd_t* cmd,
	void* state)
{
	btok_sm_st* st;
	size_t cdf_len;
	size_t cdf_len_len;
	size_t rdf_len_len;
	size_t offset;
	// входной контроль
	if (!memIsNullOrValid(state, btokSM_keep()) ||
		!memIsValid(count, B_PER_S))
		return ERR_BAD_INPUT;
	// корректная команда?
	// команду нужно защитить, а она еще не защищена?
	if (!apduCmdIsValid(cmd) || state && (cmd->cla & 0x04))
		return ERR_BAD_APDU;
	// кодировать
	*count = apduCmdEnc(apdu, cmd);
	if (*count == SIZE_MAX)
		return ERR_BAD_APDU;
	// защита не нужна?
	if (!state)
		return ERR_OK;
	ASSERT(memIsDisjoint2(
		cmd, sizeof(apdu_cmd_t) + cmd->cdf_len, state, btokSM_keep()));
	// новая длина cdf
	cdf_len = cmd->cdf_len;
	if (cmd->cdf_len)
	{
		ASSERT(derTLEnc(0, 0x87, cmd->cdf_len + 1) != SIZE_MAX);
		cdf_len += derTLEnc(0, 0x87, cmd->cdf_len + 1) + 1;
	}
	if (cmd->rdf_len)
	{
		ASSERT(derEnc(0, 0x97, 0, apduCmdRDFLenLen(cmd)) != SIZE_MAX);
		cdf_len += derEnc(0, 0x97, 0, apduCmdRDFLenLen(cmd));
	}
	ASSERT(derEnc(0, 0x8E, 0, 8) != SIZE_MAX);
	cdf_len += derEnc(0, 0x8E, 0, 8);
	// новая длина длины cdf
	cdf_len_len = apduCmdCDFLenLen2(cdf_len);
	if (cdf_len_len == SIZE_MAX)
		return ERR_BAD_APDU;
	// новая длина длины rdf
	rdf_len_len = cdf_len_len;
	// общая длина
	*count = 4 + cdf_len_len + cdf_len + rdf_len_len;
	// только длина?
	if (!apdu)
		return ERR_OK;
	// проверить выходной буфер
	if (!memIsValid(apdu, *count))
		return ERR_BAD_INPUT;
	ASSERT(memIsDisjoint2(apdu, *count, state, btokSM_keep()));
	// увеличить счетчик
	st = (btok_sm_st*)state;
	btokSMCtrInc(st->ctr);
	// перекодировать заголовок
	offset = 0;
	apdu[0] |= 0x04;
	offset += 4;
	// перейти к cdf
	offset += cdf_len_len;
	// обработать cdf
	if (cmd->cdf_len)
	{
		// кодировать TL
		ASSERT(derTLEnc(apdu + offset, 0x87, cmd->cdf_len + 1) != SIZE_MAX);
		offset += derTLEnc(apdu + offset, 0x87, cmd->cdf_len + 1);
		// подготовить значение
		memMove(apdu + offset + 1, apdu + apduCmdCDFLenLen(cmd), cmd->cdf_len);
		apdu[offset] = 0x02;
		++offset;
		// зашифровать
		beltCFBStart(st->stack, st->key2, 32, st->ctr);
		beltCFBStepE(apdu + offset, cmd->cdf_len, st->stack);
		// дальше
		offset += cmd->cdf_len;
	}
	// теперь можно перекодировать Lc
	ASSERT(cdf_len_len == 1 || cdf_len_len == 3);
	if (cdf_len_len == 1)
		apdu[4] = (octet)cdf_len;
	else
	{
		apdu[4] = 0;
		apdu[5] = (octet)(cdf_len / 256);
		apdu[6] = (octet)cdf_len;
	}
	// обработать длину rdf
	if (cmd->rdf_len)
	{
		size_t l = apduCmdRDFLenLen(cmd);
		// кодировать TL
		ASSERT(derTLEnc(apdu + offset, 0x97, l) != SIZE_MAX);
		offset += derTLEnc(apdu + offset, 0x97, l);
		// кодировать значение
		ASSERT(1 <= l && l <= 3);
		if (l == 1)
			apdu[offset] = (octet)(cmd->rdf_len);
		else if (l == 2)
		{
			apdu[offset] = (octet)(cmd->cdf_len / 256);
			apdu[offset + 1] = (octet)cmd->cdf_len;
		}
		else
		{
			apdu[offset] = 0;
			apdu[offset + 1] = (octet)(cmd->cdf_len / 256);
			apdu[offset + 2] = (octet)cmd->cdf_len;
		}
		// дальше
		offset += l;
	}
	// вычислить имитовставку
	beltMACStart(st->stack, st->key1, 32);
	ASSERT(offset >= 4 + cdf_len_len);
	beltMACStepA(apdu + 4 + cdf_len_len, offset - 4 - cdf_len_len, st->stack);
	ASSERT(derTLEnc(apdu + offset, 0x8E, 8) != SIZE_MAX);
	offset += derTLEnc(apdu + offset, 0x8E, 8);
	beltMACStepG(apdu + offset, st->stack);
	offset += 8;
	// кодировать новую длину rdf
	memSetZero(apdu + offset, rdf_len_len);
	offset += rdf_len_len;
	ASSERT(offset == *count);
	// завершить
	return ERR_OK;
}
