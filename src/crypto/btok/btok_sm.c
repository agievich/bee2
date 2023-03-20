/*
*******************************************************************************
\file btok_sm.c
\brief STB 34.101.79 (btok): Secure Messaging
\project bee2 [cryptographic library]
\created 2022.10.31
\version 2023.03.20
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
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

Создание защищенного соединения:
  key1 <- belt-keyrep(key, 0, <1>, 256)
  key2 <- belt-keyrep(key, 0, <2>, 256)
  ctr <- 0
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
	st->ctr[0] = 2;
	beltKRPStepG(st->key2, 32, st->ctr, st->stack);
	// ctr <- 0
	st->ctr[0] = 0;
}

void btokSMCtrInc(void* state)
{
	btok_sm_st* st = (btok_sm_st*)state;
	register word carry = 1;
	size_t pos;
	// pre
	ASSERT(memIsValid(state, btokSM_keep()));
	// инкремент
	for (pos = 0; pos < 16; ++pos)
		carry += st->ctr[pos], st->ctr[pos] = (octet)carry, carry >>= 8;
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

static size_t apduCmdRDFLenLen(const apdu_cmd_t* cmd)
{
	ASSERT(apduCmdIsValid(cmd));
	if (cmd->rdf_len == 0)
		return 0;
	if (cmd->cdf_len < 256 && cmd->rdf_len <= 256)
		return 1;
	if (cmd->cdf_len != 0)
		return 2;
	return 3;
}

/*
*******************************************************************************
Кодирование и защита команды

Установка защиты:
  CLA INS P1 P2 Lc CDF Le -> CLA* INS P1 P2 Lc* CDF* Le*:
    Lc = enc(len(CDF))
	Le = enc(len(RDF))
	CLA* = CLA | 0x04
    Lc* = enc(len(CDF*))
    CDF* = [der(0x87, 0x02 Y)] [der(0x97, Le)] der(0x8E, T)
	Le* = \perp, 0x00 или 0x0000
    Y = belt-cfb(CDF, key2, ctr)
    T = belt-mac(CLA* INS P1 P2 [der(0x87, 0x02 Y)] [der(0x97, Le), key1]

Правила формирования Le* и Lc*:
1. Если len(RDF) == 0, то Le* = \perp, а Lc* определяется обычным образом:
   len(Lc*) = 1, если len(CDF) < 256, и len(Lc*) = 3 в противном случае.
2. Если len(CDF*) < 256 и len(RDF) <= 256, то Le* = 0x00, а len(Lc*) = 1.
3. Если len(CDF*) >= 256 или len(RDF) > 256, то Le* = 0x0000, а len(Lc*) = 3.

Обратим внимание, что в последнем случае len(Lc*) = 3, даже если 
len(CDF*) < 256. Форма кодирования len(CDF*) повышается до расширенной,
чтобы соответствовать форме кодирования len(RDF).

\remark Минимальная длина защищенной команды:
  4 (hdr) + 1 (cdf_len_len) + 10 (mac) + 0 (rdf_len_len) = 15.
*******************************************************************************
*/

#define apduCmdSizeof(cmd) (sizeof(apdu_cmd_t) + (cmd)->cdf_len)

err_t btokSMCmdWrap(octet apdu[], size_t* count, const apdu_cmd_t* cmd,
	void* state)
{
	size_t cdf_len;
	size_t cdf_len_len;
	size_t rdf_len_len;
	size_t offset;
	size_t c;
	btok_sm_st* st;
	// pre
	ASSERT(memIsNullOrValid(state, btokSM_keep()));
	ASSERT(memIsNullOrValid(count, O_PER_S));
	// некорректная команда? команду нужно защитить, а она уже защищена?
	if (!apduCmdIsValid(cmd) || state && (cmd->cla & 0x04))
		return ERR_BAD_APDU;
	// кодировать без защиты
	offset = apduCmdEnc(apdu, cmd);
	if (offset == SIZE_MAX)
		return ERR_BAD_APDU;
	// состояние не задано, т.е. защита не нужна?
	if (!state)
	{
		if (count)
		{
			ASSERT(memIsDisjoint2(count, O_PER_S, cmd, apduCmdSizeof(cmd)));
			*count = offset;
		}
		return ERR_OK;
	}
	ASSERT(memIsDisjoint2(state, btokSM_keep(), cmd, apduCmdSizeof(cmd)));
	// новая длина cdf
	cdf_len = cmd->cdf_len;
	if (cmd->cdf_len)
	{
		c = derTLEnc(0, 0x87, cmd->cdf_len + 1);
		ASSERT(c != SIZE_MAX);
		cdf_len += c + 1;
	}
	if (cmd->rdf_len)
	{
		c = derEnc(0, 0x97, 0, apduCmdRDFLenLen(cmd));
		ASSERT(c != SIZE_MAX);
		cdf_len += c;
	}
	c = derEnc(0, 0x8E, 0, 8);
	ASSERT(c != SIZE_MAX);
	cdf_len += c;
	// новые длины длин cdf и rdf
	if (cmd->rdf_len == 0)
		cdf_len_len = cdf_len < 256 ? 1 : 3, rdf_len_len = 0;
	else if (cmd->rdf_len <= 256 && cdf_len < 256)
		cdf_len_len = rdf_len_len = 1;
	else
		cdf_len_len = 3, rdf_len_len = 2;
	// общая длина
	offset = 4 + cdf_len_len + cdf_len + rdf_len_len;
	// не задан выходной буфер, т.е. нужно определить только его длину?
	if (!apdu)
	{
		if (count)
		{
			ASSERT(memIsDisjoint2(count, O_PER_S, state, btokSM_keep()));
			ASSERT(memIsDisjoint2(count, O_PER_S, cmd, apduCmdSizeof(cmd)));
			*count = offset;
		}
		return ERR_OK;
	}
	ASSERT(memIsDisjoint2(apdu, offset, state, btokSM_keep()));
	ASSERT(memIsDisjoint2(apdu, offset, cmd, apduCmdSizeof(cmd)));
	// проверить счетчик
	st = (btok_sm_st*)state;
	if (st->ctr[0] % 2 != 1)
		return ERR_BAD_LOGIC;
	// уточнить заголовок
	offset = 0;
	apdu[0] |= 0x04;
	offset += 4;
	// перейти к cdf
	offset += cdf_len_len;
	// обработать cdf
	if (cmd->cdf_len)
	{
		c = derTLEnc(0, 0x87, cmd->cdf_len + 1);
		ASSERT(c != SIZE_MAX);
		// подготовить значение
		memMove(apdu + offset + c + 1,
			apdu + 4 + apduCmdCDFLenLen(cmd), cmd->cdf_len);
		apdu[offset + c] = 0x02;
		// кодировать TL
		c = derTLEnc(apdu + offset, 0x87, cmd->cdf_len + 1);
		ASSERT(c != SIZE_MAX);
		offset += c + 1;
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
		c = derTLEnc(apdu + offset, 0x97, l);
		ASSERT(c != SIZE_MAX);
		offset += c;
		// кодировать значение
		ASSERT(1 <= l && l <= 3);
		if (l == 1)
			apdu[offset] = (octet)(cmd->rdf_len);
		else if (l == 2)
		{
			apdu[offset] = (octet)(cmd->rdf_len / 256);
			apdu[offset + 1] = (octet)cmd->rdf_len;
		}
		else
		{
			apdu[offset] = 0;
			apdu[offset + 1] = (octet)(cmd->rdf_len / 256);
			apdu[offset + 2] = (octet)cmd->rdf_len;
		}
		// дальше
		offset += l;
	}
	// вычислить имитовставку
	beltMACStart(st->stack, st->key1, 32);
	beltMACStepA(apdu, 4, st->stack);
	ASSERT(offset >= 4 + cdf_len_len);
	beltMACStepA(apdu + 4 + cdf_len_len, offset - 4 - cdf_len_len, st->stack);
	c = derTLEnc(apdu + offset, 0x8E, 8);
	ASSERT(c != SIZE_MAX);
	offset += c;
	beltMACStepG(apdu + offset, st->stack);
	offset += 8;
	// кодировать новую длину rdf
	memSetZero(apdu + offset, rdf_len_len);
	offset += rdf_len_len;
	// возвратить длину
	if (count)
	{
		ASSERT(memIsDisjoint2(count, O_PER_S, state, btokSM_keep()));
		ASSERT(memIsDisjoint2(count, O_PER_S, cmd, apduCmdSizeof(cmd)));
		ASSERT(memIsDisjoint2(count, O_PER_S, apdu, offset));
		*count = offset;
	}
	// завершить
	return ERR_OK;
}

err_t btokSMCmdUnwrap(apdu_cmd_t* cmd, size_t* size, const octet apdu[],
	size_t count, void* state)
{
	size_t len;
	size_t offset;
	size_t c1, c2, c3;
	size_t cdf_len;
	size_t cdf_len_len;
	const octet* cdf;
	size_t rdf_len;
	const octet* mac;
	btok_sm_st* st;
	// pre
	ASSERT(memIsValid(apdu, count));
	ASSERT(memIsNullOrValid(state, btokSM_keep()));
	ASSERT(memIsNullOrValid(cmd, sizeof(apdu_cmd_t)));
	// слишком короткая командв?
	// нужно снять защиту с незащищенной команды?
	// невозможно снять защиту?
	if (count < 4 || state && count < 15 ||
		state && (apdu[0] & 0x04) == 0 ||
		!state && (apdu[0] & 0x04) != 0)
		return ERR_BAD_APDU;
	// декодировать без снятия защиты?
	if (!state)
	{
		offset = apduCmdDec(cmd, apdu, count);
		if (offset == SIZE_MAX)
			return ERR_BAD_APDU;
		if (size)
		{
			ASSERT(memIsDisjoint2(size, O_PER_S, apdu, count));
			ASSERT(cmd == 0 ||
				memIsDisjoint2(size, O_PER_S, cmd, apduCmdSizeof(cmd)));
			*size = offset;
		}
		return ERR_OK;
	}
	ASSERT(memIsDisjoint2(state, btokSM_keep(), apdu, count));
	// разобрать длину защищенного поля cdf
	if (apdu[4] != 0)
	{
		len = apdu[4];
		cdf_len_len = 1;
	}
	else
	{
		len = apdu[5], len *= 256, len += apdu[6];
		cdf_len_len = 3;
		if (apdu[4] != 0)
			return ERR_BAD_APDU;
	}
	offset = 4 + cdf_len_len;
	// проверить длину кода
	if (4 + cdf_len_len + len > count || 4 + cdf_len_len + len + 2 < count)
		return ERR_BAD_APDU;
	// разобрать защищенное поле cdf: шифртекст
	c1 = derDec2(&cdf, &cdf_len, apdu + offset, len, 0x87);
	if (c1 != SIZE_MAX)
	{
		if (cdf_len < 2 || cdf[0] != 0x02)
			return ERR_BAD_APDU;
		++cdf, --cdf_len;
	}
	else
		c1 = cdf_len = 0;
	// разобрать защищенное поле cdf: rdf_len
	{
		const octet* val;
		size_t rdf_len_len;
		c2 = derDec2(&val, &rdf_len_len, apdu + offset + c1, len - c1, 0x97);
		if (c2 != SIZE_MAX)
		{
			if (rdf_len_len == 0 || rdf_len_len > 3)
				return ERR_BAD_APDU;
			else if (rdf_len_len == 1)
			{
				rdf_len = val[0];
				if (rdf_len == 0)
					rdf_len = 256;
				if (cdf_len >= 256)
					return ERR_BAD_APDU;
			}
			else if (rdf_len_len == 2)
			{
				rdf_len = val[0], rdf_len *= 256, rdf_len += val[1];
				if (rdf_len == 0)
					rdf_len = 65536;
				if (cdf_len < 256 && rdf_len <= 256 || cdf_len == 0)
					return ERR_BAD_APDU;
			}
			else
			{
				rdf_len = val[1], rdf_len *= 256, rdf_len += val[2];
				if (rdf_len == 0)
					rdf_len = 65536;
				if (val[0] != 0 || cdf_len != 0 || rdf_len <= 256)
					return ERR_BAD_APDU;
			}
		}
		else
			c2 = rdf_len = 0;
		// еще раз проверить длину кода, а также его завершение 
		// (мы только сейчас узнали rdf_len)
		if (rdf_len == 0)
			rdf_len_len = 0;
		else if (len < 256 && rdf_len <= 256)
			rdf_len_len = 1;
		else
			rdf_len_len = 2;
		if (count != 4 + cdf_len_len + len + rdf_len_len ||
			!memIsZero(apdu + 4 + cdf_len_len + len, rdf_len_len))
			return ERR_BAD_APDU;
	}
	// разобрать защищенное поле cdf: имитовставка
	c3 = derDec3(&mac, apdu + offset + c1 + c2, len - c1 - c2, 0x8E, 8);
	if (c3 == SIZE_MAX || c1 + c2 + c3 != len)
		return ERR_BAD_APDU;
	// ограничиться проверкой формата?
	if (!cmd)
	{
		if (size)
		{
			ASSERT(memIsDisjoint2(size, O_PER_S, apdu, count));
			*size = sizeof(apdu_cmd_t) + cdf_len;
		}
		return ERR_OK;
	}
	// инкрементировать счетчик
	st = (btok_sm_st*)state;
	if (st->ctr[0] % 2 != 1)
		return ERR_BAD_LOGIC;
	// проверить имитовставку
	beltMACStart(st->stack, st->key1, 32);
	beltMACStepA(apdu, 4, st->stack);
	beltMACStepA(apdu + offset, c1 + c2, st->stack);
	if (!beltMACStepV(mac, st->stack))
		return ERR_BAD_MAC;
	// заполнить поля команды
	memSetZero(cmd, sizeof(apdu_cmd_t));
	cmd->cla = apdu[0] & 0xFB;
	cmd->ins = apdu[1], cmd->p1 = apdu[2], cmd->p2 = apdu[3];
	cmd->rdf_len = rdf_len;
	cmd->cdf_len = cdf_len;
	memCopy(cmd->cdf, cdf, cdf_len);
	ASSERT(memIsDisjoint2(cmd, apduCmdSizeof(cmd), state, btokSM_keep()));
	ASSERT(memIsDisjoint2(cmd, apduCmdSizeof(cmd), apdu, count));
	// расшифровать cdf
	if (cdf_len)
	{
		beltCFBStart(st->stack, st->key2, 32, st->ctr);
		beltCFBStepD(cmd->cdf, cdf_len, st->stack);
	}
	// возвратить размер
	if (size)
	{
		ASSERT(memIsDisjoint2(size, O_PER_S, state, btokSM_keep()));
		ASSERT(memIsDisjoint2(size, O_PER_S, apdu, count));
		ASSERT(memIsDisjoint2(size, O_PER_S, cmd, apduCmdSizeof(cmd)));
		*size = apduCmdSizeof(cmd);
	}
	// завершить
	return ERR_OK;
}

/*
*******************************************************************************
Кодирование и защита ответов

Установка защиты:
  RDF SW1 SW2 -> RDF* SW1 SW2:
	RDF* = [der(0x87, 0x02 Y)] der(0x8E, T)
	  Y = belt-cfb(RDF, key2, ctr)
	  T = belt-mac([der(0x87, 0x02 Y)] SW1 SW2, key1)

\remark Минимальная длина защищенного ответа:
  10 (mac) + 2 (sw) = 12.
*******************************************************************************
*/

#define apduRespSizeof(resp) (sizeof(apdu_resp_t) + (resp)->rdf_len)

err_t btokSMRespWrap(octet apdu[], size_t* count, const apdu_resp_t* resp,
	void* state)
{
	size_t rdf_len;
	size_t offset;
	size_t c;
	btok_sm_st* st;
	// pre
	ASSERT(memIsNullOrValid(state, btokSM_keep()));
	ASSERT(memIsNullOrValid(count, O_PER_S));
	// корректный ответ?
	if (!apduRespIsValid(resp))
		return ERR_BAD_APDU;
	// кодировать без защиты
	offset = apduRespEnc(apdu, resp);
	if (offset == SIZE_MAX)
		return ERR_BAD_APDU;
	// состояние не задано, т.е. защита не нужна?
	if (!state)
	{
		if (count)
		{
			ASSERT(memIsDisjoint2(count, O_PER_S, resp, apduRespSizeof(resp)));
			*count = offset;
		}
		return ERR_OK;
	}
	ASSERT(memIsDisjoint2(state, btokSM_keep(), resp, apduRespSizeof(resp)));
	// новая длина rdf
	rdf_len = resp->rdf_len;
	if (resp->rdf_len)
	{
		c = derTLEnc(0, 0x87, resp->rdf_len + 1);
		ASSERT(c != SIZE_MAX);
		rdf_len += c + 1;
	}
	c = derEnc(0, 0x8E, 0, 8);
	ASSERT(c != SIZE_MAX);
	rdf_len += c;
	// общая длина
	offset = rdf_len + 2;
	// не задан выходной буфер, т.е. нужно определить только его длину?
	if (!apdu)
	{
		if (count)
		{
			ASSERT(memIsDisjoint2(count, O_PER_S, state, btokSM_keep()));
			ASSERT(memIsDisjoint2(count, O_PER_S, resp, apduRespSizeof(resp)));
			*count = offset;
		}
		return ERR_OK;
	}
	ASSERT(memIsDisjoint2(apdu, offset, state, btokSM_keep()));
	ASSERT(memIsDisjoint2(apdu, offset, resp, apduRespSizeof(resp)));
	// проверить счетчик
	st = (btok_sm_st*)state;
	if (st->ctr[0] % 2 != 0)
		return ERR_BAD_LOGIC;
	// обработать rdf
	offset = 0;
	if (resp->rdf_len)
	{
		c = derTLEnc(0, 0x87, resp->rdf_len + 1);
		ASSERT(c != SIZE_MAX);
		// подготовить значение
		memMove(apdu + c + 1, apdu, resp->rdf_len);
		apdu[c] = 0x02;
		// кодировать TL
		c = derTLEnc(apdu, 0x87, resp->rdf_len + 1);
		ASSERT(c != SIZE_MAX);
		offset += c + 1;
		// зашифровать
		beltCFBStart(st->stack, st->key2, 32, st->ctr);
		beltCFBStepE(apdu + offset, resp->rdf_len, st->stack);
		// дальше
		offset += resp->rdf_len;
	}
	// вычислить имитовставку
	beltMACStart(st->stack, st->key1, 32);
	beltMACStepA(apdu, offset, st->stack);
	beltMACStepA(&resp->sw1, 1, st->stack);
	beltMACStepA(&resp->sw2, 1, st->stack);
	c = derTLEnc(apdu + offset, 0x8E, 8);
	ASSERT(c != SIZE_MAX);
	offset += c;
	beltMACStepG(apdu + offset, st->stack);
	offset += 8;
	// кодировать статусы
	apdu[offset++] = resp->sw1, apdu[offset++] = resp->sw2;
	// возвратить длину
	if (count)
	{
		ASSERT(memIsDisjoint2(count, O_PER_S, state, btokSM_keep()));
		ASSERT(memIsDisjoint2(count, O_PER_S, resp, apduRespSizeof(resp)));
		ASSERT(memIsDisjoint2(count, O_PER_S, apdu, offset));
		*count = offset;
	}
	// завершить
	return ERR_OK;
}

err_t btokSMRespUnwrap(apdu_resp_t* resp, size_t* size, const octet apdu[],
	size_t count, void* state)
{
	size_t c1, c2;
	size_t rdf_len;
	const octet* rdf;
	const octet* mac;
	btok_sm_st* st;
	// pre
	ASSERT(memIsValid(apdu, count));
	ASSERT(memIsNullOrValid(state, btokSM_keep()));
	ASSERT(memIsNullOrValid(resp, sizeof(apdu_resp_t)));
	// слишком короткий ответ?
	if (count < 2 || state && count < 12)
		return ERR_BAD_APDU;
	// декодировать без снятия защиты?
	if (!state)
	{
		c1 = apduRespDec(resp, apdu, count);
		if (c1 == SIZE_MAX)
			return ERR_BAD_APDU;
		if (size)
		{
			ASSERT(memIsDisjoint2(size, O_PER_S, apdu, count));
			ASSERT(resp == 0 ||
				memIsDisjoint2(size, O_PER_S, resp, apduRespSizeof(resp)));
			*size = c1;
		}
		return ERR_OK;
	}
	ASSERT(memIsDisjoint2(state, btokSM_keep(), apdu, count));
	// разобрать защищенное поле rdf: шифртекст
	c1 = derDec2(&rdf, &rdf_len, apdu, count - 2, 0x87);
	if (c1 != SIZE_MAX)
	{
		if (rdf_len < 2 || rdf[0] != 0x02)
			return ERR_BAD_APDU;
		++rdf, --rdf_len;
	}
	else
		c1 = rdf_len = 0;
	// разобрать защищенное поле rdf: имитовставка
	c2 = derDec3(&mac, apdu + c1, count - 2 - c1, 0x8E, 8);
	if (c2 == SIZE_MAX || c1 + c2 + 2 != count)
		return ERR_BAD_APDU;
	// ограничиться проверкой формата?
	if (!resp)
	{
		if (size)
		{
			ASSERT(memIsDisjoint2(size, O_PER_S, apdu, count));
			*size = sizeof(apdu_resp_t) + rdf_len;
		}
		return ERR_OK;
	}
	// инкрементировать счетчик
	st = (btok_sm_st*)state;
	if (st->ctr[0] % 2 != 0)
		return ERR_BAD_LOGIC;
	// проверить имитовставку
	beltMACStart(st->stack, st->key1, 32);
	beltMACStepA(apdu, c1, st->stack);
	beltMACStepA(apdu + count - 2, 2, st->stack);
	if (!beltMACStepV(mac, st->stack))
		return ERR_BAD_MAC;
	// заполнить поля ответа
	memSetZero(resp, sizeof(apdu_resp_t));
	resp->sw1 = apdu[count - 2], resp->sw2 = apdu[count - 1];
	resp->rdf_len = rdf_len;
	memCopy(resp->rdf, rdf, rdf_len);
	ASSERT(memIsDisjoint2(resp, apduRespSizeof(resp), state, btokSM_keep()));
	ASSERT(memIsDisjoint2(resp, apduRespSizeof(resp), apdu, count));
	// расшифровать rdf
	if (rdf_len)
	{
		beltCFBStart(st->stack, st->key2, 32, st->ctr);
		beltCFBStepD(resp->rdf, rdf_len, st->stack);
	}
	// возвратить размер
	if (size)
	{
		ASSERT(memIsDisjoint2(size, O_PER_S, state, btokSM_keep()));
		ASSERT(memIsDisjoint2(size, O_PER_S, apdu, count));
		ASSERT(memIsDisjoint2(size, O_PER_S, resp, apduRespSizeof(resp)));
		*size = apduRespSizeof(resp);
	}
	// завершить
	return ERR_OK;
}
