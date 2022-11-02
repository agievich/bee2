/*
*******************************************************************************
\file apdu.c
\brief Smart card Application Protocol Data Unit
\project bee2 [cryptographic library]
\created 2022.10.31
\version 2022.11.02
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/apdu.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Команда

Логика декодирования:
1. Если Lc = 0, то len(apdu) in {4, 5, 7}, причем если len(apdu) == 7,
   то apdu[5] == 0.
2. Если Lc > 0, то len(apdu) >= 6, причем если len(apdu) == 7, то apdu[5] != 0.
3. Итак, Lc == 0 <=> len(apdu) in {4, 5} или len(apdu) == 7 и apdu[5] == 0.
*******************************************************************************
*/

#define apduCmdSizeof(cmd) (sizeof(apdu_cmd_t) + (cmd)->cdf_len)

bool_t apduCmdIsValid(const apdu_cmd_t* cmd)
{
	return memIsValid(cmd, sizeof(apdu_cmd_t)) &&
		cmd->cdf_len < 65536 &&
		memIsValid(cmd->cdf, cmd->cdf_len) &&
		cmd->rdf_len <= 65536;
}

size_t apduCmdEnc(octet apdu[], const apdu_cmd_t* cmd)
{
	size_t count;
	// pre
	ASSERT(apduCmdIsValid(cmd));
	// кодировать заголовок
	if (apdu)
	{
		ASSERT(memIsDisjoint2(apdu, 4, cmd, apduCmdSizeof(cmd)));
		apdu[0] = cmd->cla, apdu[1] = cmd->ins;
		apdu[2] = cmd->p1, apdu[3] = cmd->p2;
		apdu += 4;
	}
	count = 4;
	// кодировать [cdf_len]cdf: пустая форма
	if (cmd->cdf_len == 0)
		count += 0 + cmd->cdf_len;
	// кодировать [cdf_len]cdf: короткая форма
	else if (cmd->cdf_len < 256 && cmd->rdf_len <= 256)
	{
		if (apdu)
		{
			ASSERT(memIsDisjoint2(apdu, 1, cmd, apduCmdSizeof(cmd)));
			apdu[0] = (octet)cmd->cdf_len;
			memCopy(apdu + 1, cmd->cdf, cmd->cdf_len);
			apdu += 1 + cmd->cdf_len;
		}
		count += 1 + cmd->cdf_len;
	}
	// кодировать [cdf_len]cdf: длинная форма
	else
	{
		ASSERT(cmd->cdf_len < 65536);
		if (apdu)
		{
			ASSERT(memIsDisjoint2(apdu, 3, cmd, apduCmdSizeof(cmd)));
			apdu[0] = 0;
			apdu[1] = (octet)(cmd->cdf_len / 256);
			apdu[2] = (octet)cmd->cdf_len;
			memCopy(apdu + 3, cmd->cdf, cmd->cdf_len);
			apdu += 3 + cmd->cdf_len;
		}
		count += 3 + cmd->cdf_len;
	}
	// кодировать rdf_len: пустая форма
	if (cmd->rdf_len == 0)
		count += 0;
	// кодировать rdf_len: короткая форма
	else if (cmd->rdf_len <= 256 && cmd->cdf_len < 256)
	{
		if (apdu)
		{
			ASSERT(memIsDisjoint2(apdu, 1, cmd, apduCmdSizeof(cmd)));
			apdu[0] = (octet)cmd->rdf_len;
		}
		count += 1;
	}
	// кодировать rdf_len: длинная форма, 2 октета
	else if (cmd->cdf_len)
	{ 
		ASSERT(256 <= cmd->cdf_len || 256 < cmd->rdf_len);
		ASSERT(cmd->rdf_len <= 65536);
		if (apdu)
		{
			ASSERT(memIsDisjoint2(apdu, 2, cmd, apduCmdSizeof(cmd)));
			apdu[0] = (octet)(cmd->cdf_len / 256);
			apdu[1] = (octet)cmd->cdf_len;
		}
		count += 2;
	}
	else
	{
		ASSERT(256 < cmd->rdf_len && cmd->rdf_len <= 65536);
		if (apdu)
		{
			ASSERT(memIsDisjoint2(apdu, 3, cmd, apduCmdSizeof(cmd)));
			apdu[0] = 0;
			apdu[1] = (octet)(cmd->cdf_len / 256);
			apdu[2] = (octet)cmd->cdf_len;
		}
		count += 3;
	}
	// возвратить длину кода
	return count;
}

size_t apduCmdDec(apdu_cmd_t* cmd, const octet apdu[], size_t count)
{
	size_t cdf_len_len;
	size_t cdf_len;
	size_t rdf_len;
	// pre
	ASSERT(memIsValid(apdu, count));
	ASSERT(memIsNullOrValid(cmd, sizeof(apdu_cmd_t)));
	// декодировать заголовок
	if (count < 4)
		return SIZE_MAX;
	if (cmd)
	{
		ASSERT(memIsDisjoint2(cmd, sizeof(apdu_cmd_t), apdu, count));
		memSetZero(cmd, sizeof(apdu_cmd_t));
		cmd->cla = apdu[0], cmd->ins = apdu[1];
		cmd->p1 = apdu[2], cmd->p2 = apdu[3];
	}
	apdu += 4, count -= 4;
	// декодировать cdf_len
	if (count == 0 || count == 1 || count == 3 && apdu[0] == 0)
		cdf_len_len = 0, cdf_len = 0;
	else
	{
		ASSERT(count > 1);
		// короткая форма?
		if (apdu[0])
			cdf_len_len = 1, cdf_len = apdu[0];
		// длинная форма?
		else
		{
			if (count < 3)
				return SIZE_MAX;
			cdf_len_len = 3;
			cdf_len = apdu[1], cdf_len *= 256, cdf_len += apdu[2];
		}
		apdu += cdf_len_len, count -= cdf_len_len;
	}
	// декодировать cdf
	if (cdf_len > count)
		return SIZE_MAX;
	if (cmd)
		memCopy(cmd->cdf, apdu, cdf_len);
	apdu += cdf_len, count -= cdf_len;
	// декодировать rdf_len
	switch (count)
	{
	case 0:
		rdf_len = 0;
		break;
	case 1:
		// короткая форма
		rdf_len = apdu[0];
		if (rdf_len == 0)
			rdf_len = 256;
		if (cdf_len_len == 3)
			return SIZE_MAX;
		break;
	case 2:
		// длинная форма, 2 октета
		rdf_len = apdu[0], rdf_len *= 256, rdf_len += apdu[1];
		if (rdf_len == 0)
			rdf_len = 65536;
		if (cdf_len_len == 0 || cdf_len_len == 1 ||
			cdf_len < 256 && rdf_len <= 256)
			return SIZE_MAX;
		break;
	case 3:
		// длинная форма, 3 октета
		rdf_len = apdu[1], rdf_len *= 256, rdf_len += apdu[2];
		if (rdf_len == 0)
			rdf_len = 65536;
		if (apdu[0] != 0 || cdf_len_len == 1 ||
			cdf_len < 256 && rdf_len <= 256)
			return SIZE_MAX;
		break;
	default:
		return SIZE_MAX;
	}
	// сохранить длины
	if (cmd)
		cmd->cdf_len = cdf_len, cmd->rdf_len = rdf_len;
	// возвратить размер cmd
	return sizeof(apdu_cmd_t) + cdf_len;
}

/*
*******************************************************************************
Ответ
*******************************************************************************
*/

bool_t apduRespIsValid(const apdu_resp_t* resp)
{
	return memIsValid(resp, sizeof(apdu_resp_t)) &&
		resp->rdf_len <= 65536 &&
		memIsValid(resp->rdf, resp->rdf_len);
}

size_t apduRespEnc(octet apdu[], const apdu_resp_t* resp)
{
	// pre
	ASSERT(apduRespIsValid(resp));
	// кодировать
	if (apdu)
	{
		ASSERT(memIsValid(apdu, resp->rdf_len + 2));
		memCopy(apdu, resp->rdf, resp->rdf_len);
		apdu[resp->rdf_len] = resp->sw1, apdu[resp->rdf_len + 1] = resp->sw2;
	}
	// возвратить длину кода
	return resp->rdf_len + 2;
}

size_t apduRespDec(apdu_resp_t* resp, const octet apdu[], size_t count)
{
	// pre
	ASSERT(memIsValid(apdu, count));
	ASSERT(memIsNullOrValid(resp, sizeof(apdu_resp_t)));
	// декодировать
	if (count < 2)
		return SIZE_MAX;
	if (resp)
	{
		memSetZero(resp, sizeof(apdu_resp_t));
		resp->sw1 = apdu[count - 2], resp->sw2 = apdu[count - 1];
		resp->rdf_len = count - 2;
		memCopy(resp->rdf, apdu, resp->rdf_len);
	}
	// возвратить размер resp
	return sizeof(apdu_resp_t) + count - 2;
}
