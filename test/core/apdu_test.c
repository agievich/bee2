/*
*******************************************************************************
\file apdu_test.c
\brief Tests for APDU formats
\project bee2/test
\created 2022.10.31
\version 2023.03.30
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/apdu.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Тестирование

- used https://habr.com/ru/post/439574/
*******************************************************************************
*/

bool_t apduTest()
{
	octet stack[2048];
	apdu_cmd_t* cmd = (apdu_cmd_t*)stack;
	apdu_cmd_t* cmd1 = (apdu_cmd_t*)(stack + 1024);
	apdu_resp_t* resp = (apdu_resp_t*)stack;
	apdu_resp_t* resp1 = (apdu_resp_t*)(stack + 1024);
	octet apdu[1024];
	size_t count;
	size_t count1;
	// cmd: точечный тест
	memSetZero(cmd, sizeof(apdu_cmd_t));
	cmd->cla = 0x00, cmd->ins = 0xA4, cmd->p1 = 0x04, cmd->p2 = 0x04;
	cmd->cdf_len = 4, cmd->rdf_len = 256;
	hexTo(cmd->cdf, "54657374");
	count = apduCmdEnc(0, cmd);
	if (count > sizeof(apdu) ||
		count != 10 ||
		apduCmdEnc(apdu, cmd) != count ||
		!hexEq(apdu, "00A40404045465737400"))
		return FALSE;
	count1 = apduCmdDec(0, apdu, count);
	if (count1 > sizeof(stack) / 2 ||
		count1 != sizeof(apdu_cmd_t) + 4 ||
		apduCmdDec(cmd1, apdu, count) != count1 || 
		!memEq(cmd, cmd1, count1))
		return FALSE;
	// cmd: сочетания длин
	cmd->cla = 0x00, cmd->ins = 0xA4, cmd->p1 = 0x04, cmd->p2 = 0x04;
	memSet(cmd->cdf, 0x36, 257);
	for (cmd->cdf_len = 0; cmd->cdf_len <= 257; ++cmd->cdf_len)
		for (cmd->rdf_len = 0; cmd->rdf_len <= 257; ++cmd->rdf_len)
		{
			count = apduCmdEnc(0, cmd);
			if (count > sizeof(apdu) ||
				apduCmdEnc(apdu, cmd) != count)
				return FALSE;
			count1 = apduCmdDec(0, apdu, count);
			if (count1 > sizeof(stack) / 2 ||
				apduCmdDec(cmd1, apdu, count) != count1 ||
				!memEq(cmd, cmd1, count1))
				return FALSE;
		}
	// resp: точечный тест
	memSetZero(resp, sizeof(apdu_resp_t));
	resp->sw1 = 0x90, resp->sw2 = 0x00;
	cmd->rdf_len = 20;
	hexTo(resp->rdf, "E012C00401FF8010C00402FF8010C00403FF8010");
	count = apduRespEnc(0, resp);
	if (count > sizeof(apdu) ||
		count != 22 ||
		apduRespEnc(apdu, resp) != count ||
		!hexEq(apdu, "E012C00401FF8010C00402FF8010C00403FF80109000"))
		return FALSE;
	count1 = apduRespDec(0, apdu, count);
	if (count1 > sizeof(stack) / 2 ||
		count1 != sizeof(apdu_resp_t) + 20 ||
		apduRespDec(resp1, apdu, count) != count1 ||
		!memEq(resp, resp1, count1))
		return FALSE;
	// все нормально
	return TRUE;
}
