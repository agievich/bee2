/*
*******************************************************************************
\file bels-test.c
\brief Tests for STB 34.101.60 (bels)
\project bee2/test
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.06.27
\version 2015.08.24
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/brng.h>

/*
*******************************************************************************
Самотестирование

-#	Выполняются тесты из приложения  к СТБ 34.101.60.
-#	Номера тестов соответствуют номерам таблиц приложения.
*******************************************************************************
*/

bool_t belsTest()
{
	size_t len, num;
	octet m0[32];
	octet mi[32 * 5];
	octet s[32];
	octet si[32 * 5];
	char id[] = "Alice";
	octet echo_state[64];
	octet combo_state[512];
	// проверить состояния
	ASSERT(sizeof(echo_state) >= prngEcho_keep());
	ASSERT(sizeof(combo_state) >= prngCOMBO_keep());
	// проверить таблицы A.1 -- A.4
	for (len = 16; len <= 32; len += 8)
	for (num = 0; num <= 16; ++num)
	{
		if (belsStdM(mi, len, num) != ERR_OK)
			return FALSE;
		if (belsValM(mi, len) != ERR_OK)
			return FALSE;
	}
	// сгенерировать общие ключи
	prngCOMBOStart(combo_state, utilNonce32());
	if (belsGenM0(m0, 16, prngCOMBOStepG, combo_state) != ERR_OK ||
		belsValM(m0, 16) != ERR_OK)
		return FALSE;
	if (belsGenM0(m0, 24, prngCOMBOStepG, combo_state) != ERR_OK ||
		belsValM(m0, 24) != ERR_OK)
		return FALSE;
	if (belsGenM0(m0, 32, prngCOMBOStepG, combo_state) != ERR_OK ||
		belsValM(m0, 32) != ERR_OK)
		return FALSE;
	// тест Б.1
	belsStdM(m0, 16, 0);
	if (belsGenMid(mi, 16, m0, (const octet*)id, strLen(id)) != ERR_OK ||
		belsValM(mi, 16) != ERR_OK ||
		!memEqHex(mi, 
		"F9D6F31B5DB0BB61F00E17EEF2E6007F"))
		return FALSE;
	belsStdM(m0, 24, 0);
	if (belsGenMid(mi, 24, m0, (const octet*)id, strLen(id)) != ERR_OK ||
		belsValM(mi, 24) != ERR_OK ||
		!memEqHex(mi, 
		"09EA79297F94A3E43A3885FC0D1BB8FD"
		"D0DF86FD313CEF46"))
		return FALSE;
	belsStdM(m0, 32, 0);
	if (belsGenMid(mi, 32, m0, (const octet*)id, strLen(id)) != ERR_OK ||
		belsValM(mi, 32) != ERR_OK ||
		!memEqHex(mi,
		"D53CC51BE1F976F1032A00D9CD0E190E"
		"62C37FFD233E8A9DF14C85F85C51A045"))
		return FALSE;
	// проверка belsGenMi
	for (len = 16; len <= 32; len += 8)
	{
		belsStdM(m0, len, 0);
		if (belsGenMi(mi, len, m0, prngCOMBOStepG, combo_state) != ERR_OK || 
			belsValM(mi, len) != ERR_OK)
			return FALSE;
	}
	// проверка belsShare
	for (len = 16; len <= 32; len += 8)
	{
		// загрузить открытые ключи
		belsStdM(m0, len, 0);
		belsStdM(mi + 0 * len, len, 1);
		belsStdM(mi + 1 * len, len, 2);
		belsStdM(mi + 2 * len, len, 3);
		belsStdM(mi + 3 * len, len, 4);
		belsStdM(mi + 4 * len, len, 5);
		// инициализировать эхо-генератор
		prngEchoStart(echo_state, beltGetH() + 128, 128);
		// разделить секрет
		if (belsShare(si, 5, 3, len, beltGetH(), m0, mi, prngEchoStepG, 
			echo_state) != ERR_OK)
			return FALSE;
		if (len == 16 && !memEqHex(si,
			"E27D0CFD31C557BC37C3897DCFF2C7FC"
			"50BB9EECBAEF52DDB811BCDE1495441D"
			"A92473F6796683534AD115812A3F9950"
			"9A8331FD945D58E6D8723E4744FB1DA9"
			"51913D18C8625C5AB0812133FB643D66"))
			return FALSE;
		if (len == 24 && !memEqHex(si,
			"8D0EBB0C67A315C214B34A5D68E9712A"
			"12F7B43287E3138A2506EB8283D85553"
			"18479D278A752B04E9B5E6CC43543403"
			"E5B885E65E69ADD330D08268EC3D0A44"
			"B04B8E142CDDDD5CE85B368A66489AFE"
			"0E73D3D0EEB6A210CF0629C275AB1E94"
			"ED6CD8B56C37C03EE4FF04AE2A975AAA"
			"748AA0E97AA0DE20"))
			return FALSE;
		if (len == 32 && !memEqHex(si,
			"27EC2268C7A06E7CC54F66FC3D357298"
			"4D4D4EF69916EB8D1EAFDFA420217ADC"
			"20E06235E355CC433E2AF2F4100C636F"
			"3BFAB861A4390614E42BC17577BCBE42"
			"1E14B1E795CED216AAC5BB526EFC786C"
			"5BCE1F1865D3886ED4DD7D9EFEF77F39"
			"62EFAD2544718293262E2CB74A396B50"
			"B6D8843DF5E2F0EEFFFE6CD18722765E"
			"71ADE959FC88CCBB1C521FA9A1168C184"
			"619832AB66265E08A65DD48EE406418"))
			return FALSE;
		// восстановить секрет
		if (belsRecover(s, 1, len, si, m0, mi) != ERR_OK ||
			memEq(s, beltGetH(), len))
			return FALSE;
		if (belsRecover(s, 2, len, si, m0, mi) != ERR_OK ||
			memEq(s, beltGetH(), len))
			return FALSE;
		if (belsRecover(s, 3, len, si, m0, mi) != ERR_OK ||
			!memEq(s, beltGetH(), len))
			return FALSE;
		if (belsRecover(s, 4, len, si, m0, mi) != ERR_OK ||
			!memEq(s, beltGetH(), len))
			return FALSE;
		if (belsRecover(s, 5, len, si, m0, mi) != ERR_OK ||
			!memEq(s, beltGetH(), len))
			return FALSE;
	}
	// все нормально
	return TRUE;
}
