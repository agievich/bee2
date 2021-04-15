/*
*******************************************************************************
\file bels_test.c
\brief Tests for STB 34.101.60 (bels)
\project bee2/test
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.06.27
\version 2021.04.15
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
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
	octet si[33 * 5];
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
	if (belsGenM0(m0, 16, prngCOMBOStepR, combo_state) != ERR_OK ||
		belsValM(m0, 16) != ERR_OK)
		return FALSE;
	if (belsGenM0(m0, 24, prngCOMBOStepR, combo_state) != ERR_OK ||
		belsValM(m0, 24) != ERR_OK)
		return FALSE;
	if (belsGenM0(m0, 32, prngCOMBOStepR, combo_state) != ERR_OK ||
		belsValM(m0, 32) != ERR_OK)
		return FALSE;
	// тест Б.1
	belsStdM(m0, 16, 0);
	if (belsGenMid(mi, 16, m0, (const octet*)id, strLen(id)) != ERR_OK ||
		belsValM(mi, 16) != ERR_OK ||
		!hexEq(mi, 
		"F9D6F31B5DB0BB61F00E17EEF2E6007F"))
		return FALSE;
	belsStdM(m0, 24, 0);
	if (belsGenMid(mi, 24, m0, (const octet*)id, strLen(id)) != ERR_OK ||
		belsValM(mi, 24) != ERR_OK ||
		!hexEq(mi, 
		"09EA79297F94A3E43A3885FC0D1BB8FD"
		"D0DF86FD313CEF46"))
		return FALSE;
	belsStdM(m0, 32, 0);
	if (belsGenMid(mi, 32, m0, (const octet*)id, strLen(id)) != ERR_OK ||
		belsValM(mi, 32) != ERR_OK ||
		!hexEq(mi,
		"D53CC51BE1F976F1032A00D9CD0E190E"
		"62C37FFD233E8A9DF14C85F85C51A045"))
		return FALSE;
	// проверка belsGenMi
	for (len = 16; len <= 32; len += 8)
	{
		belsStdM(m0, len, 0);
		if (belsGenMi(mi, len, m0, prngCOMBOStepR, combo_state) != ERR_OK || 
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
		prngEchoStart(echo_state, beltH() + 128, 128);
		// разделить секрет (тесты Б.2 -- Б.4)
		if (belsShare(si, 5, 3, len, beltH(), m0, mi, prngEchoStepR, 
			echo_state) != ERR_OK)
			return FALSE;
		if (len == 16 && !hexEq(si,
			"E27D0CFD31C557BC37C3897DCFF2C7FC"
			"50BB9EECBAEF52DDB811BCDE1495441D"
			"A92473F6796683534AD115812A3F9950"
			"9A8331FD945D58E6D8723E4744FB1DA9"
			"51913D18C8625C5AB0812133FB643D66"))
			return FALSE;
		if (len == 24 && !hexEq(si,
			"8D0EBB0C67A315C214B34A5D68E9712A"
			"12F7B43287E3138A"
			"2506EB8283D8555318479D278A752B04"
			"E9B5E6CC43543403"
			"E5B885E65E69ADD330D08268EC3D0A44"
			"B04B8E142CDDDD5C"
			"E85B368A66489AFE0E73D3D0EEB6A210"
			"CF0629C275AB1E94"
			"ED6CD8B56C37C03EE4FF04AE2A975AAA"
			"748AA0E97AA0DE20"))
			return FALSE;
		if (len == 32 && !hexEq(si,
			"27EC2268C7A06E7CC54F66FC3D357298"
			"4D4D4EF69916EB8D1EAFDFA420217ADC"
			"20E06235E355CC433E2AF2F4100C636F"
			"3BFAB861A4390614E42BC17577BCBE42"
			"1E14B1E795CED216AAC5BB526EFC786C"
			"5BCE1F1865D3886ED4DD7D9EFEF77F39"
			"62EFAD2544718293262E2CB74A396B50"
			"B6D8843DF5E2F0EEFFFE6CD18722765E"
			"71ADE959FC88CCBB1C521FA9A1168C18"
			"4619832AB66265E08A65DD48EE406418"))
			return FALSE;
		// восстановить секрет
		if (belsRecover(s, 1, len, si, m0, mi) != ERR_OK ||
			memEq(s, beltH(), len))
			return FALSE;
		if (belsRecover(s, 2, len, si, m0, mi) != ERR_OK ||
			memEq(s, beltH(), len))
			return FALSE;
		if (belsRecover(s, 3, len, si, m0, mi) != ERR_OK ||
			!memEq(s, beltH(), len))
			return FALSE;
		if (belsRecover(s, 4, len, si, m0, mi) != ERR_OK ||
			!memEq(s, beltH(), len))
			return FALSE;
		if (belsRecover(s, 5, len, si, m0, mi) != ERR_OK ||
			!memEq(s, beltH(), len))
			return FALSE;
		// восстановить секрет (тесты Б.5 -- Б.7, строка 1)
		if (belsRecover(s, 2, len, si, m0, mi) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"6380669CA508058FA9AADF986C77C175") ||
			len == 24 && !hexEq(s, 
			"1E9811BD520C56E12B5B0E517756FA1A"
			"EE3CACC13B6313E9") ||
			len == 32 && !hexEq(s, 
			"C39C8FA8590A7855914AED9B05940D9E"
			"8A119B130D939B8799889C938D1E078D"))
			return FALSE;
		// восстановить секрет (тесты Б.5 -- Б.7, строка 5)
		if (belsRecover(s, 2, len, si + len, m0, mi + len) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"E8BA837676967C5C939DBF5172C9AB4F") ||
			len == 24 && !hexEq(s, 
			"AF8AB8304FEBD5CF89D643A850C77165"
			"7310CA0E8EDF9C60") ||
			len == 32 && !hexEq(s, 
			"31C06C2BF7AF38C2A6870A7F1B7BA9CC"
			"1A741DD96374A4D17A1F701666C9A777"))
			return FALSE;
		// восстановить секрет (тесты Б.5 -- Б.7, строка 8)
		if (belsRecover(s, 2, len, si + 2 * len, m0, mi + 2 * len) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"81C498D55DC506E858DE632A079C2C31") ||
			len == 24 && !hexEq(s, 
			"21B6A467511CD2CE6AE671E1D0992538"
			"BFB4EAE927F70991") ||
			len == 32 && !hexEq(s, 
			"3ACC00A6DF80BC314A708A19D467F954"
			"40B214356D4666B4075E384B87BEB86C"))
			return FALSE;
		// восстановить секрет (тесты Б.5 -- Б.7, строка 10)
		if (belsRecover(s, 2, len, si + 3 * len, m0, mi + 3 * len) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"40F629F9A4487DBCBF53192EA4A49EAA") ||
			len == 24 && !hexEq(s, 
			"1C0E2B99D81134E0EB9AD40279D09786"
			"CA3CDA79B2E5D385") ||
			len == 32 && !hexEq(s, 
			"3F5F33C778D77A4FADC0BB51BE9F0153"
			"2627D1E83D023DA72255CC826B05213B"))
			return FALSE;
		// изменить порядок открытых ключей / частичных секретов: 13245
		memSwap(mi + len, mi + 2 * len, len);
		memSwap(si + len, si + 2 * len, len);
		// восстановить секрет (тесты Б.5 -- Б.7, строка 2)
		if (belsRecover(s, 2, len, si, m0, mi) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"ABD72A835739A358DD954BEF7A923AEC") ||
			len == 24 && !hexEq(s, 
			"A2E3B51AFBD7AFD552048DD6444416E0"
			"7F2D9FA92D726920") ||
			len == 32 && !hexEq(s, 
			"70EDE256F46BDC35EEE39361921EE8A3"
			"94E8E67F3F56ABFBA65329D146DA185B"))
			return FALSE;
		// восстановить секрет (тесты Б.5 -- Б.7, строка 6)
		if (belsRecover(s, 2, len, si + 2 * len, m0, mi + 2 * len) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"6CB93B8CF600A746F8520860901E36FA") ||
			len == 24 && !hexEq(s, 
			"6D542544073C04C1C417ABDC292755A2"
			"861B4EB590B65841") ||
			len == 32 && !hexEq(s, 
			"44FC1DE684980BE2660BB7BCE50728A1"
			"25A81D3B71B8D4ACD74E03190ADA473B"))
			return FALSE;
		// изменить порядок открытых ключей / частичных секретов: 53241
		memSwap(mi, mi + 4 * len, len);
		memSwap(si, si + 4 * len, len);
		// восстановить секрет (тесты Б.5 -- Б.7, строка 9)
		if (belsRecover(s, 2, len, si, m0, mi) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"E685CC725DDE29E60927563912CBBEA4") ||
			len == 24 && !hexEq(s, 
			"F2E193958DB1D3391D54C410244C151D"
			"BC267D6F5182DEC4") ||
			len == 32 && !hexEq(s, 
			"B3C2EDAD484A5A864575721D10B9D0C0"
			"9AE32C972C74857BA423D04502EE0066"))
			return FALSE;
		// восстановить секрет (тесты Б.5 -- Б.7, строка 3)
		if (belsRecover(s, 2, len, si + 3 * len, m0, mi + 3 * len) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"225E2DF0E4AE6532D5A741981410A83C") ||
			len == 24 && !hexEq(s, 
			"2B65B8D1BEF2EA079F6C45DF5877EAA1"
			"8F1188539B0AEF32") ||
			len == 32 && !hexEq(s, 
			"7C2D5033F0F10CC69065B13BB53BE7D1"
			"9D61CF864CF1578E8325F10564F995A3"))
			return FALSE;
		// изменить порядок открытых ключей / частичных секретов: 43251
		memSwap(mi, mi + 3 * len, len);
		memSwap(si, si + 3 * len, len);
		// восстановить секрет (тесты Б.5 -- Б.7, строка 7)
		if (belsRecover(s, 2, len, si + 2 * len, m0, mi + 2 * len) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"E4FCC7E24E448324367F400326954776") ||
			len == 24 && !hexEq(s, 
			"EF5CE43C8AE6F4E441CE1C2D16ACC662"
			"D6CC1D8BAF937320") ||
			len == 32 && !hexEq(s, 
			"264FD3BE9298495758B2446363616A38"
			"75D15EB96F95A122332597A87B2CCCBC"))
			return FALSE;
		// восстановить секрет (тесты Б.5 -- Б.7, строка 4)
		if (belsRecover(s, 2, len, si + 3 * len, m0, mi + 3 * len) != ERR_OK ||
			len == 16 && !hexEq(s, 
			"E0C4268AC9C5FE35C15334E4D01417BE") ||
			len == 24 && !hexEq(s, 
			"7E880E3E89CE5FD4E8452256BD66E42D"
			"18D88C0CF85FDC26") ||
			len == 32 && !hexEq(s, 
			"00DD41CD32684FE7564F67FC51B0AD87"
			"003EEBDF90E803BA37CBA4FF8D9A724F"))
			return FALSE;
	}
	// разделение и сборка на стандартных открытых ключах
	for (len = 16; len <= 32; len += 8)
	{
		// разделить секрет
		if (belsShare3(si, 5, 3, len, beltH()) != ERR_OK)
			return FALSE;
		// восстановить секрет
		if (belsRecover2(s, 1, len, si) != ERR_OK ||
			memEq(s, beltH(), len))
			return FALSE;
		if (belsRecover2(s, 2, len, si) != ERR_OK ||
			memEq(s, beltH(), len))
			return FALSE;
		if (belsRecover2(s, 3, len, si) != ERR_OK ||
			!memEq(s, beltH(), len))
			return FALSE;
		if (belsRecover2(s, 4, len, si) != ERR_OK ||
			!memEq(s, beltH(), len))
			return FALSE;
		if (belsRecover2(s, 5, len, si) != ERR_OK ||
			!memEq(s, beltH(), len))
			return FALSE;
	}
	// все нормально
	return TRUE;
}
