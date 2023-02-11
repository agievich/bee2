/*
*******************************************************************************
\file g12s_test.c
\brief Tests for GOST R 34.10-2012 (Russia)
\project bee2/test
\created 2014.04.07
\version 2016.07.15
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>
#include <bee2/crypto/g12s.h>

/*
*******************************************************************************
Самотестирование

-#	Выполняются тесты из приложения A к ГОСТ Р 34.10-2012.
-#	Дополнительно проверяются стандартные кривые.
*******************************************************************************
*/

bool_t g12sTest()
{
	g12s_params params[1];
	octet buf[G12S_ORDER_SIZE];
	octet privkey[G12S_ORDER_SIZE];
	octet pubkey[2 * G12S_FIELD_SIZE];
	octet hash[64];
	octet sig[2 * G12S_ORDER_SIZE];
	octet echo[64];
	// тест A.1 [загрузка параметров]
	if (g12sStdParams(params, "1.2.643.2.2.35.0") != ERR_OK ||
		g12sValParams(params) != ERR_OK)
		return FALSE;
	// тест A.1 [генерация ключей]
	hexToRev(buf, 
		"7A929ADE789BB9BE10ED359DD39A72C1"
		"1B60961F49397EEE1D19CE9891EC3B28");
	ASSERT(sizeof(echo) >= prngEcho_keep());
	prngEchoStart(echo, buf, 32);
	if (g12sGenKeypair(privkey, pubkey, params, prngEchoStepR, echo) 
		!= ERR_OK ||
		!hexEqRev(privkey, 
			"7A929ADE789BB9BE10ED359DD39A72C1"
			"1B60961F49397EEE1D19CE9891EC3B28") ||
		!hexEqRev(pubkey, 
			"26F1B489D6701DD185C8413A977B3CBB"
			"AF64D1C593D26627DFFB101A87FF77DA"
			"7F2B49E270DB6D90D8595BEC458B50C5"
			"8585BA1D4E9B788F6689DBD8E56FD80B"))
		return FALSE;
	// тест A.1 [выработка ЭЦП]
	hexTo(hash, 
		"2DFBC1B372D89A1188C09C52E0EEC61F"
		"CE52032AB1022E8E67ECE6672B043EE5");
	hexToRev(buf, 
		"77105C9B20BCD3122823C8CF6FCC7B95"
		"6DE33814E95B7FE64FED924594DCEAB3");
	if (g12sSign(sig, params, hash, privkey, prngEchoStepR, echo) != ERR_OK ||
		!hexEq(sig, 
			"41AA28D2F1AB148280CD9ED56FEDA419"
			"74053554A42767B83AD043FD39DC0493"
			"01456C64BA4642A1653C235A98A60249"
			"BCD6D3F746B631DF928014F6C5BF9C40"))
		return FALSE;
	// тест A.1 [проверка ЭЦП]
	if (g12sVerify(params, hash, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, g12sVerify(params, hash, sig, pubkey) == ERR_OK))
		return FALSE;
	// тест A.2 [загрузка параметров]
	if (g12sStdParams(params, "1.2.643.7.1.2.1.2.0") != ERR_OK ||
		g12sValParams(params) != ERR_OK)
		return FALSE;
	// тест A.2 [генерация ключей]
	hexToRev(buf, 
		"0BA6048AADAE241BA40936D47756D7C9"
		"3091A0E8514669700EE7508E508B1020"
		"72E8123B2200A0563322DAD2827E2714"
		"A2636B7BFD18AADFC62967821FA18DD4");
	ASSERT(sizeof(echo) >= prngEcho_keep());
	prngEchoStart(echo, buf, 64);
	if (g12sGenKeypair(privkey, pubkey, params, prngEchoStepR, echo) 
		!= ERR_OK ||
		!hexEqRev(privkey, 
			"0BA6048AADAE241BA40936D47756D7C9"
			"3091A0E8514669700EE7508E508B1020"
			"72E8123B2200A0563322DAD2827E2714"
			"A2636B7BFD18AADFC62967821FA18DD4") ||
		!hexEqRev(pubkey, 
			"37C7C90CD40B0F5621DC3AC1B751CFA0"
			"E2634FA0503B3D52639F5D7FB72AFD61"
			"EA199441D943FFE7F0C70A2759A3CDB8"
			"4C114E1F9339FDF27F35ECA93677BEEC"
			"115DC5BC96760C7B48598D8AB9E740D4"
			"C4A85A65BE33C1815B5C320C854621DD"
			"5A515856D13314AF69BC5B924C8B4DDF"
			"F75C45415C1D9DD9DD33612CD530EFE1"))
		return FALSE;
	// тест A.2 [выработка ЭЦП]
	hexTo(hash, 
		"3754F3CFACC9E0615C4F4A7C4D8DAB53"
		"1B09B6F9C170C533A71D147035B0C591"
		"7184EE536593F4414339976C647C5D5A"
		"407ADEDB1D560C4FC6777D2972075B8C");
	hexToRev(buf, 
		"0359E7F4B1410FEACC570456C6801496"
		"946312120B39D019D455986E364F3658"
		"86748ED7A44B3E794434006011842286"
		"212273A6D14CF70EA3AF71BB1AE679F1");
	if (g12sSign(sig, params, hash, privkey, prngEchoStepR, echo) 
		!= ERR_OK ||
		!hexEq(sig, 
			"2F86FA60A081091A23DD795E1E3C689E"
			"E512A3C82EE0DCC2643C78EEA8FCACD3"
			"5492558486B20F1C9EC197C906998502"
			"60C93BCBCD9C5C3317E19344E173AE36"
			"1081B394696FFE8E6585E7A9362D26B6"
			"325F56778AADBC081C0BFBE933D52FF5"
			"823CE288E8C4F362526080DF7F70CE40"
			"6A6EEB1F56919CB92A9853BDE73E5B4A"))
		return FALSE;
	// тест A.2 [проверка ЭЦП]
	if (g12sVerify(params, hash, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, g12sVerify(params, hash, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую cryptoproA
	if (g12sStdParams(params, "1.2.643.2.2.35.1") != ERR_OK ||
		g12sValParams(params) != ERR_OK)
		return FALSE;
	// проверить кривую cryptoproB
	if (g12sStdParams(params, "1.2.643.2.2.35.2") != ERR_OK ||
		g12sValParams(params) != ERR_OK)
		return FALSE;
	// проверить кривую cryptoproC
	if (g12sStdParams(params, "1.2.643.2.2.35.3") != ERR_OK ||
		g12sValParams(params) != ERR_OK)
		return FALSE;
	// проверить кривую cryptocom
	if (g12sStdParams(params, "1.2.643.2.9.1.8.1") != ERR_OK ||
		g12sValParams(params) != ERR_OK)
		return FALSE;
	// проверить кривую paramsetA512
	if (g12sStdParams(params, "1.2.643.7.1.2.1.2.1") != ERR_OK ||
		g12sValParams(params) != ERR_OK)
		return FALSE;
	// проверить кривую paramsetB512
	if (g12sStdParams(params, "1.2.643.7.1.2.1.2.2") != ERR_OK ||
		g12sValParams(params) != ERR_OK)
		return FALSE;
	// все нормально
	return TRUE;
}
