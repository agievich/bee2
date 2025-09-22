/*
*******************************************************************************
\file cmd_st.c
\brief Command-line interface to Bee2: self-tests
\project bee2/cmd 
\created 2025.04.09
\version 2025.09.22
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/err.h>
#include <bee2/core/file.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/brng.h>
#include "bee2/cmd.h"

/*
*******************************************************************************
Самотестирование: алгоритмы
*******************************************************************************
*/

static err_t cmdStBash()
{
	octet state[1024];
	octet buf[32];
	octet buf1[16];
	// A.3.1
	ASSERT(sizeof(state) >= bashHash_keep());
	bash256Start(state);
	bash256StepH(beltH(), 0, state);
	bash256StepG(buf, state);
	if (!hexEq(buf,
		"114C3DFAE373D9BCBC3602D6386F2D6A"
		"2059BA1BF9048DBAA5146A6CB775709D"))
		return ERR_SELFTEST;
	// A.4.alpha
	ASSERT(sizeof(state) >= bashPrg_keep());
	bashPrgStart(state, 256, 2, 0, 0, beltH(), 32);
	bashPrgAbsorb(beltH() + 32, 95, state);
	bashPrgRatchet(state);
	bashPrgSqueeze(buf1, 16, state);
	if (!hexEq(buf1,
		"71CC358A0D5082173DE04803F7E905CB"))
		return ERR_SELFTEST;
	// A.4.beta
	bashPrgStart(state, 128, 1, beltH() + 128, 16, buf1, 16);
	memCopy(buf, beltH() + 128 + 32, 23);
	bashPrgEncr(buf, 23, state);
	if (!hexEq(buf,
		"51ED3B28D345FFD1AD22815B86ECC17C"
		"278C8FE8920214"))
		return ERR_SELFTEST;
	bashPrgStart(state, 128, 1, beltH() + 128, 16, buf1, 16);
	bashPrgDecr(buf, 23, state);
	if (!memEq(buf, beltH() + 128 + 32, 23))
		return ERR_SELFTEST;
	return ERR_OK;
}

static err_t cmdStBelt()
{
	const char pwd[] = "B194BAC80A08F53B";
	octet state[1024];
	octet buf[48];
	octet buf1[32];
	// belt-ecb: тест A.9-1
	ASSERT(sizeof(state) >= beltECB_keep());
	memCopy(buf, beltH(), 48);
	beltECBStart(state, beltH() + 128, 32);
	beltECBStepE(buf, 16, state);
	if (!hexEq(buf,
		"69CCA1C93557C9E3D66BC3E0FA88FA6E"))
		return ERR_SELFTEST;
	// belt-ecb: тест A.10-1
	memCopy(buf, beltH() + 64, 48);
	beltECBStart(state, beltH() + 128 + 32, 32);
	beltECBStepD(buf, 16, state);
	if (!hexEq(buf,
		"0DC5300600CAB840B38448E5E993F421"))
		return ERR_SELFTEST;
	// belt-mac: тест A.17-1
	ASSERT(sizeof(state) >= beltMAC_keep());
	beltMAC(buf, beltH(), 13, beltH() + 128, 32);
	if (!hexEq(buf, "7260DA60138F96C9"))
		return ERR_SELFTEST;
	// pbkdf2 тест E.5
	beltPBKDF2(buf, (const octet*)pwd, strLen(pwd), 10000,
		beltH() + 128 + 64, 8);
	if (!hexEq(buf,
		"3D331BBBB1FBBB40E4BF22F6CB9A689E"
		"F13A77DC09ECF93291BFE42439A72E7D"))
		return ERR_SELFTEST;
	// belt-che: тест A.19-2
	ASSERT(sizeof(state) >= beltCHE_keep());
	beltCHEStart(state, beltH() + 128, 32, beltH() + 192);
	memCopy(buf, beltH(), 15);
	beltCHEStepE(buf, 15, state);
	beltCHEStepI(beltH() + 16, 32, state);
	beltCHEStepA(buf, 15, state);
	beltCHEStepG(buf1, state);
	if (!hexEq(buf,
		"BF3DAEAF5D18D2BCC30EA62D2E70A4"))
		return ERR_SELFTEST;
	if (!hexEq(buf1,
		"548622B844123FF7"))
		return ERR_SELFTEST;
	if (!beltCHEStepV(buf1, state))
		return ERR_SELFTEST;
	// belt-che: тест A.20-2
	beltCHEStart(state, beltH() + 128 + 32, 32, beltH() + 192 + 16);
	memCopy(buf, beltH() + 64, 20);
	beltCHEStepI(beltH() + 64 + 16, 32, state);
	beltCHEStepA(buf, 20, state);
	beltCHEStepD(buf, 20, state);
	beltCHEStepG(buf1, state);
	if (!hexEq(buf,
		"2BABF43EB37B5398A9068F31A3C758B762F44AA9"))
		return ERR_SELFTEST;
	if (!hexEq(buf1,
		"7D9D4F59D40D197D"))
		return ERR_SELFTEST;
	// belt-kwp: тест A.21
	ASSERT(sizeof(state) >= beltKWP_keep());
	beltKWPStart(state, beltH() + 128, 32);
	memCopy(buf, beltH(), 32);
	memCopy(buf + 32, beltH() + 32, 16);
	beltKWPStepE(buf, 48, state);
	if (!hexEq(buf,
		"49A38EE108D6C742E52B774F00A6EF98"
		"B106CBD13EA4FB0680323051BC04DF76"
		"E487B055C69BCF541176169F1DC9F6C8"))
		return ERR_SELFTEST;
	// belt-kwp: тест A.22
	beltKWPStart(state, beltH() + 128 + 32, 32);
	memCopy(buf, beltH() + 64, 48);
	beltKWPStepD(buf, 48, state);
	if (!hexEq(buf,
		"92632EE0C21AD9E09A39343E5C07DAA4"
		"889B03F2E6847EB152EC99F7A4D9F154"))
		return ERR_SELFTEST;
	if (!hexEq(buf + 32,
		"B5EF68D8E4A39E567153DE13D72254EE"))
		return ERR_SELFTEST;
	// belt-hash: тест A.23-1
	beltHashStart(state);
	beltHashStepH(beltH(), 13, state);
	beltHashStepG(buf1, state);
	if (!hexEq(buf1,
		"ABEF9725D4C5A83597A367D14494CC25"
		"42F20F659DDFECC961A3EC550CBA8C75"))
		return ERR_SELFTEST;
	return ERR_OK;
}

static err_t cmdStBels()
{
	octet buf[5 * (32 + 1)];
	octet buf1[32];
	// bels-share: разделение и сборка
	if (belsShare3(buf, 5, 3, 32, beltH()) != ERR_OK)
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 1, 32, buf) != ERR_OK ||
		memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 2, 32, buf) != ERR_OK ||
		memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 3, 32, buf) != ERR_OK ||
		!memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	return ERR_OK;
}

static err_t cmdStBign()
{
	octet state[1024];
	bign_params params[1];
	octet privkey[32];
	octet pubkey[64];
	octet hash[32];
	const octet oid[] = {
		0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
	};
	octet sig[48];
	// bign-genkeypair
	hexTo(privkey,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269");
	ASSERT(sizeof(state) >= prngEcho_keep());
	prngEchoStart(state, privkey, 32);
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignKeypairGen(privkey, pubkey, params, prngEchoStepR,
			state) != ERR_OK ||
		!hexEq(pubkey,
			"BD1A5650179D79E03FCEE49D4C2BD5DD"
			"F54CE46D0CF11E4FF87BF7A890857FD0"
			"7AC6A60361E8C8173491686D461B2826"
			"190C2EDA5909054A9AB84D2AB9D99A90"))
		return ERR_SELFTEST;
	// bign-valpubkey
	if (bignPubkeyVal(params, pubkey) != ERR_OK)
		return ERR_SELFTEST;
	// bign-sign
	if (beltHash(hash, beltH(), 13) != ERR_OK)
		return ERR_SELFTEST;
	if (bignSign2(sig, params, oid, sizeof(oid), hash, privkey,
		0, 0) != ERR_OK)
		return ERR_SELFTEST;
	if (!hexEq(sig,
		"19D32B7E01E25BAE4A70EB6BCA42602C"
		"CA6A13944451BCC5D4C54CFD8737619C"
		"328B8A58FB9C68FD17D569F7D06495FB"))
		return ERR_SELFTEST;
	if (bignVerify(params, oid, sizeof(oid), hash, sig, pubkey) != ERR_OK)
		return ERR_SELFTEST;
	sig[0] ^= 1;
	if (bignVerify(params, oid, sizeof(oid), hash, sig, pubkey) == ERR_OK)
		return ERR_SELFTEST;
	// все нормально
	return ERR_OK;
}

static err_t cmdStBrng()
{
	octet state[1024];
	octet buf[96];
	// brng-ctr: тест Б.2
	ASSERT(sizeof(state) >= brngCTR_keep());
	memCopy(buf, beltH(), 96);
	brngCTRStart(state, beltH() + 128, beltH() + 128 + 64);
	brngCTRStepR(buf, 96, state);
	if (!hexEq(buf,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269"
		"4C0E74B2CD5811AD21F23DE7E0FA742C"
		"3ED6EC483C461CE15C33A77AA308B7D2"
		"0F51D91347617C20BD4AB07AEF4F26A1"
		"AD1362A8F9A3D42FBE1B8E6F1C88AAD5"))
		return ERR_SELFTEST;
	return ERR_OK;
}

static err_t cmdStAlgs(u32 tests)
{
	err_t code;
	// bash?
	if (tests & CMD_ST_BASH)
	{
		code = cmdStBash();
		ERR_CALL_CHECK(code);
	}
	// bels?
	if (tests & CMD_ST_BELS)
	{
		code = cmdStBels();
		ERR_CALL_CHECK(code);
	}
	// belt?
	if (tests & CMD_ST_BELT)
	{
		code = cmdStBelt();
		ERR_CALL_CHECK(code);
	}
	// bign?
	if (tests & CMD_ST_BIGN)
	{
		code = cmdStBign();
		ERR_CALL_CHECK(code);
	}
	// brng?
	if (tests & CMD_ST_BRNG)
	{
		code = cmdStBrng();
		ERR_CALL_CHECK(code);
	}
	return ERR_OK;
}

/*
*******************************************************************************
Самотестирование: тесты
*******************************************************************************
*/

err_t cmdStDo(u32 tests)
{
	err_t code = ERR_OK;
	// algs?
	if (tests & CMD_ST_ALGS)
	{
		code = cmdStAlgs(tests);
		ERR_CALL_CHECK(code);
	}
	// rng?
	if (tests & CMD_ST_RNG)
	{
		code = cmdRngStart(TRUE);
		ERR_CALL_CHECK(code);
	}
	// stamp?
	if (tests & CMD_ST_STAMP)
	{
		code = cmdStampSelfVal();
		ERR_CALL_CHECK(code);
	}
	return code;
}

/*
*******************************************************************************
Самотестирование: контрольная сумма
*******************************************************************************
*/

err_t cmdStCrc(octet crc[32], const char* prefix)
{
	const size_t buf_size = 4096;
	err_t code;
	size_t count;
	void* state;
	char* name;					/* [count] */
	octet* buf;					/* [buf_size] */
	void* hash_state;			/* [beltHash_keep()] */
	file_t file;
	// входной контроль
	if (!memIsValid(crc, 32) || !strIsNullOrValid(prefix))
		return ERR_BAD_INPUT;
	// определить длину имени исполняемого модуля
	code = cmdSysModulePath(0, &count);
	ERR_CALL_CHECK(code);
	// выделить и разметить память	
	code = cmdBlobCreate2(state, 
		count,
		buf_size | SIZE_HI, 
		beltHash_keep(),
		SIZE_MAX,
		&name, &buf, &hash_state);		
	ERR_CALL_CHECK(code);
	// определить имя исполняемого модуля
	code = cmdSysModulePath(name, &count);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// открыть исполнямый модуль
	code = cmdFileOpen(file, name, "rb");
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// начать хэширование
	beltHashStart(hash_state);
	if (prefix)
		beltHashStepH(prefix, strLen(prefix), hash_state);
	// хэшировать файл
	do
	{
		if ((count = fileRead2(buf, buf_size, file)) == SIZE_MAX)
			code = ERR_FILE_READ;
		ERR_CALL_HANDLE(code, (cmdFileClose(file), cmdBlobClose(state)));
		beltHashStepH(buf, count, hash_state);
	} while (count);
	// закрыть файл
	code = cmdFileClose2(file);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// завершить
	beltHashStepG(crc, hash_state);
	cmdBlobClose(state);
	return code;
}
