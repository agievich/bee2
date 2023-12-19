/*
*******************************************************************************
\file bpki_test.c
\brief Tests for STB 34.101.78 (bpki) helpers
\project bee2/test
\created 2021.04.13
\version 2023.12.19
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bpki.h>

/*
*******************************************************************************
Контейнеры
*******************************************************************************
*/

static bool_t bpkiContTest()
{
	octet epki[1024];
	octet key[65];
	octet pwd[] = { 'z', 'e', 'd' };
	size_t epki_len, epki_len1;
	size_t key_len;
	// создать контейнер с личным ключом (l = 96)
	if (bpkiPrivkeyWrap(0, &epki_len, beltH(), 24,
			pwd, sizeof(pwd), beltH() + 24, 10000) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiPrivkeyWrap(epki, &epki_len1, beltH(), 24,
			pwd, sizeof(pwd), beltH() + 24, 10000) != ERR_OK ||
		epki_len != epki_len1)
		return FALSE;
	// разобрать контейнер с личным ключом (l = 96)
	if (bpkiPrivkeyUnwrap(0, &key_len, epki, epki_len,
		pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 24 || key_len > sizeof(key) ||
		bpkiPrivkeyUnwrap(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 24 || !memEq(key, beltH(), 24))
		return FALSE;
	// создать контейнер с личным ключом (l = 128)
	if (bpkiPrivkeyWrap(0, &epki_len, beltH(), 32,
			pwd, sizeof(pwd), beltH() + 32, 10001) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiPrivkeyWrap(epki, &epki_len1, beltH(), 32,
			pwd, sizeof(pwd), beltH() + 32, 10001) != ERR_OK ||
		epki_len != epki_len1)
		return FALSE;
	// разобрать контейнер с личным ключом (l = 128)
	if (bpkiPrivkeyUnwrap(0, &key_len, epki, epki_len,
		pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 32 || key_len > sizeof(key) ||
		bpkiPrivkeyUnwrap(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 32 || !memEq(key, beltH(), 32))
		return FALSE;
	// создать контейнер с личным ключом (l = 192)
	if (bpkiPrivkeyWrap(0, &epki_len, beltH(), 48,
			pwd, sizeof(pwd), beltH() + 40, 10002) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiPrivkeyWrap(epki, &epki_len1, beltH(), 48,
			pwd, sizeof(pwd), beltH() + 40, 10002) != ERR_OK ||
		epki_len1 != epki_len)
		return FALSE;
	// разобрать контейнер с личным ключом (l = 192)
	if (bpkiPrivkeyUnwrap(0, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 48 ||
		bpkiPrivkeyUnwrap(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 48 || !memEq(key, beltH(), 48))
		return FALSE;
	// создать контейнер с личным ключом (l = 256)
	if (bpkiPrivkeyWrap(0, &epki_len, beltH(), 64,
			pwd, sizeof(pwd), beltH() + 48, 10003) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiPrivkeyWrap(epki, &epki_len1, beltH(), 64,
			pwd, sizeof(pwd), beltH() + 48, 10003) != ERR_OK ||
		epki_len1 != epki_len)
		return FALSE;
	// разобрать контейнер с личным ключом (l = 256)
	if (bpkiPrivkeyUnwrap(0, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 64 ||
		bpkiPrivkeyUnwrap(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 64 || !memEq(key, beltH(), 64))
		return FALSE;
	// создать контейнер с частичным секретом (l = 128)
	memCopy(key + 1, beltH(), 16), key[0] = 1;
	if (bpkiShareWrap(0, &epki_len, key, 17,
			pwd, sizeof(pwd), beltH() + 64, 10003) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiShareWrap(epki, &epki_len1, key, 17,
			pwd, sizeof(pwd), beltH() + 64, 10003) != ERR_OK ||
		epki_len != epki_len1)
		return FALSE;
	// разобрать контейнер с частичным секретом (l = 128)
	if (bpkiShareUnwrap(0, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 17 ||
		bpkiShareUnwrap(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 17 || !memEq(key + 1, beltH(), 16) || key[0] != 1)
		return FALSE;
	// создать контейнер с частичным секретом (l = 192)
	memCopy(key + 1, beltH(), 24), key[0] = 2;
	if (bpkiShareWrap(0, &epki_len, key, 25,
			pwd, sizeof(pwd), beltH() + 64, 10004) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiShareWrap(epki, &epki_len1, key, 25,
			pwd, sizeof(pwd), beltH() + 64, 10004) != ERR_OK ||
		epki_len1 != epki_len)
		return FALSE;
	// разобрать контейнер с частичным секретом (l = 192)
	if (bpkiShareUnwrap(0, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 25 ||
		bpkiShareUnwrap(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 25 || !memEq(key + 1, beltH(), 24) || key[0] != 2)
		return FALSE;
	// создать контейнер с частичным секретом (l = 256)
	memCopy(key + 1, beltH(), 32), key[0] = 16;
	if (bpkiShareWrap(0, &epki_len, key, 33,
			pwd, sizeof(pwd), beltH() + 64, 10005) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiShareWrap(epki, &epki_len1, key, 33,
			pwd, sizeof(pwd), beltH() + 64, 10005) != ERR_OK ||
		epki_len1 != epki_len)
		return FALSE;
	// разобрать контейнер с частичным секретом (l = 256)
	if (bpkiShareUnwrap(0, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 33 ||
		bpkiShareUnwrap(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 33 || !memEq(key + 1, beltH(), 32) || key[0] != 16)
		return FALSE;
	// все нормально
	return TRUE;
}

/*
*******************************************************************************
Запрос на выпуск сертификата
*******************************************************************************
*/

static bool_t bpkiCSRTest()
{
	octet csr[382];
	octet privkey[32];
	octet pubkey[64];
	size_t pubkey_len;
	// загрузить запрос
	hexTo(csr,
		"3082017A30820134020100305F311530"
		"1306035504030C0C524F424552542053"
		"4D495448310E300C06035504040C0553"
		"4D495448310F300D060355042A0C0652"
		"4F42455254311830160603550405130F"
		"50415347422D35333333323434323831"
		"0B3009060355040613024742305D3018"
		"060A2A7000020022652D0201060A2A70"
		"00020022652D0301034100F64CDDFFE4"
		"D546EF484471583FAEBA9A38061084E2"
		"80BF996F90BA6AF0DB6620F59ABAA7AD"
		"29D4E7D1CA0C21DD9E32D485F9E74084"
		"1F4317CA9481503D1F1B50A06F301F06"
		"092A864886F70D01090731120C102F49"
		"4E464F3A65726970323334313233304C"
		"06092A864886F70D01090E313F303D30"
		"170603551D200410300E300C060A2A70"
		"00020022654E023D30220603551D1104"
		"1B30198117726F626572742E736D6974"
		"68406578616D706C652E756B300D0609"
		"2A7000020022652D0C050003310082B4"
		"F9F934E3FD457F5DF06AE63A88E722E3"
		"5D35F565551535BA94CEF9243011999D"
		"F2159E4F4BAC22AD8C3135A3BD26");
	// разобрать запрос
	if (bpkiCSRUnwrap(0, 0, csr, sizeof(csr)) != ERR_OK ||
		bpkiCSRUnwrap(0, &pubkey_len, csr, sizeof(csr)) != ERR_OK ||
		bpkiCSRUnwrap(pubkey, 0, csr, sizeof(csr)) != ERR_OK ||
		bpkiCSRUnwrap(pubkey, &pubkey_len, csr, sizeof(csr)) != ERR_OK ||
		pubkey_len != 64)
		return FALSE;
	// загрузить личный ключ (тест bign:Г.1)
	hexTo(privkey,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269");
	// перевыпустить запрос
	if (bpkiCSRRewrap(csr, sizeof(csr), privkey, 32) != ERR_OK)
		return FALSE;
	// повторно разобрать запрос
	if (bpkiCSRUnwrap(pubkey, 0, csr, sizeof(csr)) != ERR_OK ||
		!hexEq(pubkey,
			"BD1A5650179D79E03FCEE49D4C2BD5DD"
			"F54CE46D0CF11E4FF87BF7A890857FD0"
			"7AC6A60361E8C8173491686D461B2826"
			"190C2EDA5909054A9AB84D2AB9D99A90"))
		return FALSE;
	// все нормально
	return TRUE;
}

/*
*******************************************************************************
Общий тест
*******************************************************************************
*/

bool_t bpkiTest()
{
	return bpkiContTest() && bpkiCSRTest();
}
