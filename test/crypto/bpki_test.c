/*
*******************************************************************************
\file bpki_test.c
\brief Tests for STB 34.101.78 (bpki) helpers
\project bee2/test
\created 2021.04.13
\version 2023.03.30
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bpki.h>

bool_t bpkiTest()
{
	octet epki[1024];
	octet key[65];
	octet pwd[] = { 'z', 'e', 'd' };
	size_t epki_len, epki_len1;
	size_t key_len;
	// создать контейнер с личным ключом (l = 128)
	if (bpkiPrivkeyWrap(0, &epki_len, beltH(), 32,
			pwd, sizeof(pwd), beltH() + 32, 10000) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiPrivkeyWrap(epki, &epki_len1, beltH(), 32,
			pwd, sizeof(pwd), beltH() + 32, 10000) != ERR_OK ||
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
			pwd, sizeof(pwd), beltH() + 40, 10001) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiPrivkeyWrap(epki, &epki_len1, beltH(), 48,
			pwd, sizeof(pwd), beltH() + 40, 10001) != ERR_OK ||
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
			pwd, sizeof(pwd), beltH() + 48, 10002) != ERR_OK ||
		epki_len > sizeof(epki) ||
		bpkiPrivkeyWrap(epki, &epki_len1, beltH(), 64,
			pwd, sizeof(pwd), beltH() + 48, 10002) != ERR_OK ||
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
	// разобрать контейнер с частичным секретом (l = 128)
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
