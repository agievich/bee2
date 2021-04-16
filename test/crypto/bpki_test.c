/*
*******************************************************************************
\file bpki_test.c
\brief Tests for STB 34.101.78 (bpki) helpers
\project bee2/test
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2021.04.13
\version 2021.04.15
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
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
	size_t epki_len, key_len;
	// создать контейнер с личным ключом (l = 128)
	if (bpkiWrapPrivkey(epki, &epki_len, beltH(), 32,
			pwd, sizeof(pwd), beltH() + 32, 10000) != ERR_OK)
		return FALSE;
	ASSERT(epki_len <= sizeof(epki));
	// разобрать контейнер с личным ключом (l = 128)
	if (bpkiUnwrapPrivkey(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 32 || !memEq(key, beltH(), 32))
		return FALSE;
	// создать контейнер с личным ключом (l = 192)
	if (bpkiWrapPrivkey(epki, &epki_len, beltH(), 48,
			pwd, sizeof(pwd), beltH() + 40, 10001) != ERR_OK)
		return FALSE;
	ASSERT(epki_len <= sizeof(epki));
	// разобрать контейнер с личным ключом (l = 192)
	if (bpkiUnwrapPrivkey(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 48 || !memEq(key, beltH(), 48))
		return FALSE;
	// создать контейнер с личным ключом (l = 256)
	if (bpkiWrapPrivkey(epki, &epki_len, beltH(), 64,
			pwd, sizeof(pwd), beltH() + 48, 10002) != ERR_OK)
		return FALSE;
	ASSERT(epki_len <= sizeof(epki));
	// разобрать контейнер с личным ключом (l = 256)
	if (bpkiUnwrapPrivkey(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 64 || !memEq(key, beltH(), 64))
		return FALSE;
	// создать контейнер с частичным секретом (l = 128)
	memCopy(key + 1, beltH(), 32), key[0] = 1;
	if (bpkiWrapShare(epki, &epki_len, key, 33,
			pwd, sizeof(pwd), beltH() + 56, 10003) != ERR_OK)
		return FALSE;
	ASSERT(epki_len <= sizeof(epki));
	// разобрать контейнер с частичным секретом (l = 128)
	if (bpkiUnwrapShare(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 33 || !memEq(key + 1, beltH(), 32) || key[0] != 1)
		return FALSE;
	// создать контейнер с частичным секретом (l = 192)
	memCopy(key + 1, beltH(), 48), key[0] = 2;
	if (bpkiWrapShare(epki, &epki_len, key, 49,
			pwd, sizeof(pwd), beltH() + 64, 10004) != ERR_OK)
		return FALSE;
	ASSERT(epki_len <= sizeof(epki));
	// разобрать контейнер с частичным секретом (l = 192)
	if (bpkiUnwrapShare(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 49 || !memEq(key + 1, beltH(), 48) || key[0] != 2)
		return FALSE;
	// создать контейнер с частичным секретом (l = 256)
	memCopy(key + 1, beltH(), 64), key[0] = 16;
	if (bpkiWrapShare(epki, &epki_len, key, 65,
			pwd, sizeof(pwd), beltH() + 64, 10005) != ERR_OK)
		return FALSE;
	ASSERT(epki_len <= sizeof(epki));
	// разобрать контейнер с частичным секретом (l = 128)
	if (bpkiUnwrapShare(key, &key_len, epki, epki_len,
			pwd, sizeof(pwd)) != ERR_OK ||
		key_len != 65 || !memEq(key + 1, beltH(), 64) || key[0] != 16)
		return FALSE;
	// все нормально
	return TRUE;
}
