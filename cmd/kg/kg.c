/*
*******************************************************************************
\file kg.c
\brief Generate and manage private keys
\project bee2/cmd 
\created 2022.06.08
\version 2022.06.10
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "../cmd.h"

#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/bpki.h>
#include <bee2/crypto/brng.h>

#include <stdio.h>

/*
*******************************************************************************
Утилита kg

Функционал:
- генерация ключей bign;
- разделение личного ключа на частичные секреты с записью в защищенные 
  контейнеры;
- сборка ключа по контейнерам с проверкой корректности и печатью открытого 
  ключа. 
*******************************************************************************
*/

static const char _name[] = "kg";
static const char _descr[] = "generate and manage private keys";

int kgUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  kg -pass:<pwd> <share_1> <share_2> ... <share_n>\n"
		"    create a key and store it in n shares protected by <pwd>\n"
		"    \\pre 2 <= n <= 16\n"
		"  kg -pass:<pwd> -v <share_i> <share_j>\n"
		"    restore a key from 2 shares and validate it\n"
		"    \\pre 2 <= i != j <= n\n",
		_name, _descr
	);
	return -1;
}


/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

err_t kgSelfTest()
{
	const char pwd[] = "B194BAC80A08F53B";
	octet state[1024];
	bign_params params[1];
	octet privkey[32];
	octet pubkey[64];
	octet buf[5 * (32 + 1)];
	octet buf1[32];
	// bign-genkeypair
	hexTo(privkey,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269");
	ASSERT(sizeof(state) >= prngEcho_keep());
	prngEchoStart(state, privkey, 32);
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignGenKeypair(privkey, pubkey, params, prngEchoStepR,
			state) != ERR_OK ||
		!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return ERR_SELFTEST;
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
	// pbkdf2 тест E.5
	beltPBKDF2(buf, (const octet*)"B194BAC80A08F53B", strLen(pwd), 10000,
		beltH() + 128 + 64, 8);
	if (!hexEq(buf,
		"3D331BBBB1FBBB40E4BF22F6CB9A689E"
		"F13A77DC09ECF93291BFE42439A72E7D"))
		return FALSE;
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
		return FALSE;
	// все нормально
	return ERR_OK;
}

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

typedef struct
{
	size_t l;				/*!< уровень стойкости */
	octet privkey[64];		/*!< личный ключ */
	octet pubkey[128];		/*!< открытый ключ */
	octet skey[32];			/*!< ключ защиты */
} kg_key_t;

err_t kgGenKey(kg_key_t* key, size_t l)
{
	err_t code;
	bign_params params[1];
	// входной контроль и подготовка
	if (!memIsValid(key, sizeof(kg_key_t)))
		return ERR_BAD_INPUT;
	if (!rngIsValid())
		return ERR_BAD_RNG;
	// загрузить параметры
	if ((key->l = l) == 128)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1");
	else if (key->l == 192)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.2");
	else if (key->l == 256)
		code = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3");
	else
		code = ERR_BAD_INPUT;
	ERR_CALL_CHECK(code);
	// сгенерировать ключевую пару
	code = bignGenKeypair(key->privkey, key->pubkey, params, rngStepR, 0);
	ERR_CALL_CHECK(code);
	// сгенерировать ключ защиты
	rngStepR(key->skey, key->l / 8, 0);
	return ERR_OK;
}

bool_t kgKeyIsValid(const kg_key_t* key)
{
	return memIsValid(key, sizeof(kg_key_t)) &&
		(key->l == 128 || key->l == 192) || (key->l == 256);
}

err_t kgCreateKey(const char* privkey, size_t l,
	const char* shares[], size_t count, size_t threshold,
	const char* pwd)
{
	err_t code;
	const size_t iter = 10000;
	void* state;
	kg_key_t* key;
	octet* share;
	octet* salt;
	octet* epki;
	size_t epki_privkey_len;
	size_t epki_share_len;
	// входной контроль
	if (!strIsValid(privkey) ||
		!(l == 128 || l == 192 || l == 256) ||
		!memIsValid(shares, count * sizeof(const char*)) ||
		count < 2 || count > 16 ||
		threshold == 0 || threshold > count ||
		!strIsValid(pwd))
		return ERR_BAD_INPUT;
	if (!rngIsValid())
		return ERR_BAD_RNG;
	// определить длину контейнера с личным ключом
	code = bpkiWrapPrivkey(0, &epki_privkey_len, 0, l / 4, 0, 0, 0, iter);
	ERR_CALL_CHECK(code);
	// определить длину контейнера с частичным секретом
	code = bpkiWrapShare(0, &epki_share_len, 0, 33, 0, 0, 0, iter);
	ERR_CALL_CHECK(code);
	// выделить память
	state = blobCreate(sizeof(kg_key_t) + count * (l / 8 + 1) + 8 +
		MAX2(epki_privkey_len, epki_share_len));
	code = state ? ERR_OK : ERR_OUTOFMEMORY;
	ERR_CALL_CHECK(code);
	key = (kg_key_t*)state;
	share = (octet*)key + sizeof(kg_key_t);
	salt = share + count * 33;
	epki = salt + (l / 8 + 1);
	// сгенерировать ключ
	code = kgGenKey(key, l);
	ERR_CALL_HANDLE(code, blobClose(state));
	// разделить мастер-ключ на частичные секреты
	code = belsShare2(share, count, threshold, l / 8, key->skey, rngStepR, 0);
	ERR_CALL_HANDLE(code, blobClose(state));
	// защитить частичные секреты
	for (; count--; share += (l / 8 + 1), ++shares)
	{
		FILE* fp;
		// установить защиту
		rngStepR(salt, 8, 0);
		code = bpkiWrapShare(epki, 0, share, l / 8 + 1, (const octet*)pwd,
			strLen(pwd), salt, iter);
		ERR_CALL_HANDLE(code, blobClose(state));
		// открыть файл для записи
		fp = fopen(*shares, "wb");
		code = fp ? ERR_OK : ERR_FILE_CREATE;
		ERR_CALL_HANDLE(code, blobClose(state));
		// записать
		code = fwrite(epki, 1, epki_share_len, fp) == epki_share_len ?
			ERR_OK : ERR_FILE_WRITE;
		ERR_CALL_HANDLE(code, (fclose(fp), blobClose(state)));
		fclose(fp);
	}
	// защитить личный ключ
	{
		FILE* fp;
		// установить защиту
		rngStepR(salt, 8, 0);
		code = bpkiWrapPrivkey(epki, 0, key->privkey, l / 4, key->skey,
			l / 8, salt, iter);
		ERR_CALL_HANDLE(code, blobClose(state));
		// открыть файл для записи
		fp = fopen(privkey, "wb");
		code = fp ? ERR_OK : ERR_FILE_CREATE;
		ERR_CALL_HANDLE(code, blobClose(state));
		// записать
		code = fwrite(epki, 1, epki_privkey_len, fp) == epki_privkey_len ?
			ERR_OK : ERR_FILE_WRITE;
		ERR_CALL_HANDLE(code, (fclose(fp), blobClose(state)));
		fclose(fp);
	}
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t kgReadKey(kg_key_t* key, const char* privkey,
	const char* shares[], size_t count, const char* pwd)
{
	err_t code;
	void* state;
	octet* share;
	octet* epki_privkey;
	octet* epki_share;
	size_t epki_privkey_len128;
	size_t epki_privkey_len192;
	size_t epki_privkey_len;
	size_t epki_share_len;
	size_t len;
	FILE* fp;
	// входной контроль
	if (!memIsValid(key, sizeof(kg_key_t)) ||
		!strIsValid(privkey) ||
		count < 2 || count > 16 ||
		!memIsValid(shares, count * sizeof(const char*)) ||
		!strIsValid(pwd))
		return ERR_BAD_INPUT;
	// определить возможные длины контейнера с личным ключом
	code = bpkiWrapPrivkey(0, &epki_privkey_len128, 0, 32, 0, 0, 0, SIZE_MAX);
	ERR_CALL_CHECK(code);
	code = bpkiWrapPrivkey(0, &epki_privkey_len192, 0, 48, 0, 0, 0, SIZE_MAX);
	ERR_CALL_CHECK(code);
	code = bpkiWrapPrivkey(0, &epki_privkey_len, 0, 64, 0, 0, 0, SIZE_MAX);
	ERR_CALL_CHECK(code);
	// определить максимальную длину контейнера с частичным секретом
	code = bpkiWrapShare(0, &epki_share_len, 0, 33, 0, 0, 0, SIZE_MAX);
	ERR_CALL_CHECK(code);
	// выделить память
	state = blobCreate(count * 33 + epki_privkey_len + epki_share_len + 2);
	code = state ? ERR_OK : ERR_OUTOFMEMORY;
	ERR_CALL_CHECK(code);
	share = (octet*)state;
	epki_privkey = share + count * 33;
	epki_share = epki_privkey + epki_privkey_len + 1;
	// открыть файл с личным ключом
	fp = fopen(privkey, "rb");
	code = fp ? ERR_OK : ERR_FILE_OPEN;
	ERR_CALL_HANDLE(code, blobClose(state));
	// прочитать
	len = fread(epki_privkey, 1, epki_privkey_len + 1, fp);
	code = len <= epki_privkey_len ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, (fclose(fp), blobClose(state)));
	// определить уровень стойкости
	if (len == epki_privkey_len)
		key->l = 256;
	else if (len == epki_privkey_len128)
	{
		key->l = 128;
		epki_privkey_len = epki_privkey_len128;
	}
	else if (len == epki_privkey_len192)
	{
		key->l = 192;
		epki_privkey_len = epki_privkey_len192;
	}
	else
		code = ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, (fclose(fp), blobClose(state)));
	fclose(fp);
	// уточнить длину контейнера с частичным секретом
	code = bpkiWrapShare(0, &epki_share_len, 0, key->l / 8 + 1,
		0, 0, 0, SIZE_MAX);
	ERR_CALL_HANDLE(code, blobClose(state));
	// прочитать частичные секреты
	for (; count--; share += (key->l / 8 + 1), ++shares)
	{
		// открыть файл для чтения
		fp = fopen(*shares, "rb");
		code = fp ? ERR_OK : ERR_FILE_OPEN;
		ERR_CALL_HANDLE(code, blobClose(state));
		// прочитать
		len = fread(epki_share, 1, epki_share_len + 1, fp);
		code = len == epki_share_len ? ERR_OK : ERR_BAD_FORMAT;
		ERR_CALL_HANDLE(code, (fclose(fp), blobClose(state)));
		// декодировать
		code = bpkiUnwrapShare(share, &len, epki_share, epki_share_len,
			(const octet*)pwd, strLen(pwd));
		ERR_CALL_HANDLE(code, (fclose(fp), blobClose(state)));
		code = len == key->l / 8 + 1 ? ERR_OK : ERR_BAD_FORMAT;
		ERR_CALL_HANDLE(code, (fclose(fp), blobClose(state)));
		fclose(fp);
	}
	// собрать ключ защиты
	share -= count * (key->l / 8 + 1);
	code = belsRecover2(key->skey, count, key->l / 8, share);
	ERR_CALL_HANDLE(code, blobClose(state));
	// декодировать личный ключ
	code = bpkiUnwrapShare(share, &len, epki_privkey, epki_privkey_len,
		(const octet*)pwd, strLen(pwd));
	ERR_CALL_HANDLE(code, blobClose(state));
	code = len == key->l / 4 ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// завершение
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int kgMain(int argc, const char* argv[])
{
	err_t code;
	const char* pwd;
	bool_t check;
	// определить пароль
	if (argc < 2 || !strStartsWith(argv[1], "-pass:"))
		return kgUsage();
	pwd = argv[1] + strLen("-pass:");
	argc -= 2, argv += 2;
	// режим проверки?
	if (check = strEq(argv[0], "-v"))
		argc--, argv++;
	// контроль числа частичных секретов
	if (argc > 16 || argc < 2 || check && argc != 2)
		return kgUsage();
	// создать ключ
	if (!check)
	{
		const char* sources[] = { "trng", "trng2", "sys", "timer" };
		size_t read, pos, count;

		printf("Validating output files... ");
		code = cmdValFilesNotExist(argc, argv);
		printf("%s\n", errMsg(code));
		ERR_CALL_CHECK(code);

		printf("Performing self-tests... ");
		code = kgSelfTest();
		printf("%s\n", errMsg(code));
		ERR_CALL_CHECK(code);

		printf("Starting the RNG[");
		for (pos = count = 0; pos < COUNT_OF(sources); ++pos)
			if (rngReadSource(&read, 0, 0, sources[pos]) == ERR_OK)
				printf(count++ ? ", %s" : "%s", sources[pos]);
		printf("]... ");
		code = rngCreate(0, 0);
		printf("%s\n", errMsg(code));
		ERR_CALL_CHECK(code);

		printf("Running stat-tests for the RNG... ");
		code = cmdRngTest();
		printf("%s\n", errMsg(code));
		ERR_CALL_CHECK(code);

		printf("Generating and sharing a key... ");
		code = kgCreateKey("privkey", 128, argv, (size_t)argc, 2, pwd);
		printf("%s\n", errMsg(code));
		rngClose();
		ERR_CALL_CHECK(code);
		printf("Password-protected shares are stored in %d files.\n", argc);
	}
	// проверить ключ
	else
	{
		blob_t state;
		kg_key_t* key;
		char* hex;

		printf("Validating input files... ");
		code = cmdValFilesExist(argc, argv);
		printf("%s\n", errMsg(code));
		ERR_CALL_CHECK(code);

		printf("Performing self-tests... ");
		code = kgSelfTest();
		printf("%s\n", errMsg(code));
		ERR_CALL_CHECK(code);

		printf("Recovering a key... ");
		state = blobCreate(sizeof(kg_key_t) + 128 + 1);
		if (state)
		{
			key = (kg_key_t*)state;
			hex = (char*)key + sizeof(kg_key_t);
			code = kgReadKey(key, "privkey", argv, (size_t)argc, pwd);
		}
		else
			code = ERR_OUTOFMEMORY;
		printf("%s\n", errMsg(code));
		ERR_CALL_HANDLE(code, blobClose(state));

		hexFrom(hex, key->pubkey, key->l / 2);
		printf("pubkey[bign] = %s\n", hex);
		blobClose(state);
	}
	// возврат
	return code;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t kgInit()
{
	return cmdReg(_name, _descr, kgMain);
}
