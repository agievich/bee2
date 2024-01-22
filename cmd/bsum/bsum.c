/*
*******************************************************************************
\file bsum.c
\brief Hash files using belt-hash / bash-hash
\project bee2/cmd 
\created 2014.10.28
\version 2024.01.22
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/dec.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>

#include <stdio.h>
#ifdef OS_WIN
	#include <locale.h>
#endif

/*
*******************************************************************************
Утилита bsum

Функционал:
- хэширование файлов с помощью алгоритмов СТБ 34.101.31 и СТБ 34.101.77;
- проверка хэш-значений.

Поддержаны следующие алгоритмы хэширования:
- belt-hash (СТБ 34.101.31);
- bash32, bash64, ..., bash512 (СТБ 34.101.77);
- bash-prg-hashNNND (СТБ 34.101.77), где NNN in {256, 384, 512}, D in {1, 2}.

\remark В алгоритмах bash-prg-hashNNND используется пустой анонс (annonce, фр.).

Хэш-значения выводятся в формате
```
	hex(хэш_значение_файла) имя_файла
```
Файл такого формата используется при проверке хэш-значений.

\remark Такой же формат файла хэш-значений используется в утилитах
{md5|sha1|sha256}sum. В bsum частично повторен интерфейс командной строки
этих утилит.

Примеры:
	bee2cmd bsum file1 file2 file3
	bee2cmd bsum -belt-hash file1 file2 file3 > checksum
	bee2cmd bsum -c checksum
	bee2cmd bsum -- -c

Обратим внимание на последнюю команду. В ней лексема "--" означает окончание
опций командной строки. Следующий за лексемой параметр "-с" будет
интерпретироваться как имя файла, а не как опция.

\warning В Windows имена файлов на русском языке будут записаны в checksum_file
в кодировке cp1251. В Linux -- в кодировке UTF8.

\todo Поддержка UTF8 в Windows.
*******************************************************************************
*/

static const char _name[] = "bsum";
static const char _descr[] = "hash files using {belt|bash} algorithms";

static int bsumUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n" 
		"  bsum [hash_alg] <file_to_hash> <file_to_hash> ...\n"
		"  bsum [hash_alg] -c <checksum_file>\n"
		"  hash_alg:\n" 
		"    -belt-hash (STB 34.101.31), by default\n"
		"    -bash32, -bash64, ..., -bash512 (STB 34.101.77)\n"
		"    -bash-prg-hashNNND (STB 34.101.77)\n"
		"      with NNN in {256, 384, 512}, D in {1, 2}\n"
		"      \\note annonce = NULL\n"
		"  \\remark use \"--\" to stop parsing options"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Разбор параметров

Идентификатор хэш-алгоритма (hid), заданного в командной строке:
*	0 -- belt-hash;
*	32, 64, ..., 512 -- bash32, bash64, ..., bash512;
*	NNND  -- bash-prg-hashNNND (NNN in {256, 384, 512}, D in {1, 2}).
*******************************************************************************
*/

static bool_t bsumHidIsValid(size_t hid)
{
	return hid == 0 ||
		(hid <= 512 && hid % 32 == 0) ||
		(hid % 10 != 0 && hid % 10 <= 2 &&
			(hid / 10) % 128 == 0 && 2 <= hid / 1280 && hid / 1280 <= 4);
}

static size_t bsumHidHashLen(size_t hid)
{
	ASSERT(bsumHidIsValid(hid));
	return hid == 0 ? 32 : (hid <= 512 ? hid / 8 : hid / 80);
};

/*
*******************************************************************************
Хэширование файла

\remark Если в функции bsumHash() переместить переменную buf в кучу,
то скорость обработки больших файлов (несколько Gb) существенно упадет.
Возможные объяснения:
```
https://stackoverflow.com/questions/24057331/
	is-accessing-data-in-the-heap-faster-than-from-the-stack
```
*******************************************************************************
*/

static int bsumHash(octet hash[], size_t hid, const char* filename)
{
	octet buf[32768];
	octet state[4096];
	size_t hash_len;
	void (*step_hash)(const void*, size_t, void*);
	FILE* fp;
	size_t count;
	// pre
	ASSERT(beltHash_keep() <= sizeof(state));
	ASSERT(bashHash_keep() <= sizeof(state));
	ASSERT(bashPrg_keep() <= sizeof(state));
	// обработать hid
	hash_len = bsumHidHashLen(hid);
	if (hid == 0)
	{
		beltHashStart(state);
		step_hash = beltHashStepH;
	}
	else if (hid <= 512)
	{
		bashHashStart(state, hid / 2);
		step_hash = bashHashStepH;
	}
	else
	{
		bashPrgStart(state, hid / 20, hid % 10, 0, 0, 0, 0);
		bashPrgAbsorbStart(state);
		step_hash = bashPrgAbsorbStep;
	}
	ASSERT(memIsValid(hash, hash_len));
	// открыть файл
	fp = fopen(filename, "rb");
	if (!fp)
	{
		printf("%s: FAILED [open]\n", filename);
		return -1;
	}
	// читать и хэшировать файл
	do
	{
		count = fread(buf, 1, sizeof(buf), fp);
		step_hash(buf, count, state);
	}
	while (count == sizeof(buf));
	// ошибка чтения?
	if (ferror(fp))
	{
		fclose(fp);
		memWipe(buf, sizeof(buf));
		memWipe(state, sizeof(state));
		printf("%s: FAILED [read]\n", filename);
		return -1;
	}
	fclose(fp);
	// возвратить хэш-значение
	if (hid == 0)
		beltHashStepG(hash, state);
	else if (hid <= 512)
		bashHashStepG(hash, hash_len, state);
	else
		bashPrgSqueeze(hash, hash_len, state);
	// завершить
	memWipe(buf, sizeof(buf));
	memWipe(state, sizeof(state));
	return 0;
}

static int bsumPrint(size_t hid, int argc, char* argv[])
{
	octet hash[64];
	char str[64 * 2 + 8];
	int ret = 0;
	for (; argc--; argv++)
	{
		if (bsumHash(hash, hid, argv[0]) != 0)
		{
			ret = -1;
			continue;
		}
		hexFrom(str, hash, bsumHidHashLen(hid));
		hexLower(str);
		printf("%s  %s\n", str, argv[0]);
	}
	return ret;
}

static int bsumCheck(size_t hid, const char* filename)
{
	octet hash[64];
	size_t hash_len;
	char str[1024];
	size_t str_len;
	FILE* fp;
	size_t all_lines = 0;
	size_t bad_lines = 0;
	size_t bad_files = 0;
	size_t bad_hashes = 0;
	// длина хэш-значения в байтах
	hash_len = bsumHidHashLen(hid);
	// открыть checksum_file
	fp = fopen(filename, "rb");
	if (!fp)
	{
		printf("%s: No such file\n", filename);
		return -1;
	}
	for (; fgets(str, sizeof(str), fp); ++all_lines)
	{
		// проверить строку
		str_len = strLen(str);
		if (str_len < hash_len * 2 + 2 || 
			str[2 * hash_len] != ' ' || 
			str[2 * hash_len + 1] != ' ' ||
			(str[hash_len * 2] = 0, !hexIsValid(str)))
		{
			bad_lines++;
			continue;
		}
		// выделить имя файла
		if(str[str_len - 1] == '\n') 
			str[--str_len] = 0;
		if(str[str_len - 1] == '\r') 
			str[--str_len] = 0;
		// хэшировать
		if (bsumHash(hash, hid, str + 2 * hash_len + 2) == -1)
		{
			bad_files++;
			continue;
		}
		if (!hexEq(hash, str))
		{
			bad_hashes++;
			printf("%s: FAILED [checksum]\n", str + 2 * hash_len + 2);
			continue;
		}
		printf("%s: OK\n", str + 2 * hash_len + 2);
	}
	fclose(fp);
	if (bad_lines)
		fprintf(stderr, bad_lines == 1 ? 
			"WARNING: %lu input line (out of %lu) is improperly formatted\n" :
			"WARNING: %lu input lines (out of %lu) are improperly formatted\n",
			(unsigned long)bad_lines, (unsigned long)all_lines);
	if (bad_files)
		fprintf(stderr, bad_files == 1 ? 
			"WARNING: %lu listed file could not be opened or read\n" :
			"WARNING: %lu listed files could not be opened or read\n", 
			(unsigned long)bad_files);
	if (bad_hashes)
		fprintf(stderr, bad_hashes == 1 ? 
			"WARNING: %lu computed checksum did not match\n":  
			"WARNING: %lu computed checksums did not match\n",  
			(unsigned long)bad_hashes);
	return (bad_lines || bad_files || bad_hashes) ? -1 : 0;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int bsumMain(int argc, char* argv[])
{
	err_t code = ERR_OK;
	size_t hid = SIZE_MAX;
	bool_t check = FALSE;
#ifdef OS_WIN
	setlocale(LC_ALL, "russian_belarus.1251");
#endif
	// справка
	if (argc < 2)
		return bsumUsage();
	// разбор опций
	++argv, --argc;
	while (argc && strStartsWith(argv[0], "-"))
	{
		// belt-hash
		if (strStartsWith(argv[0], "-belt-hash"))
		{
			if (hid != SIZE_MAX)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			hid = 0;
			--argc, ++argv;
		}
		// bash-prg-hash
		else if (strStartsWith(argv[0], "-bash-prg-hash"))
		{
			char* alg_name = argv[0] + strLen("-bash-prg-hash");
			if (hid != SIZE_MAX || !decIsValid(alg_name) ||
				strLen(alg_name) != 4 || decCLZ(alg_name) ||
				!bsumHidIsValid(hid = (size_t)decToU32(alg_name)))
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			--argc, ++argv;
		}
		// bash
		else if (strStartsWith(argv[0], "-bash"))
		{
			char* alg_name = argv[0] + strLen("-bash");
			if (hid != SIZE_MAX || !decIsValid(alg_name) ||
				2 > strLen(alg_name) || strLen(alg_name) > 4 ||
				decCLZ(alg_name) ||
				!bsumHidIsValid(hid = (size_t)decToU32(alg_name)))
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			--argc, ++argv;
		}
		// check
		else if (strEq(argv[0], "-c"))
		{
			if (check)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			check = TRUE;
			--argc, ++argv;
		}
		// --
		else if (strEq(argv[0], "--"))
		{
			--argc, ++argv;
			break;
		}
		else
		{
			code = ERR_CMD_PARAMS;
			break;
		}
	}
	// дополнительные проверки и обработка ошибок
	if (code == ERR_OK && (argc < 1 || check && argc != 1))
		code = ERR_CMD_PARAMS;
	if (code != ERR_OK)
	{
		fprintf(stderr, "bee2cmd/%s: %s\n", _name, errMsg(code));
		return -1;
	}
	// belt-hash по умолчанию
	if (hid == SIZE_MAX)
		hid = 0;
	// вычисление/проверка хэш-значениий
	ASSERT(bsumHidIsValid(hid));
	return check ? bsumCheck(hid, argv[0]) : bsumPrint(hid, argc, argv);
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t bsumInit()
{
	return cmdReg(_name, _descr, bsumMain);
}
