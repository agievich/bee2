/*
*******************************************************************************
\file bsum.c
\brief A file hashing utility based on the belt-hash and bash algorithms
\project bee2/apps/bsum 
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.28
\version 2017.01.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/defs.h>
#include <bee2/core/dec.h>
#include <bee2/core/hex.h>
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

Максимально точно поддержан интерфейс командной строки утилиты sha1sum.

\warning В Windows имена файлов на русском языке будут записаны в checksum_file 
в кодировке cp1251. В Linux -- в кодировке UTF8.

\todo Поддержка UTF8 в Windows.
*******************************************************************************
*/


int bsumUsage()
{
	printf(
		"bee2/bsum: STB 34.101.31/77 hashing utility [bee2 version %s]\n"
		"Usage:\n" 
        "  bsum [hash_alg] <file_to_hash> <file_to_hash> ...\n"
        "  bsum [hash_alg] -c <checksum_file>\n"
		"  hash_alg:\n" 
        "    belt-hash (STB 34.101.31, by default)\n"
        "    bash32, bash64, ..., bash512 (STB 34.101.77)\n",
		utilVersion());
	return -1;
}

size_t bsumParseHid(const char* alg_name)
{
	if (strEq(alg_name, "belt-hash"))
		return 0;
	if (strStartsWith(alg_name, "bash"))
	{
		size_t hid;
		alg_name += 4;
		if (!decIsValid(alg_name) || !strLen(alg_name) || 
			strLen(alg_name) > 3 || decCLZ(alg_name) || 
			(hid = (size_t)decToU32(alg_name)) % 32 || hid > 512)
			hid = SIZE_MAX;
		return hid;
	}
	return SIZE_MAX;
}

int bsumHashFile(octet hash[], size_t hid, const char* filename)
{
	FILE* fp;
	octet state[4096];
	octet buf[4096];
	size_t count;
	// открыть файл
	fp = fopen(filename, "rb");
	if (!fp)
	{
		printf("%s: FAILED [open]\n", filename);
		return -1;
	}
	// хэшировать
	ASSERT(beltHash_keep() <= sizeof(state));
	ASSERT(bash_keep() <= sizeof(state));
	hid ? bashStart(state, hid / 2) : beltHashStart(state);
	while (1)
	{
		count = fread(buf, 1, sizeof(buf), fp);
		if (count == 0)
		{
			if (ferror(fp))
			{
				fclose(fp);
				printf("%s: FAILED [read]\n", filename);
				return -1;
			}
			break;
		}
		hid ? bashStepH(buf, count, state) : beltHashStepH(buf, count, state);
	}
	// завершить
	fclose(fp);
	hid ? bashStepG(hash, hid / 8, state) : beltHashStepG(hash, state);
	return 0;
}

int bsumPrint(size_t hid, int argc, char* argv[])
{
	octet hash[64];
	char str[64 * 2 + 8];
	int ret = 0;
	for (; argc--; argv++)
	{
		if (bsumHashFile(hash, hid, argv[0]) != 0)
		{
			ret = -1;
			continue;
		}
		hexFrom(str, hash, hid ? hid / 8 : 32);
		hexLower(str);
		printf("%s  %s\n", str, argv[0]);
	}
	return ret;
}

int bsumCheck(size_t hid, const char* filename)
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
	hash_len = hid ? hid / 8 : 32;
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
		if (bsumHashFile(hash, hid, str + 2 * hash_len + 2) == -1)
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
	return (bad_lines || bad_files || bad_hashes) ? - 1 : 0;
}

int main(int argc, char* argv[])
{
	size_t hid = 0;
#ifdef OS_WIN
	setlocale(LC_ALL, "russian_belarus.1251");
#endif
	if (argc < 2)
		return bsumUsage();
	// check mode?
	if (3 <= argc && argc <= 4 && strEq(argv[argc - 2], "-c"))
	{
		if (argc == 4)
		{
			hid = bsumParseHid(argv[1]);
			if (hid == SIZE_MAX)
				return bsumUsage();
		}
		return bsumCheck(hid, argv[argc - 1]);
	}
	// print mode
	if (argc > 2)
	{
		hid = bsumParseHid(argv[1]);
		if (hid != SIZE_MAX)
			argc--, argv++;
		else
			hid = 0;
	}
	return bsumPrint(hid, argc - 1, argv + 1);
}
