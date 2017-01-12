/*
*******************************************************************************
\file stamp.c
\brief Integrity control of Windows PE Executables
\project bee2/apps/stamp
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2011.10.18
\version 2017.01.12
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/ 

/*
*******************************************************************************
Контрольная характеристика представляет собой строку из STAMP_SIZE октетов,
которая должна быть добавлена в исполнимый файл как строковый ресурс 
с идентификатором STAMP_ID.
*******************************************************************************
*/ 

#include <windows.h>
#include <stdio.h>
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>

/* 
*******************************************************************************
Работа с PE-файлом
*******************************************************************************
*/

#include "stamp_pe.c"

/* 
*******************************************************************************
Вспомогательные функции
*******************************************************************************
*/

//! Справка о соглашениях
void stampUsage(const char* prg_name)
{
	// короткое имя программы
	const char* short_name = prg_name + strLen(prg_name);
	while (--short_name != prg_name && *short_name != '\\');
	if (*short_name == '\\')
		short_name++;
	// печать справки
	printf(
		"bee2/%s: Integrity control of PE-modules\n"
		"[bee2 version %s]\n"
		"Usage: %s -{s|c} name\n"
		"  s -- set control stamp\n"
		"  c -- check control stamp\n"
		"  name -- name of PE-module (exe or dll)\n"
		"\\pre resource file of the target module must contains the string\n"
		"  %d %d {\"0123456789ABCDEF0123456789ABCDEF\"}\n",
		short_name, utilVersion(), short_name, STAMP_ID, STAMP_TYPE);
}

//! Разбор командной строки
/*! Разбирается командная строка:
		stamp -{s|с} name
	\return 
	-	0 -- set;
	-	1 -- create;
	-	-1 -- ошибка синтаксиса. 
*/
int stampParsing(int argc, const char* argv[])
{
	// проверяем число аргументов
	if (argc != 3)
	{
		stampUsage(argv[0]);
		return -1;
	}
	// проверяем режим
	if (strEq(argv[1], "-s"))
		return 0;
	if (strEq(argv[1], "-c"))
		return 1;
	return -1;
}

void stampPrint(const octet* stamp, const char* stamp_name)
{
	size_t pos;
	printf(stamp_name ? "[%s = " : "[", stamp_name);
	for (pos = 0; pos < STAMP_SIZE; ++pos)
		printf("%02X", stamp[pos]);
	printf("]\n");
}

/* 
*******************************************************************************
Работа с контрольными характеристиками
*******************************************************************************
*/

// установить характеристику
void stampSet(const char* name)
{
	HANDLE hFile;
	DWORD size;
	HANDLE hMapping;
	octet* image;
	DWORD offset;
	void* hash_state;
	// открыть файл
	hFile = CreateFileA(name, GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("File \"%s\" was not found or could not be open.\n", name);
		return;
	}
	// длина файла
	size = SetFilePointer(hFile, 0, NULL, FILE_END);
	if (size == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return;
	}
	// проецировать файл в память
	hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return;
	}
	// отобразить файл в память
	image = (octet*)MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
	if (image == NULL)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return;
	}
	// найти смещение контрольной характеристики
	offset = stampFindOffset(image, size);
	if (offset == (DWORD)-1)
	{
		UnmapViewOfFile(image);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("Control stamp of \"%s\" was not found or corrupted.\n", name);
		return;
	}
	// подготовить место для контрольной характеристики
	CASSERT(STAMP_SIZE >= 32);
	memSetZero(image + offset, STAMP_SIZE);
	// стек хэширования
	hash_state = blobCreate(beltHash_keep());
	if (hash_state)
	{
		// хэшировать
		beltHashStart(hash_state);
		beltHashStepH(image, offset, hash_state);
		beltHashStepH(image + offset + STAMP_SIZE, 
			size - offset - STAMP_SIZE, hash_state);
		beltHashStepG(image + offset, hash_state);
		blobClose(hash_state);
		// печать
		printf("Control stamp successfully added to \"%s\"\n", name);
		stampPrint(image + offset, "stamp");
	}
	else
		printf("Insufficient memory.\n");
	// очистка
	UnmapViewOfFile(image);
	CloseHandle(hMapping);
	CloseHandle(hFile);
}

// проверить характеристику
void stampCheck(const char* name)
{
	HANDLE hFile;
	DWORD size;
	HANDLE hMapping;
	octet* image;
	DWORD offset;
	octet stamp[STAMP_SIZE];
	void* hash_state;
	bool_t success;
	// открыть файл
	hFile = CreateFileA(name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("File \"%s\" was not found or could not be open.\n", name);
		return;
	}
	// длина файла
	size = SetFilePointer(hFile, 0, NULL, FILE_END);
	if (size == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return;
	}
	// проецировать файл в память
	hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == NULL)
	{
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return;
	}
	// отобразить файл в память
	image = (octet*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (image == NULL)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return;
	}
	// найти смещение контрольной характеристики
	offset = stampFindOffset(image, size);
	if (offset == (DWORD)-1)
	{
		UnmapViewOfFile(image);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("Control stamp of \"%s\" was not found or corrupted.\n", name);
		return;
	}
	// подготовить место для контрольной характеристики
	CASSERT(STAMP_SIZE >= 32);
	memSet(stamp, 0, STAMP_SIZE);
	// состояние хэширования
	hash_state = blobCreate(beltHash_keep());
	if (hash_state)
	{
		// хэшировать
		beltHashStart(hash_state);
		beltHashStepH(image, offset, hash_state);
		beltHashStepH(image + offset + STAMP_SIZE, 
			size - offset - STAMP_SIZE, hash_state);
		beltHashStepG(stamp, hash_state);
		blobClose(hash_state);
		// сравнить
		success = memEq(image + offset, stamp, STAMP_SIZE);
		printf("Integrity of \"%s\"... %s\n", name, success ? "OK" : "Failed");
		if (success)
			stampPrint(image + offset, "stamp");
		else
			stampPrint(image + offset, "read_stamp"),
			stampPrint(stamp, "calc_stamp");
	}
	else
		printf("Insufficient memory.\n");
	// очистка
	UnmapViewOfFile(image);
	CloseHandle(hMapping);
	CloseHandle(hFile);
}

/* 
*******************************************************************************
main
*******************************************************************************
*/

void main(int argc, char* argv[])
{
	int d;
	// разобрать командную строку
	d = stampParsing(argc, argv);
	// set?
	if (d == 0)
		stampSet(argv[2]);
	// create?
	else if (d == 1)
		stampCheck(argv[2]);
}
