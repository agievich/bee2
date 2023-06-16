/*
*******************************************************************************
\file stamp.c
\brief Integrity control of Windows PE Executables
\project bee2/cmd
\created 2011.10.18
\version 2023.06.08
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/ 

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <windows.h>
#include <stdio.h>

/*
*******************************************************************************
Работа с PE-файлом
*******************************************************************************
*/

#include "stamp_pe.c"

/*
*******************************************************************************
Утилита stamp

Функционал:
- добавление в исполнимый файл Windows контрольной суммы;
- проверка контрольной суммы.

Контрольная сумма представляет собой строку из STAMP_SIZE октетов, которая
добавляется в исполнимый файл как строковый ресурс с идентификатором STAMP_ID.
*******************************************************************************
*/

static const char _name[] = "stamp";
static const char _descr[] = "integrity control of Windows PE executables";

static int stampUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  stamp -s filename\n"
		"    set a stamp on filename\n"
		"  stamp -c filename\n"
		"    check a stamp of filename\n"
		"\\pre  filename is a PE-module (exe or dll)\n"
		"\\pre resource file of the target module must contains the string\n"
		"  %d %d {\"0123456789ABCDEF0123456789ABCDEF\"}\n"
		,
		_name, _descr,
		STAMP_ID, STAMP_TYPE
	);
	return -1;
}

/* 
*******************************************************************************
Вспомогательные функции
*******************************************************************************
*/


//! Разбор командной строки
/*! Разбирается командная строка:
		stamp -{s|с} name
	\return 
	- 0 -- set;
	- 1 -- create;
	- -1 -- ошибка синтаксиса. 
*/
static int stampParse(int argc, const char* argv[])
{
	// проверяем число аргументов
	if (argc != 3)
		return stampUsage(argv[0]);
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

static int stampSet(const char* name)
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
		return -1;
	}
	// длина файла
	size = SetFilePointer(hFile, 0, NULL, FILE_END);
	if (size == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return -1;
	}
	// проецировать файл в память
	hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return -1;
	}
	// отобразить файл в память
	image = (octet*)MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
	if (image == NULL)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return -1;
	}
	// найти смещение контрольной характеристики
	offset = stampFindOffset(image, size);
	if (offset == (DWORD)-1)
	{
		UnmapViewOfFile(image);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("A stamp of \"%s\" was not found or corrupted.\n", name);
		return -1;
	}
	// подготовить место для контрольной характеристики
	CASSERT(STAMP_SIZE >= 32);
	memSetZero(image + offset, STAMP_SIZE);
	// стек хэширования
	hash_state = blobCreate(beltHash_keep());
	if (!hash_state)
	{
		UnmapViewOfFile(image);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("Insufficient memory.\n");
		return -1;
	}
	// хэшировать
	beltHashStart(hash_state);
	beltHashStepH(image, offset, hash_state);
	beltHashStepH(image + offset + STAMP_SIZE,
		size - offset - STAMP_SIZE, hash_state);
	beltHashStepG(image + offset, hash_state);
	blobClose(hash_state);
	// печать
	printf("A stamp successfully added to \"%s\"\n", name);
	stampPrint(image + offset, "stamp");
	// завершение
	UnmapViewOfFile(image);
	CloseHandle(hMapping);
	CloseHandle(hFile);
	return 0;
}

// проверить характеристику
static int stampCheck(const char* name)
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
		return -1;
	}
	// длина файла
	size = SetFilePointer(hFile, 0, NULL, FILE_END);
	if (size == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return -1;
	}
	// проецировать файл в память
	hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == NULL)
	{
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return -1;
	}
	// отобразить файл в память
	image = (octet*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (image == NULL)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("Error processing the file \"%s\".\n", name);
		return -1;
	}
	// найти смещение контрольной характеристики
	offset = stampFindOffset(image, size);
	if (offset == (DWORD)-1)
	{
		UnmapViewOfFile(image);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("A stamp of \"%s\" was not found or corrupted.\n", name);
		return -1;
	}
	// подготовить место для контрольной характеристики
	CASSERT(STAMP_SIZE >= 32);
	memSet(stamp, 0, STAMP_SIZE);
	// состояние хэширования
	hash_state = blobCreate(beltHash_keep());
	if (!hash_state)
	{
		UnmapViewOfFile(image);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf("Insufficient memory.\n");
		return -1;
	}
	// хэшировать
	beltHashStart(hash_state);
	beltHashStepH(image, offset, hash_state);
	beltHashStepH(image + offset + STAMP_SIZE, 
		size - offset - STAMP_SIZE, hash_state);
	beltHashStepG(stamp, hash_state);
	blobClose(hash_state);
	// сравнить
	success = memEq(image + offset, stamp, STAMP_SIZE);
	printf("Validating \"%s\"... %s\n", name, success ? "OK" : "Failed");
	if (success)
		stampPrint(image + offset, "stamp");
	else
		stampPrint(image + offset, "read_stamp"),
		stampPrint(stamp, "calc_stamp");
	// завершение
	UnmapViewOfFile(image);
	CloseHandle(hMapping);
	CloseHandle(hFile);
	return 0;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int stampMain(int argc, char* argv[])
{
	int d;
	// разобрать командную строку
	d = stampParse(argc, argv);
	// set?
	if (d == 0)
		return stampSet(argv[2]);
	// create?
	else if (d == 1)
		return stampCheck(argv[2]);
	return -1;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t stampInit()
{
	return cmdReg(_name, _descr, stampMain);
}
