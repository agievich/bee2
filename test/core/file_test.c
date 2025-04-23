/*
*******************************************************************************
\file file_test.c
\brief Tests for file management functions
\project bee2/test
\created 2025.04.13
\version 2025.04.23
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/file.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t fileTest()
{
	file_t file;
	size_t len;
	octet buf[64];
	octet buf1[64];
	char str[32];
	char str1[32];
	// создать временный файл
	file = fileTmp();
	if (!file)
		return FALSE;
	// запись
	if (fileWrite( &len, beltH(), 12, file) != ERR_OK ||
		len != 12 || fileTell(file) != 12 ||
		!fileFlush(file) ||
	// перемещение указателя
		!fileSeek(file, 20, SEEK_END) || fileTell(file) != 32 ||
		!fileSeek(file, 7, SEEK_SET) || fileTell(file) != 7 || 
		!fileSeek(file, 8, SEEK_CUR) || fileTell(file) != 15 ||
	// запись 2
		fileWrite2(file, beltH() + 12, 20) != 20 ||	
		fileTell(file) != 35 ||
	// чтение
		!fileSeek(file, 0, SEEK_SET) || fileTell(file) != 0 ||
		fileRead(&len, buf, sizeof(buf), file) != ERR_MAX ||
		len != 35 ||
		!memEq(buf, beltH(), 12) || 
		!memIsZero(buf + 12, 3) ||
		!memEq(buf + 15, beltH() + 12, 20) ||
	// чтение 2
		!fileSeek(file, 0, SEEK_SET) || fileTell(file) != 0 ||
		fileRead2(buf1, sizeof(buf1), file) != 35 ||
		!memEq(buf, buf1, 35))
	{
		fileClose(file);
		return FALSE;
	}
	// запись / чтение строки
	hexFrom(str, buf, 10);
	if (!filePuts(file, str) || fileTell(file) != 35 + 20 ||
		!fileSeek(file, 35, SEEK_SET) ||
		!fileGets(str1, 5, file)  ||
		!strStartsWith(str, str1) ||
		!fileSeek(file, 35, SEEK_SET) ||
		!fileGets(str1, sizeof(str1), file) ||
		!strEq(str, str1))
	{
		fileClose(file);
		return FALSE;
	}
	// закрыть файл
	if (!fileClose(file))
		return FALSE;				
	// все нормально
	return TRUE;
}
