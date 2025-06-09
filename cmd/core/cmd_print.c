/*
*******************************************************************************
\file cmd_print.c
\brief Command-line interface to Bee2: print to terminal
\project bee2/cmd
\created 2023.06.06
\version 2025.06.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include "bee2/cmd.h"

/*
*******************************************************************************
Память
*******************************************************************************
*/

err_t cmdPrintMem(const void* buf, size_t count)
{
	char* hex;
	// pre
	ASSERT(memIsValid(buf, count));
	// выделить память
	hex = (char*)blobCreate(32);
	if (!hex)
		return ERR_OUTOFMEMORY;
	// печатать
	while (count > 14)
	{
		hexFrom(hex, buf, 14);
		printf("%s", hex);
		buf = (const octet*)buf + 14, count -= 14;
	}
	hexFrom(hex, buf, count);
	printf("%s", hex);
	// завершить
	blobClose(hex);
	return ERR_OK;
}

err_t cmdPrintMem2(const void* buf, size_t count)
{
	char* hex;
	// pre
	ASSERT(memIsValid(buf, count));
	// выделить память
	hex = (char*)blobCreate(32);
	if (!hex)
		return ERR_OUTOFMEMORY;
	// печатать
	if (count > 14)
	{
		hexFrom(hex, buf, 12);
		hex[24] = hex[25] = hex[26] = '.';
		hexFrom(hex + 27, (const octet*)buf + count - 2, 2);
		printf("%s (%u)", hex, (unsigned)count);
	}
	else
	{
		hexFrom(hex, buf, count);
		printf("%s", hex);
	}
	// завершить
	blobClose(hex);
	return ERR_OK;
}

/*
*******************************************************************************
Дата
*******************************************************************************
*/

err_t cmdPrintDate(const octet date[6])
{
	if (!tmDateIsValid2(date))
		return ERR_BAD_DATE;
	printf("%c%c%c%c%c%c",
		date[0] + '0', date[1] + '0', date[2] + '0',
		date[3] + '0', date[4] + '0', date[5] + '0');
	return ERR_OK;
}
