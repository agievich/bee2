/*
*******************************************************************************
\file cmd_date.c
\brief Command-line interface to Bee2: managing dates
\project bee2/cmd
\created 2023.05.29
\version 2023.06.06
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <stdio.h>

/*
*******************************************************************************
Разбор даты
*******************************************************************************
*/

err_t cmdDateParse(octet date[6], const char* str)
{
	// входной контроль
	if (!memIsValid(date, 6) || !strIsValid(str))
		return ERR_BAD_INPUT;
	if (strLen(str) != 6 || !strIsNumeric(str))
		return ERR_BAD_DATE;
	// разобрать дату
	memCopy(date, str, 6);
	date[0] -= '0', date[1] -= '0', date[2] -= '0';
	date[3] -= '0', date[4] -= '0', date[5] -= '0';
	if (memIsZero(date, 6))
	{
		if (!tmDate2(date))
			return ERR_BAD_DATE;
	}
	else if (!tmDateIsValid2(date))
		return ERR_BAD_DATE;
	return ERR_OK;	
}
