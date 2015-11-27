/*
*******************************************************************************
\file botp-test.c
\brief Tests for STB 34.101.botp
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.06
\version 2015.11.27
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/botp.h>

#include <stdio.h>

/*
*******************************************************************************
Самотестирование

Создаются тесты для приложения А к СТБ 34.101.botp.
*******************************************************************************
*/

bool_t botpTest()
{
	octet ctr[8], ctr1[8];
	char otp[10];
	tm_time_t t;
	octet state[2048];
	// создать стек
	ASSERT(sizeof(state) >= botpHOTP_keep());
	// тесты HOTP
	memSetZero(ctr, 8); 
	botpHOTPStart(state, 6, beltH(), 32);
	botpHOTPStepS(state, ctr);
	botpHOTPStepR(otp, state);
	botpHOTPStepG(ctr, state);
	printf("HOTP.1 otp = %s\n", otp);
	botpHOTPStart(state, 7, beltH(), 32);
	botpHOTPStepS(state, ctr);
	botpHOTPStepR(otp, state);
	botpHOTPStepG(ctr, state);
	printf("HOTP.2 otp = %s\n", otp);
	botpHOTPStart(state, 8, beltH(), 32);
	botpHOTPStepS(state, ctr);
	if (botpHOTPRand(otp, 8, beltH(), 32, ctr) != ERR_OK)
		return FALSE;
	printf("HOTP.3 otp = %s\n", otp);
	memSetZero(ctr1, 8);
	if (!botpHOTPStepV(otp, 0, state) ||
		botpHOTPVerify(otp, beltH(), 32, ctr1, 1) == ERR_OK ||
		botpHOTPVerify(otp, beltH(), 32, ctr1, 2) != ERR_OK ||
		!memEq(ctr, ctr1, 8) ||
		botpHOTPVerify(otp, beltH(), 32, ctr1, 4) == ERR_OK)
		return FALSE;
	// тесты TOTP
	t = tmTimeRound(0, 30);
	if (t == TIME_ERR)
		return FALSE;
	botpTOTPStart(state, 6, beltH(), 32);
	botpTOTPStepR(otp, t - 2, state);
	printf("TOTP.1 otp = %s\n", otp);
	if (botpTOTPRand(otp, 7, beltH(), 32, t - 1) != ERR_OK)
		return FALSE;
	printf("TOTP.2 otp = %s\n", otp);
	botpTOTPStart(state, 8, beltH(), 32);
	botpTOTPStepR(otp, t, state);
	printf("TOTP.3 otp = %s\n", otp);
	if (botpTOTPStepV(otp, t + 4, 3, 3, state) ||
		botpTOTPVerify(otp, beltH(), 32, t + 2, 1, 0) == ERR_OK ||
		botpTOTPStepV(otp, t - 2, 0, 1, state) ||
		!botpTOTPStepV(otp, t + 2, 2, 0, state) ||
		botpTOTPVerify(otp, beltH(), 32, t - 2, 0, 2) != ERR_OK)
		return FALSE;
	// OCRA
	if (botpOCRAStart(state, "OCRA-:HOTP-HBELT-6:C-QN08", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-3:C-QN08", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-6-QN08", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:C-QA65", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:C-QN08-", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:C-QN08-PSHA", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:QN08-SA13", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:QN08-T1N", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:QN08-T61S", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:QN08-T51H", beltH(), 32))
		return FALSE;
	memCopy(ctr1, ctr, 8);
	if (botpOCRARand(otp, "OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S032-T30S",	
			beltH(), 32, "01234567", ctr, 
			beltH() + 32, beltH() + 64, t) != ERR_OK)
			return FALSE;
	printf("OCRA.1 otp = %s\n", otp);
	if (botpOCRAVerify(otp, "OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S032-T30S",	
			beltH(), 32, "01234567", ctr, 
			beltH() + 32, beltH() + 64, t) == ERR_OK)
			return FALSE;
	if (botpOCRAVerify(otp, "OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S032-T30S",	
			beltH(), 32, "01234567", ctr1, 
			beltH() + 32, beltH() + 64, t) != ERR_OK)
			return FALSE;
	// все нормально
	return TRUE;
}
