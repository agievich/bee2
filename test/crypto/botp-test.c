/*
*******************************************************************************
\file botp-test.c
\brief Tests for STB 34.101.botp
\project bee2/test
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.06
\version 2015.11.06
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
	octet state[1024];
	// создать стек
	ASSERT(sizeof(state) >= botpHOTP_keep());
	// тесты HOTP
	ctr[0] = 1, memSetZero(ctr + 1, 7); 
	botpHOTPStart(state, beltH(), 32);
	botpHOTPStepG(otp, 6, ctr, state);
	printf("HOTP.1 otp = %s\n", otp);
	botpHOTPStepG(otp, 7, ctr, state);
	printf("HOTP.2 otp = %s\n", otp);
	botpHOTPStepG(otp, 8, ctr, state);
	printf("HOTP.3 otp = %s\n", otp);
	memSetZero(ctr1, 8);
	if (botpHOTPStepV(otp, ctr1, 2, state) ||
		!botpHOTPStepV(otp, ctr1, 0, state) ||
		!memEq(ctr, ctr1, 8) ||
		botpHOTPStepV(otp, ctr1, 100, state) ||
		ctr1[0] != 105 || !memIsZero(ctr1 + 1, 7))
		return FALSE;
	// тесты TOTP
	t = tmTimeRound(0, 30); 
	botpTOTPStart(state, beltH(), 32);
	botpTOTPStepG(otp, 6, t - 2, state);
	printf("TOTP.1 otp = %s\n", otp);
	botpTOTPStepG(otp, 7, t - 1, state);
	printf("TOTP.2 otp = %s\n", otp);
	botpTOTPStepG(otp, 8, t, state);
	printf("TOTP.3 otp = %s\n", otp);
	if (botpTOTPStepV(otp, t + 4, 3, 3, state) ||
		botpTOTPStepV(otp, t + 2, 1, 0, state) ||
		botpTOTPStepV(otp, t - 2, 0, 1, state) ||
		!botpTOTPStepV(otp, t + 2, 2, 0, state) ||
		!botpTOTPStepV(otp, t - 2, 0, 2, state))
		return FALSE;
	// все нормально
	return TRUE;
}
