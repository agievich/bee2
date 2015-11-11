/*
*******************************************************************************
\file botp-test.c
\brief Tests for STB 34.101.botp
\project bee2/test
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.06
\version 2015.11.11
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
	ctr[7] = 1, memSetZero(ctr, 7); 
	botpHOTPStart(state, beltH(), 32);
	botpHOTPStepG(otp, 6, ctr, state);
	printf("HOTP.1 otp = %s\n", otp);
	botpHOTPStepG(otp, 7, ctr, state);
	printf("HOTP.2 otp = %s\n", otp);
	if (botpHOTPGen(otp, 8, beltH(), 32, ctr) != ERR_OK)
		return FALSE;
	printf("HOTP.3 otp = %s\n", otp);
	memSetZero(ctr1, 8);
	if (botpHOTPVerify(otp, beltH(), 32, ctr1, 2) == ERR_OK ||
		!botpHOTPStepV(otp, ctr1, 4, state) ||
		!memEq(ctr, ctr1, 8) ||
		botpHOTPStepV(otp, ctr1, 9, state))
		return FALSE;
	// тесты TOTP
	t = tmTimeRound(0, 30);
	if (t == TIME_MAX)
		return FALSE;
	botpTOTPStart(state, beltH(), 32);
	botpTOTPStepG(otp, 6, t - 2, state);
	printf("TOTP.1 otp = %s\n", otp);
	if (botpTOTPGen(otp, 7, beltH(), 32, t - 1) != ERR_OK)
		return FALSE;
	printf("TOTP.2 otp = %s\n", otp);
	botpTOTPStepG(otp, 8, t, state);
	printf("TOTP.3 otp = %s\n", otp);
	if (//botpTOTPStepV(otp, t + 4, 3, 3, state) ||
		//botpTOTPVerify(otp, beltH(), 32, t + 2, 1, 0) == ERR_OK ||
		//botpTOTPStepV(otp, t - 2, 0, 1, state) ||
		!botpTOTPStepV(otp, t + 2, 2, 0, state)// ||
		//botpTOTPVerify(otp, beltH(), 32, t - 2, 0, 2) != ERR_OK
		)
		return FALSE;
	// все нормально
	return TRUE;
}
