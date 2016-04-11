/*
*******************************************************************************
\file botp-test.c
\brief Tests for STB 34.101.47/botp
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.06
\version 2016.03.10
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

/*
*******************************************************************************
Самотестирование

Создаются тесты для приложения А к СТБ 34.101.botp.
*******************************************************************************
*/

bool_t botpTest()
{
	octet ctr[8];
	char otp[10], otp1[10], otp2[10], otp3[10];
	const char suite[] = "OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S064-T1M";
	char q[32];
	octet p[32];
	char str[17];
	char p_str[65];
	char s_str[129];
	tm_time_t t;
	octet state[2048];
	// создать стек
	ASSERT(sizeof(state) >= botpHOTP_keep());
	// тесты HOTP
	memCopy(ctr, beltH() + 192, 8); 
	botpHOTPStart(state, 8, beltH() + 128, 32);
	botpHOTPStepS(state, ctr);
	botpHOTPStepG(ctr, state);
	botpHOTPStepR(otp1, state);
	hexFrom(str, ctr, 8);
	printf("HOTP.1:\n\tC = %s\n\tR = %s\n", str, otp1);
	botpHOTPStepG(ctr, state);
	botpHOTPStepR(otp2, state);
	hexFrom(str, ctr, 8);
	printf("HOTP.2:\n\tC = %s\n\tR = %s\n", str, otp2);
	botpHOTPStepG(ctr, state);
	botpHOTPStepR(otp3, state);
	hexFrom(str, ctr, 8);
	printf("HOTP.3:\n\tC = %s\n\tR = %s\n", str, otp3);
	botpHOTPStepG(ctr, state);
	// тесты TOTP
	t = 1449165288;
	if (t == TIME_ERR)
		return FALSE;
	botpTOTPStart(state, 8, beltH() + 128, 32);
	botpTOTPStepR(otp, t / 60, state);
	printf("TOTP.1:\n\tT = %u / 60 = %u\n\tR = %s\n", 
		(unsigned)t, (unsigned)(t / 60), otp);
	t /= 60, ++t, t *= 60;
	botpTOTPStart(state, 8, beltH() + 128, 32);
	botpTOTPStepR(otp, t / 60, state);
	printf("TOTP.2:\n\tT = %u / 60 = %u\n\tR = %s\n", 
		(unsigned)t, (unsigned)(t / 60), otp);
	t /= 60, t += 2, t *= 60, --t;
	botpTOTPStart(state, 8, beltH() + 128, 32);
	botpTOTPStepR(otp, t / 60, state);
	printf("TOTP.3:\n\tT = %u / 60 = %u\n\tR = %s\n", 
		(unsigned)t, (unsigned)(t / 60), otp);
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
	beltHash(p, beltH(), 13);
	hexFrom(p_str, p, 32);
	hexFrom(s_str, beltH(), 64); 
	botpOCRAStart(state, suite, beltH() + 128, 32);
	botpOCRAStepS(state, ctr, p, beltH());
	printf("OCRA:\t\n\tD = %s\n\tP = %s\n\tS = %s\n", 
		suite, p_str, s_str);
	t /= 60;
	strCopy(q, otp1);
	botpOCRAStepR(otp, (const octet*)otp1, strLen(otp1), t += 3, state);
	hexFrom(str, ctr, 8);
	printf("OCRA.1:\n\tQ = %s\n\tC = %s\n\tT = %u\n\tR = %s\n", 
		q, str, (unsigned)t, otp);
	botpOCRAStepG(ctr, state);
	strCopy(q, otp2);
	strCopy(q + strLen(q), otp3);
	botpOCRAStepR(otp, (const octet*)q, strLen(q), t += 10, state);
	hexFrom(str, ctr, 8);
	printf("OCRA.2:\n\tQ = %s\n\tC = %s\n\tT = %u\n\tR = %s\n", 
		q, str, (unsigned)t, otp);
	botpOCRAStepG(ctr, state);
	strCopy(q, otp3);
	strCopy(q + strLen(q), otp2);
	botpOCRAStepR(otp, (const octet*)q, strLen(q), ++t, state);
	hexFrom(str, ctr, 8);
	printf("OCRA.2:\n\tQ = %s\n\tC = %s\n\tT = %u\n\tR = %s\n", 
		q, str, (unsigned)t, otp);
	// все нормально
	return TRUE;
}
