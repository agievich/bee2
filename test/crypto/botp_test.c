/*
*******************************************************************************
\file botp_test.c
\brief Tests for STB 34.101.47/botp
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.06
\version 2019.08.30
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

Выполняются тесты из приложения А к СТБ 34.101.47-2016.
*******************************************************************************
*/

bool_t botpTest()
{
	octet ctr[8];
	char otp[16], otp1[16], otp2[16], otp3[16];
	const char suite[] = "OCRA-1:HOTP-HBELT-8:C-QN08-PHBELT-S064-T1M";
	char q[32];
	octet p[32];
	char p_str[72];
	char s_str[136];
	tm_time_t t;
	octet state[2048];
	// создать стек
	ASSERT(sizeof(state) >= botpHOTP_keep());
	ASSERT(sizeof(state) >= botpTOTP_keep());
	ASSERT(sizeof(state) >= botpOCRA_keep());
	// HOTP.1
	memCopy(ctr, beltH() + 192, 8); 
	botpHOTPStart(state, 8, beltH() + 128, 32);
	botpHOTPStepS(state, ctr);
	botpHOTPStepG(ctr, state);
	botpHOTPStepR(otp, state);
	if (!strEq(otp, "21157984"))
		return FALSE;
	botpHOTPStepS(state, ctr);
	if (!botpHOTPStepV(otp, state))
		return FALSE;
	botpHOTPRand(otp1, 8, beltH() + 128, 32, ctr);
	if (!strEq(otp1, otp) ||
		botpHOTPVerify(otp1, beltH() + 128, 32, ctr) != ERR_OK)
		return FALSE;
	// HOTP.2
	botpHOTPStepR(otp2, state);
	if (!strEq(otp2, "17877985"))
		return FALSE;
	// HOTP.3
	botpHOTPStepR(otp3, state);
	if (!strEq(otp3, "26078636"))
		return FALSE;
	botpHOTPStepG(ctr, state);
	// TOTP.1
	t = 1449165288;
	ASSERT(t != TIME_ERR);
	botpTOTPStart(state, 8, beltH() + 128, 32);
	botpTOTPStepR(otp, t / 60, state);
	if (!strEq(otp, "97660664"))
		return FALSE;
	if (!botpTOTPStepV(otp, t / 60, state))
		return FALSE;
	botpTOTPRand(otp, 8, beltH() + 128, 32, t / 60);
	if (!strEq(otp, "97660664") ||
		botpTOTPVerify(otp, beltH() + 128, 32, t / 60) != ERR_OK)
		return FALSE;
	// TOTP.2
	t /= 60, ++t, t *= 60;
	botpTOTPStart(state, 8, beltH() + 128, 32);
	botpTOTPStepR(otp, t / 60, state);
	if (!strEq(otp, "94431522"))
		return FALSE;
	// TOTP.3
	t /= 60, t += 2, t *= 60, --t;
	botpTOTPStart(state, 8, beltH() + 128, 32);
	botpTOTPStepR(otp, t / 60, state);
	if (!strEq(otp, "55973851"))
		return FALSE;
	// OCRA.format
	if (botpOCRAStart(state, "OCRA-:HOTP-HBELT-6:C-QN08", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-3:C-QN08", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-6-QN08", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:C-QA65", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:C-QN08-", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:C-QN08-PSHA", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:QN08-SA13", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:QN08-T1N", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:QN08-T61S", beltH(), 32) ||
		botpOCRAStart(state, "OCRA-1:HOTP-HBELT-8:QN08-T51H", beltH(), 32) ||
		!botpOCRAStart(state, "OCRA-1:HOTP-HBELT-9:QN08-T8S", beltH(), 32))
		return FALSE;
	// OCRA.1
	beltHash(p, beltH(), 13);
	hexFrom(p_str, p, 32);
	hexFrom(s_str, beltH(), 64); 
	botpOCRAStart(state, suite, beltH() + 128, 32);
	botpOCRAStepS(state, ctr, p, beltH());
	botpOCRAStepG(ctr, state);
	t /= 60;
	strCopy(q, otp1);
	botpOCRAStepR(otp, (const octet*)q, strLen(q), t += 3, state);
	if (!strEq(otp, "85199085"))
		return FALSE;
	botpOCRAStepS(state, ctr, p, beltH());
	if (!botpOCRAStepV(otp, (const octet*)q, strLen(q), t, state))
		return FALSE;
	botpOCRARand(otp, suite, beltH() + 128, 32, (const octet*)q, strLen(q), 
		ctr, p, beltH(), t);
	if (!strEq(otp, "85199085"))
		return FALSE;
	if (botpOCRAVerify(otp, suite, beltH() + 128, 32, (const octet*)q, strLen(q), 
		ctr, p, beltH(), t) != ERR_OK)
		return FALSE;
	// OCRA.2
	strCopy(q, otp2);
	strCopy(q + strLen(q), otp3);
	botpOCRAStepR(otp, (const octet*)q, strLen(q), t += 10, state);
	if (!strEq(otp, "89873725"))
		return FALSE;
	// OCRA.3
	strCopy(q, otp3);
	strCopy(q + strLen(q), otp2);
	botpOCRAStepR(otp, (const octet*)q, strLen(q), ++t, state);
	if (!strEq(otp, "21318915"))
		return FALSE;
	// все нормально
	return TRUE;
}
