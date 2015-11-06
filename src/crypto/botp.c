/*
*******************************************************************************
\file botp.с
\brief STB 34.101.botp: experimental OTP algorithms
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.02
\version 2015.11.06
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/tm.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/botp.h"

/*
*******************************************************************************
Вспомогательные функции

\todo В botpMACTrunc() реализован спорный механизм "динамической обрезки"
(dynamic truncation). Предлагается использовать естественную обрезку: 
взять первые 32 бита mac в качестве pwd, снять в pwd старший бит.
*******************************************************************************
*/

static u32 botpMACTrunc(const octet mac[32])
{
	register u32 pwd;
	register size_t offset;
	offset = mac[31] & 15;
	pwd = mac[offset + 3], pwd <<= 8;
	pwd ^= mac[offset + 2], pwd <<= 8;
	pwd ^= mac[offset + 1], pwd <<= 8;
	pwd ^= mac[offset];
	pwd &= 0x7FFFFFFF;
	offset = 0;
	return pwd;
}

static void botpMacToOtp(char* otp, size_t digit, const octet mac[32])
{
	register u32 pwd;
	ASSERT(6 <= digit && digit <= 8);
	ASSERT(memIsValid(otp, digit + 1));
	// выделить пароль и закодировать его
	pwd = botpMACTrunc(mac);
	while (digit--)
	{
		*otp = '0' + (char)(pwd % 10);
		pwd /= 10;
		++otp;
	}
	*otp = '\0';
	pwd = 0;
}

static bool_t botpMacFitOtp(const char* otp, size_t digit, 
	const octet mac[32])
{
	register u32 pwd;
	register word diff = 0;
	ASSERT(6 <= digit && digit <= 8);
	ASSERT(strIsValid(otp) && strLen(otp) == digit);
	// выделить пароль и сравнить его c otp
	pwd = botpMACTrunc(mac);
	while (digit--)
	{
		diff |= *otp ^ ('0' + (char)(pwd % 10));
		pwd /= 10;
		++otp;
	}
	pwd = 0;
	return wordEq(diff, 0);
}

static void botpCtrNext(octet ctr[8])
{
	wwFrom((word*)ctr, ctr, 8);
	zzAddW2((word*)ctr, W_OF_O(8), 1);
	wwTo(ctr, 8, (word*)ctr);
}

static void botpCtrPrev(octet ctr[8])
{
	wwFrom((word*)ctr, ctr, 8);
	zzSubW2((word*)ctr, W_OF_O(8), 1);
	wwTo(ctr, 8, (word*)ctr);
}

static void botpTimeToCtr(octet ctr[8], tm_time_t t)
{
	memCopy(ctr, &t, sizeof(t));
#if (OCTET_ORDER == BIG_ENDIAN)
	memRev(ctr, sizeof(t));
#endif
	memSetZero(ctr + sizeof(t), 8 - sizeof(t));
}

/*
*******************************************************************************
Режим HOTP
*******************************************************************************
*/
typedef struct
{
	octet mac[32];		/*< имитовставка */		
	octet stack[];		/*< [2 * beltHMAC_deep()] */
} botp_hotp_st;

size_t botpHOTP_keep()
{
	return sizeof(botp_hotp_st) + 2 * beltHMAC_keep();
}

void botpHOTPStart(void* state, const octet key[], size_t len)
{
	botp_hotp_st* s = (botp_hotp_st*)state;
	ASSERT(memIsDisjoint2(key, len, s, botpHOTP_keep()));
	beltHMACStart(s->stack + beltHMAC_keep(), key, len);
}

void botpHOTPStepG(char* otp, size_t digit, octet ctr[8], void* state)
{
	botp_hotp_st* s = (botp_hotp_st*)state;
	// pre
	ASSERT(6 <= digit && digit <= 8);
	ASSERT(memIsDisjoint3(otp, digit + 1, ctr, 8, state, botpHOTP_keep()));
	// вычислить имитовставку
	memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
	beltHMACStepA(ctr, 8, s->stack);
	beltHMACStepG(s->mac, s->stack);
	// инкремент счетчика
	botpCtrNext(ctr);
	// построить пароль
	botpMacToOtp(otp, digit, s->mac);
}

bool_t botpHOTPStepV(const char* otp, octet ctr[8], size_t attempts, 
	void* state)
{
	botp_hotp_st* s = (botp_hotp_st*)state;
	size_t digit;
	// pre
	ASSERT(strIsValid(otp));
	ASSERT(attempts < 1000);
	ASSERT(memIsDisjoint3(otp, strLen(otp) + 1, ctr, 8, 
		state, botpHOTP_keep()));
	// проверить длину
	digit = strLen(otp);
	if (digit < 6 || digit > 8)
		return FALSE;
	// попытки синхронизации
	do
	{
		// вычислить имитовставку
		memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
		beltHMACStepA(ctr, 8, s->stack);
		beltHMACStepG(s->mac, s->stack);
		// инкремент счетчика
		botpCtrNext(ctr);
		// проверить пароль
		if (botpMacFitOtp(otp, digit, s->mac))
			return TRUE;
	}
	while (attempts--);
	return FALSE;
}


/*
*******************************************************************************
Режим TOTP
*******************************************************************************
*/
typedef struct
{
	octet ctr[8];		/*< счетчик */
	octet mac[32];		/*< имитовставка */
	octet stack[];		/*< [2 * beltHMAC_deep()] */
} botp_totp_st;

size_t botpTOTP_keep()
{
	return sizeof(botp_totp_st) + 2 * beltHMAC_keep();
}

void botpTOTPStart(void* state, const octet key[], size_t len)
{
	botp_totp_st* s = (botp_totp_st*)state;
	ASSERT(memIsDisjoint2(key, len, s, botpTOTP_keep()));
	beltHMACStart(s->stack + beltHMAC_keep(), key, len);
}

void botpTOTPStepG(char* otp, size_t digit, tm_time_t t, void* state)
{
	botp_totp_st* s = (botp_totp_st*)state;
	// pre
	ASSERT(strIsValid(otp));
	ASSERT(6 <= digit && digit <= 8);
	ASSERT(t != TIME_MAX);
	ASSERT(memIsDisjoint2(otp, digit + 1, state, botpTOTP_keep()));
	// вычислить имитовставку
	memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
	botpTimeToCtr(s->ctr, t);
	beltHMACStepA(s->ctr, 8, s->stack);
	beltHMACStepG(s->mac, s->stack);
	// построить пароль
	botpMacToOtp(otp, digit, s->mac);
}

bool_t botpTOTPStepV(const char* otp, tm_time_t t, size_t attempts_bwd, 
	size_t attempts_fwd, void* state)
{
	botp_totp_st* s = (botp_totp_st*)state;
	size_t digit;
	// pre
	ASSERT(strIsValid(otp));
	ASSERT(t != TIME_MAX);
	ASSERT(attempts_bwd <= 3 && attempts_fwd <= 3);
	ASSERT(memIsDisjoint2(otp, strLen(otp) + 1, state, botpTOTP_keep()));
	// проверить длину
	digit = strLen(otp);
	if (digit < 6 || digit > 8)
		return FALSE;
	// вычислить имитовставку
	memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
	botpTimeToCtr(s->ctr, t);
	beltHMACStepA(s->ctr, 8, s->stack);
	beltHMACStepG(s->mac, s->stack);
	// проверить пароль
	if (botpMacFitOtp(otp, digit, s->mac))
		return TRUE;
	// попытки "синхронизации назад"
	while (attempts_bwd--)
	{
		// декремент счетчика
		botpCtrPrev(s->ctr);
		// вычислить имитовставку
		memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
		beltHMACStepA(s->ctr, 8, s->stack);
		beltHMACStepG(s->mac, s->stack);
		// проверить пароль
		if (botpMacFitOtp(otp, digit, s->mac))
			return TRUE;
	}
	// попытки "синхронизации вперед"
	botpTimeToCtr(s->ctr, t);
	while (attempts_fwd--)
	{
		// инкремент счетчика
		botpCtrNext(s->ctr);
		// вычислить имитовставку
		memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
		beltHMACStepA(s->ctr, 8, s->stack);
		beltHMACStepG(s->mac, s->stack);
		// проверить пароль
		if (botpMacFitOtp(otp, digit, s->mac))
			return TRUE;
	}
	return FALSE;
}
