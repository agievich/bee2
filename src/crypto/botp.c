/*
*******************************************************************************
\file botp.с
\brief STB 34.101.botp: experimental OTP algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.02
\version 2015.11.20
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/dec.h"
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

В botpDT() реализован механизм "динамической обрезки" (dynamic truncation),
объявленный в RFC 4226 для HMAC(SHA-1), а затем продолженный в RFC 6238, 6287 
для HMAC(SHA-256) и HMAC(SHA-512). Пояснений по продолжению нет, но как выяснили
экспериментально вот здесь, 
	http://crypto.stackexchange.com/questions/27474/
	[how-does-the-hotp-dynamic-truncation-function-generalize-to-longer-hashes]
номер октета, с которого начинается пароль, определяется по последнему октету 
mac.

В RFC 4226/6238 разрешается использовать пароли из 6..8 десятичных символов.
В RFC 6287 это требование ослабляется: пароль может дополнительно состоять 
из 4, 5, 9, 10 цифр. Ослабление не очень понятно, поскольку имеется только 
3 варианта выбора первой (старшей) цифры пароля из 10 цифр: '0', '1' или '2'.
*******************************************************************************
*/

static const u32 powers_of_10[11] = {
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000,
	4294967295u,
};

static u32 botpDT(const octet mac[], size_t mac_len, size_t digit)
{
	register u32 pwd;
	register size_t offset;
	ASSERT(mac_len >= 20);
	ASSERT(memIsValid(mac, mac_len));
	ASSERT(4 <= digit && digit <= 10);
	offset = mac[mac_len - 1] & 15;
	pwd = mac[offset], pwd <<= 8;
	pwd ^= mac[offset + 1], pwd <<= 8;
	pwd ^= mac[offset + 2], pwd <<= 8;
	pwd ^= mac[offset + 3];
	pwd &= 0x7FFFFFFF;
	pwd %= powers_of_10[digit];
	offset = 0;
	return pwd;
}

static void botpCtrNext(octet ctr[8])
{
	register octet carry = 1;
	ASSERT(memIsValid(ctr, 8));
	carry = ((ctr[7] += carry) < carry);
	carry = ((ctr[6] += carry) < carry);
	carry = ((ctr[5] += carry) < carry);
	carry = ((ctr[4] += carry) < carry);
	carry = ((ctr[3] += carry) < carry);
	carry = ((ctr[2] += carry) < carry);
	carry = ((ctr[1] += carry) < carry);
	carry = ((ctr[0] += carry) < carry);
	carry = 0;
}

static void botpCtrPrev(octet ctr[8])
{
	register octet borrow = 1;
	borrow = ((ctr[7] -= borrow) > (255 - borrow));
	borrow = ((ctr[6] -= borrow) > (255 - borrow));
	borrow = ((ctr[5] -= borrow) > (255 - borrow));
	borrow = ((ctr[4] -= borrow) > (255 - borrow));
	borrow = ((ctr[3] -= borrow) > (255 - borrow));
	borrow = ((ctr[2] -= borrow) > (255 - borrow));
	borrow = ((ctr[1] -= borrow) > (255 - borrow));
	borrow = ((ctr[0] -= borrow) > (255 - borrow));
	borrow = 0;
}

static void botpTimeToCtr(octet ctr[8], tm_time_t t)
{
	ASSERT(sizeof(t) <= 8);
	memSetZero(ctr, 8 - sizeof(t));
	memCopy(ctr + 8 - sizeof(t), &t, sizeof(t));
#if (OCTET_ORDER == LITTLE_ENDIAN)
	memRev(ctr + 8 - sizeof(t), sizeof(t));
#endif
}

/*
*******************************************************************************
Режим HOTP
*******************************************************************************
*/
typedef struct
{
	octet ctr[8];		/*< счетчик */
	octet mac[32];		/*< имитовставка */
	octet stack[];		/*< [2 * beltHMAC_deep()] */
} botp_hotp_st;

size_t botpHOTP_keep()
{
	return sizeof(botp_hotp_st) + 2 * beltHMAC_keep();
}

void botpHOTPStart(void* state, const octet key[], size_t key_len)
{
	botp_hotp_st* s = (botp_hotp_st*)state;
	ASSERT(memIsDisjoint2(key, key_len, s, botpHOTP_keep()));
	beltHMACStart(s->stack + beltHMAC_keep(), key, key_len);
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
	decFromU32(otp, digit, botpDT(s->mac, 32, digit));
}

bool_t botpHOTPStepV(const char* otp, octet ctr[8], size_t attempts, 
	void* state)
{
	register u32 pwd;
	size_t digit;
	botp_hotp_st* s = (botp_hotp_st*)state;
	// pre
	ASSERT(decIsValid(otp) && strLen(otp) >= 6 && strLen(otp) <= 8);
	ASSERT(attempts < 10);
	ASSERT(memIsDisjoint3(otp, strLen(otp) + 1, ctr, 8, 
		state, botpHOTP_keep()));
	// обработать контрольный пароль и счетчик
	digit = strLen(otp);
	pwd = decToU32(otp);
	memCopy(s->ctr, ctr, 8);
	// попытки синхронизации
	do
	{
		// вычислить имитовставку
		memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
		beltHMACStepA(s->ctr, 8, s->stack);
		beltHMACStepG(s->mac, s->stack);
		// инкремент счетчика
		botpCtrNext(s->ctr);
		// проверить пароль
		if (botpDT(s->mac, 32, digit) == pwd)
		{
			memCopy(ctr, s->ctr, 8);
			pwd = 0, digit = 0;
			return TRUE;
		}
	}
	while (attempts--);
	pwd = 0, digit = 0;
	return FALSE;
}

err_t botpHOTPGen(char* otp, size_t digit, const octet key[], size_t key_len, 
	octet ctr[8])
{
	void* state;
	// проверить параметры
	if (digit < 6 || digit > 8)
		return ERR_BAD_PARAMS;
	// проверить входные данные
	if (!memIsValid(otp, digit + 1) || 
		!memIsValid(key, key_len) ||
		!memIsValid(ctr, 8) ||
		!memIsDisjoint2(otp, digit + 1, ctr, 8))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(botpHOTP_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// сгенерировать пароль
	botpHOTPStart(state, key, key_len);
	botpHOTPStepG(otp, digit, ctr, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t botpHOTPVerify(const char* otp, const octet key[], size_t key_len, 
	octet ctr[8], size_t attempts)
{
	void* state;
	bool_t success;
	// проверить контрольный пароль
	if (!strIsValid(otp) || strLen(otp) < 6 || strLen(otp) > 8)
		return ERR_BAD_PWD;
	// проверить параметры
	if (attempts >= 10)
		return ERR_BAD_PARAMS;
	// проверить входные данные
	if (!memIsValid(key, key_len) ||
		!memIsValid(ctr, 8))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(botpHOTP_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// проверить пароль
	botpHOTPStart(state, key, key_len);
	success = botpHOTPStepV(otp, ctr, attempts, state);
	// завершить
	blobClose(state);
	return success ? ERR_OK : ERR_BAD_PWD;
}

/*
*******************************************************************************
Режим TOTP
*******************************************************************************
*/

typedef struct
{
	octet ctr0[8];		/*< отправной счетчик */
	octet ctr[8];		/*< счетчик */
	octet mac[32];		/*< имитовставка */
	octet stack[];		/*< [2 * beltHMAC_deep()] */
} botp_totp_st;

size_t botpTOTP_keep()
{
	return sizeof(botp_totp_st) + 2 * beltHMAC_keep();
}

void botpTOTPStart(void* state, const octet key[], size_t key_len)
{
	botp_totp_st* s = (botp_totp_st*)state;
	ASSERT(memIsDisjoint2(key, key_len, s, botpTOTP_keep()));
	beltHMACStart(s->stack + beltHMAC_keep(), key, key_len);
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
	decFromU32(otp, digit, botpDT(s->mac, 32, digit));
}

bool_t botpTOTPStepV(const char* otp, tm_time_t t, size_t attempts_bwd, 
	size_t attempts_fwd, void* state)
{
	register u32 pwd;
	size_t digit;
	botp_totp_st* s = (botp_totp_st*)state;
	// pre
	ASSERT(decIsValid(otp) && strLen(otp) >= 6 && strLen(otp) <= 8);
	ASSERT(t != TIME_MAX);
	ASSERT(attempts_bwd < 5 && attempts_fwd < 5);
	ASSERT(memIsDisjoint2(otp, strLen(otp) + 1, state, botpTOTP_keep()));
	// обработать контрольный пароль
	digit = strLen(otp);
	pwd = decToU32(otp);
	// вычислить и проверить пароль
	memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
	botpTimeToCtr(s->ctr0, t);
	beltHMACStepA(s->ctr0, 8, s->stack);
	beltHMACStepG(s->mac, s->stack);
	// проверить пароль
	if (botpDT(s->mac, 32, digit) == pwd)
	{	
		pwd = 0, digit = 0;
		return TRUE;
	}
	// попытки "синхронизации назад"
	if (attempts_bwd)
	{
		memCopy(s->ctr, s->ctr0, 8);
		do
		{
			// декремент счетчика
			botpCtrPrev(s->ctr);
			// вычислить и проверить пароль
			memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
			beltHMACStepA(s->ctr, 8, s->stack);
			beltHMACStepG(s->mac, s->stack);
			if (botpDT(s->mac, 32, digit) == pwd)
			{
				pwd = 0, digit = 0;
				return TRUE;
			}
		}
		while (--attempts_bwd);
	}
	// попытки "синхронизации вперед"
	if (attempts_fwd)
	{
		memCopy(s->ctr, s->ctr0, 8);
		do
		{
			// инкремент счетчика
			botpCtrNext(s->ctr);
			// вычислить и проверить пароль
			memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
			beltHMACStepA(s->ctr, 8, s->stack);
			beltHMACStepG(s->mac, s->stack);
			if (botpDT(s->mac, 32, digit) == pwd)
			{
				pwd = 0, digit = 0;
				return TRUE;
			}
		}
		while (--attempts_fwd);
	}
	pwd = 0, digit = 0;
	return FALSE;
}

err_t botpTOTPGen(char* otp, size_t digit, const octet key[], size_t key_len, 
	tm_time_t t)
{
	void* state;
	// проверить параметры
	if (digit < 6 || digit > 8 || t == TIME_MAX)
		return ERR_BAD_PARAMS;
	// проверить входные данные
	if (!memIsValid(otp, digit + 1) || 
		!memIsValid(key, key_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(botpTOTP_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// сгенерировать пароль
	botpTOTPStart(state, key, key_len);
	botpTOTPStepG(otp, digit, t, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t botpTOTPVerify(const char* otp, const octet key[], size_t key_len, 
	tm_time_t t, size_t attempts_bwd, size_t attempts_fwd)
{
	void* state;
	bool_t success;
	// проверить контрольный пароль
	if (!strIsValid(otp) || strLen(otp) < 6 || strLen(otp) > 8)
		return ERR_BAD_PWD;
	// проверить параметры
	if (t == TIME_MAX || attempts_bwd >= 5 || attempts_bwd >= 5)
		return ERR_BAD_PARAMS;
	// проверить входные данные
	if (!memIsValid(key, key_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(botpTOTP_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// проверить пароль
	botpTOTPStart(state, key, key_len);
	success = botpTOTPStepV(otp, t, attempts_bwd, attempts_fwd, state);
	// завершить
	blobClose(state);
	return success ? ERR_OK : ERR_BAD_PWD;
}
