/*
*******************************************************************************
\file botp.с
\brief STB 34.101.47/botp: OTP algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.02
\version 2016.04.22
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
экспериментально вот здесь 
	http://crypto.stackexchange.com/questions/27474/
	[how-does-the-hotp-dynamic-truncation-function-generalize-to-longer-hashes]
номер октета, с которого начинается пароль, определяется по последнему октету 
mac.

В RFC 4226/6238 разрешается использовать пароли из 6..8 десятичных символов.
В RFC 6287 это требование ослабляется: пароль может дополнительно состоять 
из 4, 5, 9, 10 цифр. Ослабление не очень понятно, поскольку имеется только 
3 варианта выбора первой (старшей) цифры пароля из 10 цифр: '0', '1' или '2'.
В реализации пароли из 10 цифр запрещаются.
*******************************************************************************
*/

static const u32 powers_of_10[10] = {
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
};

void botpDT(char* otp, size_t digit, const octet mac[], size_t mac_len)
{
	register u32 pwd;
	register size_t offset;
	ASSERT(mac_len >= 20);
	ASSERT(4 <= digit && digit <= 9);
	ASSERT(memIsValid(otp, digit + 1));
	ASSERT(memIsValid(mac, mac_len));
	offset = mac[mac_len - 1] & 15;
	pwd = mac[offset], pwd <<= 8;
	pwd ^= mac[offset + 1], pwd <<= 8;
	pwd ^= mac[offset + 2], pwd <<= 8;
	pwd ^= mac[offset + 3];
	pwd &= 0x7FFFFFFF;
	pwd %= powers_of_10[digit];
	decFromU32(otp, digit, pwd);
	offset = 0;
	pwd = 0;
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

void botpCtrNext(octet ctr[8])
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

/*
*******************************************************************************
Режим HOTP
*******************************************************************************
*/

typedef struct
{
	size_t digit;		/*< число цифр в пароле */
	octet ctr[8];		/*< счетчик */
	octet ctr1[8];		/*< копия счетчика */
	octet mac[32];		/*< имитовставка */
	char otp[10];		/*< текущий пароль */
	octet stack[];		/*< [2 * beltHMAC_deep()] */
} botp_hotp_st;

size_t botpHOTP_keep()
{
	return sizeof(botp_hotp_st) + 2 * beltHMAC_keep();
}

void botpHOTPStart(void* state, size_t digit, const octet key[], 
	size_t key_len)
{
	botp_hotp_st* s = (botp_hotp_st*)state;
	ASSERT(6 <= digit && digit <= 8);
	ASSERT(memIsDisjoint2(key, key_len, s, botpHOTP_keep()));
	s->digit = digit;
	beltHMACStart(s->stack + beltHMAC_keep(), key, key_len);
}

void botpHOTPStepS(void* state, const octet ctr[8])
{
	botp_hotp_st* s = (botp_hotp_st*)state;
	ASSERT(memIsDisjoint2(ctr, 8, s, botpHOTP_keep()) || ctr == s->ctr);
	memMove(s->ctr, ctr, 8);
}

void botpHOTPStepR(char* otp, void* state)
{
	botp_hotp_st* s = (botp_hotp_st*)state;
	// pre
	ASSERT(memIsDisjoint2(otp, s->digit + 1, state, botpHOTP_keep()) || 
		otp == s->otp);
	// вычислить имитовставку
	memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
	beltHMACStepA(s->ctr, 8, s->stack);
	beltHMACStepG(s->mac, s->stack);
	// построить пароль
	botpDT(otp, s->digit, s->mac, 32);
	// инкремент счетчика
	botpCtrNext(s->ctr);
}

bool_t botpHOTPStepV(const char* otp, void* state)
{
	botp_hotp_st* s = (botp_hotp_st*)state;
	// pre
	ASSERT(strIsValid(otp));
	ASSERT(memIsDisjoint2(otp, strLen(otp) + 1, state, botpHOTP_keep()));
	// сохранить счетчик
	memCopy(s->ctr1, s->ctr, 8);
	// проверить пароль
	botpHOTPStepR(s->otp, state);
	if (strEq(s->otp, otp))
		return TRUE;
	// вернуться к первоначальному счетчику
	memCopy(s->ctr, s->ctr1, 8);
	return FALSE;
}

void botpHOTPStepG(octet ctr[8], const void* state)
{
	const botp_hotp_st* s = (const botp_hotp_st*)state;
	ASSERT(memIsDisjoint2(ctr, 8, state, botpHOTP_keep()) || ctr == s->ctr);
	memMove(ctr, s->ctr, 8);
}

err_t botpHOTPRand(char* otp, size_t digit, const octet key[], size_t key_len, 
	const octet ctr[8])
{
	void* state;
	// проверить входные данные
	if (digit < 6 || digit > 8)
		return ERR_BAD_PARAMS;
	if (!memIsValid(otp, digit + 1) || 
		!memIsValid(key, key_len) ||
		!memIsValid(ctr, 8))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(botpHOTP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// сгенерировать пароль и изменить счетчик
	botpHOTPStart(state, digit, key, key_len);
	botpHOTPStepS(state, ctr);
	botpHOTPStepR(otp, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t botpHOTPVerify(const char* otp, const octet key[], size_t key_len, 
	const octet ctr[8])
{
	void* state;
	bool_t success;
	// проверить входные данные
	if (!strIsValid(otp) || strLen(otp) < 6 || strLen(otp) > 8)
		return ERR_BAD_PWD;
	if (!memIsValid(key, key_len) || !memIsValid(ctr, 8))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(botpHOTP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// проверить пароль
	botpHOTPStart(state, strLen(otp), key, key_len);
	botpHOTPStepS(state, ctr);
	success = botpHOTPStepV(otp, state);
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
	size_t digit;		/*< число цифр в пароле */
	octet t[8];			/*< округленная отметка времени */
	octet mac[32];		/*< имитовставка */
	char otp[10];		/*< текущий пароль */
	octet stack[];		/*< [2 * beltHMAC_deep()] */
} botp_totp_st;

size_t botpTOTP_keep()
{
	return sizeof(botp_totp_st) + 2 * beltHMAC_keep();
}

void botpTOTPStart(void* state, size_t digit, const octet key[], 
	size_t key_len)
{
	botp_totp_st* s = (botp_totp_st*)state;
	ASSERT(6 <= digit && digit <= 8);
	ASSERT(memIsDisjoint2(key, key_len, s, botpTOTP_keep()));
	s->digit = digit;
	beltHMACStart(s->stack + beltHMAC_keep(), key, key_len);
}

void botpTOTPStepR(char* otp, tm_time_t t, void* state)
{
	botp_totp_st* s = (botp_totp_st*)state;
	// pre
	ASSERT(t != TIME_ERR);
	ASSERT(memIsDisjoint2(otp, s->digit + 1, state, botpHOTP_keep()) || 
		otp == s->otp);
	// вычислить имитовставку
	memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
	botpTimeToCtr(s->t, t);
	beltHMACStepA(s->t, 8, s->stack);
	beltHMACStepG(s->mac, s->stack);
	// построить пароль
	botpDT(otp, s->digit, s->mac, 32);
}

bool_t botpTOTPStepV(const char* otp, tm_time_t t, void* state)
{
	botp_totp_st* s = (botp_totp_st*)state;
	// pre
	ASSERT(strIsValid(otp));
	ASSERT(t != TIME_ERR);
	ASSERT(memIsDisjoint2(otp, strLen(otp) + 1, state, botpTOTP_keep()));
	// вычислить и проверить пароль
	botpTOTPStepR(s->otp, t, state);
	return strEq(s->otp, otp);
}

err_t botpTOTPRand(char* otp, size_t digit, const octet key[], size_t key_len, 
	tm_time_t t)
{
	void* state;
	// проверить входные данные
	if (digit < 6 || digit > 8)
		return ERR_BAD_PARAMS;
	if (t == TIME_ERR)
		return ERR_BAD_TIME;
	if (!memIsValid(otp, digit + 1) || 
		!memIsValid(key, key_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(botpTOTP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// сгенерировать пароль
	botpTOTPStart(state, digit, key, key_len);
	botpTOTPStepR(otp, t, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t botpTOTPVerify(const char* otp, const octet key[], size_t key_len, 
	tm_time_t t)
{
	void* state;
	bool_t success;
	// проверить входные данные
	if (!strIsValid(otp) || strLen(otp) < 6 || strLen(otp) > 8)
		return ERR_BAD_PWD;
	if (t == TIME_ERR)
		return ERR_BAD_TIME;
	if (!memIsValid(key, key_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(botpTOTP_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// проверить пароль
	botpTOTPStart(state, strLen(otp), key, key_len);
	success = botpTOTPStepV(otp, t, state);
	// завершить
	blobClose(state);
	return success ? ERR_OK : ERR_BAD_PWD;
}

/*
*******************************************************************************
Режим OCRA
*******************************************************************************
*/

typedef struct botp_ocra_st
{
	char suite[64];		/*< описатель */
	size_t digit;		/*< число цифр в пароле */
	octet ctr[8];		/*< счетчик */
	octet ctr1[8];		/*< копия счетчика */
	size_t ctr_len;		/*< длина счетчика */
	octet q[128];		/*< запрос */
	char q_type;		/*< тип запроса (A, N, H) */
	size_t q_max;		/*< максимальная длина одиночного запроса */
	octet p[64];		/*< хэш-значение статического пароля */
	size_t p_len;		/*< длина p */
	octet s[512];		/*< идентификатор сеанса */
	size_t s_len;		/*< длина идентификатора */
	octet t[8];			/*< отметка времени */
	tm_time_t ts;		/*< шаг времени */
	octet mac[32];		/*< имитовставка */
	char otp[10];		/*< текущий пароль */
	octet stack[];		/*< [2 * beltHMAC_deep()] */
} botp_ocra_st;

size_t botpOCRA_keep()
{
	return sizeof(botp_ocra_st) + 2 * beltHMAC_keep();
}

static const char ocra_prefix[] = "OCRA-1:HOTP-";
static const char ocra_hbelt[] = "HBELT";
static const char ocra_sha1[] = "SHA1";
static const char ocra_sha256[] = "SHA256";
static const char ocra_sha512[] = "SHA512";

bool_t botpOCRAStart(void* state, const char* suite, const octet key[], 
	size_t key_len)
{
	botp_ocra_st* s = (botp_ocra_st*)state;
	// pre
	ASSERT(strIsValid(suite));
	ASSERT(memIsDisjoint2(suite, strLen(suite) + 1, s, botpOCRA_keep()));
	ASSERT(memIsDisjoint2(key, key_len, s, botpOCRA_keep()));
	// подготовить state
	memSetZero(s, botpOCRA_keep());
	// разбор suite: длина
	if (strLen(suite) >= sizeof(s->suite))
		return FALSE;
	// разбор suite: префикс
	if (!strStartsWith(suite, ocra_prefix))
		return FALSE;
	suite += strLen(ocra_prefix);
	if (!strStartsWith(suite, ocra_hbelt))
		return FALSE;
	suite += strLen(ocra_hbelt);
	if (*suite++ != '-')
		return FALSE;
	// разбор suite: digit
	if (*suite < '4' || *suite > '9')
		return FALSE;
	s->digit = (size_t)(*suite++ - '0');
	// разбор suite: DataInput
	if (*suite++ != ':')
		return FALSE;
	// разбор suite: ctr
	if (*suite == 'C')
	{
		if (*++suite != '-')
			return FALSE;
		++suite;
		s->ctr_len = 8;
	}
	// разбор suite: q
	if (*suite++ != 'Q')
		return FALSE;
	switch (*suite)
	{
	case 'A':
	case 'N':
	case 'H':
		s->q_type = *suite++;
		break;
	default:
		return FALSE;
	}
	if (suite[0] < '0' || suite[0] > '9' || 
		suite[1] < '0' || suite[1] > '9')
		return FALSE;
	s->q_max = (size_t)(suite[0] - '0');
	s->q_max *= 10, s->q_max += (size_t)(suite[1] - '0');
	if (s->q_max < 4 || s->q_max > 64)
		return FALSE;
	suite += 2;
	// разбор suite: p
	if (strStartsWith(suite, "-P"))
	{
		suite += 2;
		if (strStartsWith(suite, ocra_hbelt))
		{
			suite += strLen(ocra_hbelt);
			s->p_len = 32;
		}
		else if (strStartsWith(suite, ocra_sha1))
		{
			suite += strLen(ocra_sha1);
			s->p_len = 20;
		}
		else if (strStartsWith(suite, ocra_sha256))
		{
			suite += strLen(ocra_sha256);
			s->p_len = 32;
		}
		else if (strStartsWith(suite, ocra_sha512))
		{
			suite += strLen(ocra_sha512);
			s->p_len = 64;
		}
		else
			return FALSE;
	}
	// разбор suite: s
	if (strStartsWith(suite, "-S"))
	{
		suite += 2;
		if (suite[0] < '0' || suite[0] > '9' || 
			suite[1] < '0' || suite[1] > '9' ||
			suite[2] < '0' || suite[2] > '9')
			return FALSE;
		s->s_len = (size_t)(suite[0] - '0');
		s->s_len *= 10, s->s_len += (size_t)(suite[1] - '0');
		s->s_len *= 10, s->s_len += (size_t)(suite[2] - '0');
		if (s->s_len > 512)
			return FALSE;
		suite += 3;
	}
	// разбор suite: t
	if (strStartsWith(suite, "-T"))
	{
		suite += 2;
		if (*suite < '1' || *suite > '5')
			return FALSE;
		s->ts = (size_t)(*suite++ - '0');
		if (*suite >= '0' && *suite <= '9')
			s->ts *= 10, s->ts += (size_t)(*suite++ - '0');
		switch (*suite++)
		{
		case 'S':
			if (s->ts > 59)
				return FALSE;
			break;
		case 'M':
			if (s->ts > 59)
				return FALSE;
			s->ts *= 60;
			break;
		case 'H':
			if (s->ts > 48)
				return FALSE;
			s->ts *= 3600;
			break;
		default:
			return FALSE;
		}
	}
	// разбор suite: окончание
	if (*suite)
		return FALSE;
	memCopy(s->suite, suite, strLen(suite) + 1);
	// запуск HMAC 
	beltHMACStart(s->stack + beltHMAC_keep(), key, key_len);
	return TRUE;
}

void botpOCRAStepS(void* state, const octet ctr[8], const octet p[], 
	const octet s[])
{
	botp_ocra_st* ss = (botp_ocra_st*)state;
	// pre
	ASSERT(memIsValid(ss, botpOCRA_keep()));
	// загрузить сtr
	if (ss->ctr_len)
	{
		ASSERT(memIsDisjoint2(ctr, 8, ss, botpOCRA_keep()) || ctr == ss->ctr);
		memMove(ss->ctr, ctr, 8);
	}
	// загрузить p
	if (ss->p_len)
	{
		ASSERT(memIsDisjoint2(p, ss->p_len, ss, botpOCRA_keep()) || p == ss->p);
		memMove(ss->p, p, ss->p_len);
	}
	// загрузить s
	if (ss->s_len)
	{
		ASSERT(memIsDisjoint2(p, ss->s_len, s, botpOCRA_keep()) || s == ss->s);
		memMove(ss->s, s, ss->s_len);
	}
}

void botpOCRAStepR(char* otp, const octet q[], size_t q_len, tm_time_t t, 
	void* state)
{
	botp_ocra_st* s = (botp_ocra_st*)state;
	// pre
	ASSERT(memIsDisjoint2(otp, s->digit + 1, state, botpOCRA_keep()) || 
		otp == s->otp);
	ASSERT(4 <= q_len && q_len <= 2 * s->q_max);
	ASSERT(memIsValid(q, q_len));
	ASSERT(t != TIME_ERR);
	// вычислить имитовставку
	memCopy(s->stack, s->stack + beltHMAC_keep(), beltHMAC_keep());
	beltHMACStepA(s->suite, strLen(s->suite) + 1, s->stack);
	if (s->ctr_len)
		beltHMACStepA(s->ctr, 8, s->stack), botpCtrNext(s->ctr);
	memSetZero(s->q + q_len, sizeof(s->q) - q_len);
	beltHMACStepA(s->q, q_len, s->stack);
	if (s->p_len)
		beltHMACStepA(s->p, s->p_len, s->stack);
	if (s->s_len)
		beltHMACStepA(s->s, s->s_len, s->stack);
	if (s->ts)
		botpTimeToCtr(s->t, t), beltHMACStepA(s->t, 8, s->stack);
	beltHMACStepG(s->mac, s->stack);
	// построить пароль
	botpDT(otp, s->digit, s->mac, 32);
}

bool_t botpOCRAStepV(const char* otp, const octet q[], size_t q_len, 
	tm_time_t t, void* state)
{
	botp_ocra_st* s = (botp_ocra_st*)state;
	// pre
	ASSERT(strIsValid(otp));
	ASSERT(memIsDisjoint2(otp, strLen(otp) + 1, state, botpOCRA_keep()));
	// сохранить счетчик
	memCopy(s->ctr1, s->ctr, 8);
	// проверить пароль
	botpOCRAStepR(s->otp, q, q_len, t, state);
	if (strEq(s->otp, otp))
		return TRUE;
	// вернуться к первоначальному счетчику
	memCopy(s->ctr, s->ctr1, 8);
	return FALSE;
}

void botpOCRAStepG(octet ctr[8], const void* state)
{
	const botp_ocra_st* s = (const botp_ocra_st*)state;
	ASSERT(memIsDisjoint2(ctr, 8, state, botpOCRA_keep()) || ctr == s->ctr);
	memMove(ctr, s->ctr, 8);
}

err_t botpOCRARand(char* otp, const char* suite, const octet key[],	
	size_t key_len, const octet q[], size_t q_len, const octet ctr[8], 
	const octet p[], const octet s[], tm_time_t t)
{
	botp_ocra_st* state;
	// предварительно проверить входные данные
	if (!strIsValid(suite) || !memIsValid(key, key_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = (botp_ocra_st*)blobCreate(botpOCRA_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// разобрать suite
	if (!botpOCRAStart(state, suite, key, key_len))
	{
		blobClose(state);
		return ERR_BAD_FORMAT;
	}
	// проверить q_len
	if (q_len < 4 || q_len > 2 * state->q_max)
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// полностью проверить входные данные
	if (!memIsValid(otp, state->digit + 1) ||
		state->ctr_len && !memIsValid(ctr, state->ctr_len) ||
		!memIsValid(q, q_len) ||
		state->p_len && !memIsValid(p, state->p_len) ||
		state->s_len && !memIsValid(s, state->s_len))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	if (state->ts && t == TIME_ERR)
	{
		blobClose(state);
		return ERR_BAD_TIME;
	}
	// сгенерировать пароль
	botpOCRAStepS(state, ctr, p, s);
	botpOCRAStepR(otp, q, q_len, t, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t botpOCRAVerify(const char* otp, const char* suite, const octet key[], 
	size_t key_len, const octet q[], size_t q_len, const octet ctr[8], 
	const octet p[], const octet s[], tm_time_t t)
{
	botp_ocra_st* state;
	bool_t success;
	// предварительно проверить входные данные
	if (!strIsValid(suite) || !memIsValid(key, key_len))
		return ERR_BAD_INPUT;
	// создать состояние
	state = (botp_ocra_st*)blobCreate(botpOCRA_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// разобрать suite
	if (!botpOCRAStart(state, suite, key, key_len))
	{
		blobClose(state);
		return ERR_BAD_FORMAT;
	}
	// проверить q_len
	if (q_len < 4 || q_len > 2 * state->q_max)
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// полностью проверить входные данные
	if (state->digit != strLen(otp))
	{
		blobClose(state);
		return ERR_BAD_PWD;
	}
	if (!memIsValid(otp, state->digit + 1) ||
		state->ctr_len && !memIsValid(ctr, state->ctr_len) ||
		!memIsValid(q, q_len) ||
		state->p_len && !memIsValid(p, state->p_len) ||
		state->s_len && !memIsValid(s, state->s_len))
	{
		blobClose(state);
		return ERR_BAD_INPUT;
	}
	if (state->ts && t == TIME_ERR)
	{
		blobClose(state);
		return ERR_BAD_TIME;
	}
	// проверить пароль
	botpOCRAStepS(state, ctr, p, s);
	success = botpOCRAStepV(otp, q, q_len, t, state);
	// завершить
	blobClose(state);
	return success ? ERR_OK : ERR_BAD_PWD;
}
