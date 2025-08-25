/*
*******************************************************************************
\file btok_cvc.c
\brief STB 34.101.79 (btok): CV certificates
\project bee2 [cryptographic library]
\created 2022.07.04
\version 2025.05.12
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/der.h"
#include "bee2/core/mem.h"
#include "bee2/core/rng.h"
#include "bee2/core/str.h"
#include "bee2/core/tm.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bash.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bign.h"
#include "bee2/crypto/bign96.h"
#include "bee2/crypto/btok.h"

/*
*******************************************************************************
Идентификаторы
*******************************************************************************
*/

static const char oid_bign_pubkey[] = "1.2.112.0.2.0.34.101.45.2.1";
static const char oid_eid_access[] = "1.2.112.0.2.0.34.101.79.6.1";
static const char oid_esign_access[] = "1.2.112.0.2.0.34.101.79.6.2";
static const char oid_esign_auth_ext[] = "1.2.112.0.2.0.34.101.79.8.1";

/*
*******************************************************************************
Базовая криптография
*******************************************************************************
*/

static err_t btokParamsStd(bign_params* params, size_t privkey_len)
{
	switch (privkey_len)
	{
	case 24:
		return bign96ParamsStd(params, "1.2.112.0.2.0.34.101.45.3.0");
	case 32:
		return bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1");
	case 48:
		return bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.2");
	case 64:
		return bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.3");
	}
	return ERR_BAD_INPUT;
}

static err_t btokPubkeyCalc(octet pubkey[], const octet privkey[],
	size_t privkey_len)
{
	err_t code;
	bign_params params[1];
	// загрузить параметры
	code = btokParamsStd(params, privkey_len);
	ERR_CALL_CHECK(code);
	// вычислить ключ
	return privkey_len == 24 ? bign96PubkeyCalc(pubkey, params, privkey) :
		bignPubkeyCalc(pubkey, params, privkey);
}

static err_t btokPubkeyVal(const octet pubkey[], size_t pubkey_len)
{
	err_t code;
	bign_params params[1];
	// входной контроль
	if (pubkey_len % 2)
		return ERR_BAD_INPUT;
	// загрузить параметры
	code = btokParamsStd(params, pubkey_len / 2);
	ERR_CALL_CHECK(code);
	// проверить ключ
	return pubkey_len == 48 ? bign96PubkeyVal(params, pubkey) :
		bignPubkeyVal(params, pubkey);
}

static err_t btokKeypairVal(const octet privkey[], size_t privkey_len,
	const octet pubkey[], size_t pubkey_len)
{
	err_t code;
	bign_params params[1];
	// входной еонтроль
	if (pubkey_len != 2 * privkey_len)
		return ERR_BAD_KEYPAIR;
	// загрузить параметры
	code = btokParamsStd(params, privkey_len);
	ERR_CALL_CHECK(code);
	// проверить пару ключей
	return privkey_len == 24 ? bign96KeypairVal(params, privkey, pubkey) :
		bignKeypairVal(params, privkey, pubkey);
}

static err_t btokSign(octet sig[], const void* buf, size_t count,
	const octet privkey[], size_t privkey_len)
{
	err_t code;
	bign_params params[1];
	octet oid_der[16];
	size_t oid_len = sizeof(oid_der);
	void* stack;
	octet* hash;
	octet* t;
	size_t t_len;
	void* state;
	// загрузить параметры
	code = btokParamsStd(params, privkey_len);
	ERR_CALL_CHECK(code);
	// создать и разметить стек
	stack = blobCreate(2 * privkey_len + 
		(privkey_len <= 32 ? beltHash_keep() : bashHash_keep()));
	if (!stack)
		return ERR_OUTOFMEMORY;
	hash = (octet*)stack;
	t = hash + privkey_len;
	state = t + privkey_len;
	// хэшировать
	if (privkey_len <= 32)
	{
		beltHashStart(state);
		beltHashStepH(buf, count, state);
		beltHashStepG2(hash, privkey_len, state);
		code = bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
		ERR_CALL_HANDLE(code, blobClose(state));
		ASSERT(oid_len == 11);
	}
	else
	{
		bashHashStart(state, privkey_len * 4);
		bashHashStepH(buf, count, state);
		bashHashStepG(hash, privkey_len, state);
		code = bignOidToDER(oid_der, &oid_len, privkey_len == 48 ? 
			"1.2.112.0.2.0.34.101.77.12" : "1.2.112.0.2.0.34.101.77.13");
		ERR_CALL_HANDLE(code, blobClose(state));
		ASSERT(oid_len == 11);
	}
	// получить случайные числа
	if (rngIsValid())
		rngStepR(t, t_len = privkey_len, 0);
	else
		t_len = 0;
	// подписать
	if (privkey_len == 24)
		code = bign96Sign2(sig, params, oid_der, oid_len, hash, privkey,
			t, t_len);
	else
		code = bignSign2(sig, params, oid_der, oid_len, hash, privkey,
			t, t_len);
	// завершить
	blobClose(stack);
	return code;
}

static err_t btokVerify(const void* buf, size_t count, const octet sig[],
	const octet pubkey[], size_t pubkey_len)
{
	err_t code;
	bign_params params[1];
	octet oid_der[16];
	size_t oid_len = sizeof(oid_der);
	void* stack;
	octet* hash;
	void* state;
	// входной контроль
	if (pubkey_len % 2)
		return ERR_BAD_INPUT;
	// загрузить параметры
	code = btokParamsStd(params, pubkey_len / 2);
	ERR_CALL_CHECK(code);
	// создать и разметить стек
/*
	stack = blobCreate(pubkey_len / 2 +
		(pubkey_len <= 64 ? beltHash_keep() : bashHash_keep()));
	if (!stack)
		return ERR_OUTOFMEMORY;
	hash = (octet*)stack;
	state = hash + pubkey_len / 2;
*/
	stack = blobSlice(0,
		pubkey_len / 2, &hash, 
		pubkey_len <= 64 ? beltHash_keep() : bashHash_keep(), &state,
		SIZE_MAX);

	if (!stack)
		return ERR_OUTOFMEMORY;
	hash = (octet*)stack;
	state = hash + pubkey_len / 2;
   	// хэшировать
	if (pubkey_len <= 64)
	{
		beltHashStart(state);
		beltHashStepH(buf, count, state);
		beltHashStepG2(hash, pubkey_len / 2, state);
		code = bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
		ERR_CALL_HANDLE(code, blobClose(state));
		ASSERT(oid_len == 11);
	}
	else
	{
		bashHashStart(state, pubkey_len * 2);
		bashHashStepH(buf, count, state);
		bashHashStepG(hash, pubkey_len / 2, state);
		code = bignOidToDER(oid_der, &oid_len, pubkey_len == 96 ? 
			"1.2.112.0.2.0.34.101.77.12" : "1.2.112.0.2.0.34.101.77.13");
		ERR_CALL_HANDLE(code, blobClose(state));
		ASSERT(oid_len == 11);
	}
	// проверить открытый ключ
	if (pubkey_len == 48)
		code = bign96PubkeyVal(params, pubkey);
	else
		code = bignPubkeyVal(params, pubkey);
	ERR_CALL_HANDLE(code, blobClose(stack));
	// проверить подпись
	if (pubkey_len == 48)
		code = bign96Verify(params, oid_der, oid_len, hash, sig, pubkey);
	else
		code = bignVerify(params, oid_der, oid_len, hash, sig, pubkey);
	// завершить
	blobClose(stack);
	return code;
}

/*
*******************************************************************************
Содержание CV-сертификата
*******************************************************************************
*/

static bool_t btokCVCNameIsValid(const char* name)
{
	return strIsValid(name) &&
		8 <= strLen(name) && strLen(name) <= 12 &&
		strIsPrintable(name);
}

static bool_t tmDateLeq2(const octet left[6], const octet right[6])
{
	ASSERT(tmDateIsValid2(left));
	ASSERT(tmDateIsValid2(right));
	// left <= right?
	return memCmp(left, right, 6) <= 0;
}

static bool_t btokCVCSeemsValid(const btok_cvc_t* cvc)
{
	return memIsValid(cvc, sizeof(btok_cvc_t)) &&
		btokCVCNameIsValid(cvc->authority) &&
		btokCVCNameIsValid(cvc->holder) &&
		tmDateIsValid2(cvc->from) &&
		tmDateIsValid2(cvc->until) &&
		tmDateLeq2(cvc->from, cvc->until) &&
		(cvc->pubkey_len == 48 || cvc->pubkey_len == 64 || 
			cvc->pubkey_len == 96 || cvc->pubkey_len == 128);
}

err_t btokCVCCheck(const btok_cvc_t* cvc)
{
	if (!memIsValid(cvc, sizeof(btok_cvc_t)))
		return ERR_BAD_INPUT;
	if (!btokCVCNameIsValid(cvc->authority) || !btokCVCNameIsValid(cvc->holder))
		return ERR_BAD_NAME;
	if (!tmDateIsValid2(cvc->from) || !tmDateIsValid2(cvc->until) ||
		!tmDateLeq2(cvc->from, cvc->until))
		return ERR_BAD_DATE;
	return btokPubkeyVal(cvc->pubkey, cvc->pubkey_len);
}

err_t btokCVCCheck2(const btok_cvc_t* cvc, const btok_cvc_t* cvca)
{
	err_t code = btokCVCCheck(cvc);
	ERR_CALL_CHECK(code);
	if (!memIsValid(cvca, sizeof(btok_cvc_t)))
		return ERR_BAD_INPUT;
	if (!strEq(cvc->authority, cvca->holder))
		return ERR_BAD_NAME;
	if (!tmDateIsValid2(cvca->from) ||
		!tmDateIsValid2(cvca->until) ||
		!tmDateLeq2(cvca->from, cvc->from) ||
		!tmDateLeq2(cvc->from, cvca->until))
		return ERR_BAD_DATE;
	return ERR_OK;
}

/*
*******************************************************************************
Основная часть (тело) CV-сертификата

  SEQ[APPLICATION 78] CertificateBody
    SIZE[APPLICATION 41](0) -- version
	PSTR[APPLICATION 2](SIZE(8..12)) -- authority
	SEQ[APPLICATION 73] PubKey
	  OID(bign-pubkey)
	  BITS(SIZE(512|768|1024)) -- pubkey
	PSTR[APPLICATION 32](SIZE(8..12)) -- holder
	SEQ[APPLICATION 76] CertHAT OPTIONAL
	  OID(id-eIdAccess)
	  OCT(SIZE(5)) -- eid_hat
	OCT[APPLICATION 37](SIZE(6)) -- from
	OCT[APPLICATION 36](SIZE(6)) -- until
	SEQ[APPLICATION 5] CVExt OPTIONAL
      SEQ[APPLICATION 19] DDT -- Discretionary Data Template
	    OID(id-eSignAuthExt)
	    SEQ[APPLICATION 76] CertHAT OPTIONAL
	      OID(id-eSignAccess)
          OCT(SIZE(2)) -- esign_hat
*******************************************************************************
*/

#define derEncStep(step, ptr, count)\
do {\
	size_t _t = step;\
	ASSERT(_t != SIZE_MAX);\
	ptr = ptr ? ptr + _t : 0;\
	count += _t;\
} while(0)\

#define derDecStep(step, ptr, count)\
do {\
	size_t _t = step;\
	if (_t == SIZE_MAX)\
		return SIZE_MAX;\
	ptr += _t, count -= _t;\
} while(0)\

static size_t btokCVCBodyEnc(octet body[], const btok_cvc_t* cvc)
{
	der_anchor_t CertBody[1];
	der_anchor_t PubKey[1];
	der_anchor_t CertHAT[1];
	der_anchor_t CVExt[1];
	der_anchor_t DDT[1];
	size_t count = 0;
	// expect
	if (!btokCVCSeemsValid(cvc))
		return SIZE_MAX;
	// начать кодирование...
	derEncStep(derTSEQEncStart(CertBody, body, count, 0x7F4E), body, count);
	derEncStep(derTSIZEEnc(body, 0x5F29, 0), body, count);
	// ...authority...
	derEncStep(derTPSTREnc(body, 0x42, cvc->authority), body, count);
	// ...PubKey...
	derEncStep(derTSEQEncStart(PubKey, body, count, 0x7F49), body, count);
	derEncStep(derOIDEnc(body, oid_bign_pubkey), body, count);
	derEncStep(derBITEnc(body, cvc->pubkey, 8 * cvc->pubkey_len), body, count);
	derEncStep(derTSEQEncStop(body, count, PubKey), body, count);
	// ...holder...
	derEncStep(derTPSTREnc(body, 0x5F20, cvc->holder), body, count);
	// ...CertHAT...
	if (!memIsZero(cvc->hat_eid, 5))
	{
		derEncStep(derTSEQEncStart(CertHAT, body, count, 0x7F4C), body, count);
		derEncStep(derOIDEnc(body, oid_eid_access), body, count);
		derEncStep(derOCTEnc(body, cvc->hat_eid, 5), body, count);
		derEncStep(derTSEQEncStop(body, count, CertHAT), body, count);
	}
	// ...from/until...
	derEncStep(derTOCTEnc(body, 0x5F25, cvc->from, 6), body, count);
	derEncStep(derTOCTEnc(body, 0x5F24, cvc->until, 6), body, count);
	// ...CVExt...
	if (!memIsZero(cvc->hat_esign, 2))
	{
		derEncStep(derTSEQEncStart(CVExt, body, count, 0x65), body, count);
		derEncStep(derTSEQEncStart(DDT, body, count, 0x73), body, count);
		derEncStep(derOIDEnc(body, oid_esign_auth_ext), body, count);
		derEncStep(derTSEQEncStart(CertHAT, body, count, 0x7F4C), body, count);
		derEncStep(derOIDEnc(body, oid_esign_access), body, count);
		derEncStep(derOCTEnc(body, cvc->hat_esign, 2), body, count);
		derEncStep(derTSEQEncStop(body, count, CertHAT), body, count);
		derEncStep(derTSEQEncStop(body, count, DDT), body, count);
		derEncStep(derTSEQEncStop(body, count, CVExt), body, count);
	}
	// ...завершить кодирование
	derEncStep(derTSEQEncStop(body, count, CertBody), body, count);
	// возвратить длину DER-кода
	return count;
}

static size_t btokCVCBodyDec(btok_cvc_t* cvc, const octet body[], size_t count)
{
	der_anchor_t CertBody[1];
	der_anchor_t PubKey[1];
	der_anchor_t CertHAT[1];
	der_anchor_t CVExt[1];
	der_anchor_t DDT[1];
	const octet* ptr = body;
	size_t len;
	// pre
	ASSERT(memIsValid(cvc, sizeof(btok_cvc_t)));
	ASSERT(memIsValid(body, count));
	// начать декодирование...
	memSetZero(cvc, sizeof(btok_cvc_t));
	derDecStep(derTSEQDecStart(CertBody, ptr, count, 0x7F4E), ptr, count);
	derDecStep(derTSIZEDec2(ptr, count, 0x5F29, 0), ptr, count);
	// ...authority...
	if (derTPSTRDec(0, &len, ptr, count, 0x42) == SIZE_MAX ||
		len < 8 || len > 12)
		return SIZE_MAX;
	derDecStep(derTPSTRDec(cvc->authority, 0, ptr, count, 0x42), ptr, count);
	// ...PubKey...
	derDecStep(derTSEQDecStart(PubKey, ptr, count, 0x7F49), ptr, count);
	derDecStep(derOIDDec2(ptr, count, oid_bign_pubkey), ptr, count);
	if (derBITDec(0, &len, ptr, count) == SIZE_MAX ||
		len != 384 && len != 512 && len != 768 && len != 1024)
		return SIZE_MAX;
	cvc->pubkey_len = len / 8;
	derDecStep(derBITDec(cvc->pubkey, 0, ptr, count), ptr, count);
	derDecStep(derTSEQDecStop(ptr, PubKey), ptr, count);
	// ...holder...
	if (derTPSTRDec(0, &len, ptr, count, 0x5F20) == SIZE_MAX ||
		len < 8 || len > 12)
		return SIZE_MAX;
	derDecStep(derTPSTRDec(cvc->holder, 0, ptr, count, 0x5F20), ptr, count);
	// ...CertHAT...
	if (derStartsWith(ptr, count, 0x7F4C))
	{
		derDecStep(derTSEQDecStart(CertHAT, ptr, count, 0x7F4C), ptr, count);
		derDecStep(derOIDDec2(ptr, count, oid_eid_access), ptr, count);
		derDecStep(derOCTDec2(cvc->hat_eid, ptr, count, 5), ptr, count);
		derDecStep(derTSEQDecStop(ptr, CertHAT), ptr, count);
	}
	// ...from/until...
	derDecStep(derTOCTDec2(cvc->from, ptr, count, 0x5F25, 6), ptr, count);
	derDecStep(derTOCTDec2(cvc->until, ptr, count, 0x5F24, 6), ptr, count);
	// ...CVExt...
	if (derStartsWith(ptr, count, 0x65))
	{
		derDecStep(derTSEQDecStart(CVExt, ptr, count, 0x65), ptr, count);
		derDecStep(derTSEQDecStart(DDT, ptr, count, 0x73), ptr, count);
		derDecStep(derOIDDec2(ptr, count, oid_esign_auth_ext), ptr, count);
		derDecStep(derTSEQDecStart(CertHAT, ptr, count, 0x7F4C), ptr, count);
		derDecStep(derOIDDec2(ptr, count, oid_esign_access), ptr, count);
		derDecStep(derOCTDec2(cvc->hat_esign, ptr, count, 2), ptr, count);
		derDecStep(derTSEQDecStop(ptr, CertHAT), ptr, count);
		derDecStep(derTSEQDecStop(ptr, DDT), ptr, count);
		derDecStep(derTSEQDecStop(ptr, CVExt), ptr, count);
	}
	// ...завершить декодирование
	derDecStep(derTSEQDecStop(ptr, CertBody), ptr, count);
	// возвратить точную длину DER-кода
	return ptr - body;
}

/*
*******************************************************************************
Создание / разбор CV-сертификата

SEQ[APPLICATION 33] CVCertificate
  SEQ[APPLICATION 78] CertificateBody
  OCT[APPLICATION 55](SIZE(48|72|96)) -- sig
*******************************************************************************
*/

err_t btokCVCWrap(octet cert[], size_t* cert_len, btok_cvc_t* cvc,
	const octet privkey[], size_t privkey_len)
{
	err_t code;
	der_anchor_t CVCert[1];
	size_t count = 0;
	size_t t;
	// проверить входные данные
	if (!memIsValid(cvc, sizeof(btok_cvc_t)) ||
		privkey_len != 24 && 
			privkey_len != 32 && privkey_len != 48 && privkey_len != 64 ||
		!memIsValid(privkey, privkey_len) ||
		!memIsNullOrValid(cert_len, O_PER_S))
		return ERR_BAD_INPUT;
	// построить открытый ключ
	if (cvc->pubkey_len == 0)
	{
		code = btokPubkeyCalc(cvc->pubkey, privkey, privkey_len);
		ERR_CALL_CHECK(code);
		cvc->pubkey_len = 2 * privkey_len;
		memSetZero(cvc->pubkey + cvc->pubkey_len,
			sizeof(cvc->pubkey) - cvc->pubkey_len);
	}
	// проверить содержимое сертификата
	code = btokCVCCheck(cvc);
	ERR_CALL_CHECK(code);
	// начать кодирование...
	t = derTSEQEncStart(CVCert, cert, count, 0x7F21);
	ASSERT(t != SIZE_MAX);
	cert = cert ? cert + t : 0, count += t;
	// ...кодировать и подписать основную часть...
	t = btokCVCBodyEnc(cert, cvc);
	ASSERT(t != SIZE_MAX);
	if (cert)
	{
		code = btokSign(cvc->sig, cert, t, privkey, privkey_len);
		ERR_CALL_CHECK(code);
	}
	cert = cert ? cert + t : 0, count += t;
	if (privkey_len == 24)
		cvc->sig_len = 34;
	else
		cvc->sig_len = privkey_len + privkey_len / 2;
	// ...кодировать подпись...
	t = derTOCTEnc(cert, 0x5F37, cvc->sig, cvc->sig_len);
	ASSERT(t != SIZE_MAX);
	cert = cert ? cert + t : 0, count += t;
	// ...завершить кодирование
	t = derTSEQEncStop(cert, count, CVCert);
	ASSERT(t != SIZE_MAX);
	count += t;
	// возвратить длину DER-кода
	if (cert_len)
		*cert_len = count;
	return ERR_OK;
}

err_t btokCVCUnwrap(btok_cvc_t* cvc, const octet cert[], size_t cert_len,
	const octet pubkey[], size_t pubkey_len)
{
	err_t code;
	der_anchor_t CVCert[1];
	size_t t;
	const octet* body;
	size_t body_len;
	// проверить входные данные
	if (!memIsValid(cvc, sizeof(btok_cvc_t)) ||
		pubkey_len != 0 && pubkey_len != 48 &&
			pubkey_len != 64 && pubkey_len != 96 &&	pubkey_len != 128 ||
		pubkey_len == 0 && pubkey != 0 && pubkey != cvc->pubkey ||
		!memIsValid(cert, cert_len) ||
		!memIsValid(pubkey, pubkey_len) ||
		!memIsDisjoint2(cvc, sizeof(btok_cvc_t), cert, cert_len) ||
		!memIsDisjoint2(cvc, sizeof(btok_cvc_t), pubkey, pubkey_len))
		return ERR_BAD_INPUT;
	// подготовить cvc
	memSetZero(cvc, sizeof(btok_cvc_t));
	// начать декодирование...
	t = derTSEQDecStart(CVCert, cert, cert_len, 0x7F21);
	if (t == SIZE_MAX)
		return ERR_BAD_FORMAT;
	cert = cert ? cert + t : 0, cert_len -= t;
	// ...декодировать основную часть...
	t = btokCVCBodyDec(cvc, cert, cert_len);
	if (t == SIZE_MAX)
		return ERR_BAD_FORMAT;
	body = cert, body_len = t;
	cert = cert ? cert + t : 0, cert_len -= t;
	// ...определить длину подписи...
	if (pubkey_len == 0 && pubkey == cvc->pubkey)
		pubkey_len = cvc->pubkey_len;
	if (pubkey_len == 0)
	{
		size_t sig_len;
		if (derDec3(0, cert, cert_len, 0x5F37, sig_len = 34) == SIZE_MAX &&
			derDec3(0, cert, cert_len, 0x5F37, sig_len = 48) == SIZE_MAX &&
			derDec3(0, cert, cert_len, 0x5F37, sig_len = 72) == SIZE_MAX &&
			derDec3(0, cert, cert_len, 0x5F37, sig_len = 96) == SIZE_MAX)
			return ERR_BAD_FORMAT;
		cvc->sig_len = sig_len;
	}
	else
		cvc->sig_len = pubkey_len == 48 ? 34 : pubkey_len - pubkey_len / 4;
	// ...декодировать подпись...
	t = derTOCTDec2(cvc->sig, cert, cert_len, 0x5F37, cvc->sig_len);
	if (t == SIZE_MAX)
		return ERR_BAD_FORMAT;
	cert = cert ? cert + t : 0, cert_len -= t;
	// ...проверить подпись...
	if (pubkey_len)
	{
		code = btokVerify(body, body_len, cvc->sig, pubkey, pubkey_len);
		ERR_CALL_CHECK(code);
	}
	// ...завершить декодирование
	t = derTSEQDecStop(cert, CVCert);
	if (t == SIZE_MAX)
		return ERR_BAD_FORMAT;
	cert_len -= t;
	if (cert_len != 0)
		return ERR_BAD_FORMAT;
	// окончательная проверка cvc
	return btokCVCCheck(cvc);
}

/*
*******************************************************************************
Выпуск CV-сертификата
*******************************************************************************
*/

err_t btokCVCIss(octet cert[], size_t* cert_len, btok_cvc_t* cvc,
	const octet certa[], size_t certa_len, const octet privkeya[],
	size_t privkeya_len)
{
	err_t code;
	btok_cvc_t* cvca;
	// разобрать сертификат издателя
	cvca = (btok_cvc_t*)blobCreate(sizeof(btok_cvc_t));
	if (!cvca)
		return ERR_OUTOFMEMORY;
	code = btokCVCUnwrap(cvca, certa, certa_len, 0, 0);
	ERR_CALL_HANDLE(code, blobClose(cvca));
	// проверить содержимое выпускаемого сертификата
	code = btokCVCCheck2(cvc, cvca);
	ERR_CALL_HANDLE(code, blobClose(cvca));
	// проверить ключи издателя
	code = btokKeypairVal(privkeya, privkeya_len, cvca->pubkey,
		cvca->pubkey_len);
	ERR_CALL_HANDLE(code, blobClose(cvca));
	// создать сертификат
	code = btokCVCWrap(cert, cert_len, cvc, privkeya, privkeya_len);
	// завершить
	blobClose(cvca);
	return code;
}

/*
*******************************************************************************
Точная длина CV-сертификата
*******************************************************************************
*/

size_t btokCVCLen(const octet der[], size_t count)
{
	if (!memIsValid(der, count))
		return SIZE_MAX;
	return derDec2(0, 0, der, count, 0x7F21);
}

/*
*******************************************************************************
Проверка CV-сертификата
*******************************************************************************
*/

err_t btokCVCVal(const octet cert[], size_t cert_len, 
	const octet certa[], size_t certa_len, const octet* date)
{
	err_t code;
	void* stack;
	btok_cvc_t* cvc;
	btok_cvc_t* cvca;
	// входной контроль
	if (!memIsNullOrValid(date, 6))
		return ERR_BAD_INPUT;
	// выделить и разметить память
	stack = blobCreate(2 * sizeof(btok_cvc_t));
	if (!stack)
		return ERR_OUTOFMEMORY;
	cvc = (btok_cvc_t*)stack;
	cvca = cvc + 1;
	// разобрать сертификаты
	code = btokCVCUnwrap(cvca, certa, certa_len, 0, 0);
	ERR_CALL_HANDLE(code, blobClose(stack));
	code = btokCVCUnwrap(cvc, cert, cert_len, cvca->pubkey, cvca->pubkey_len);
	ERR_CALL_HANDLE(code, blobClose(stack));
	// проверить соответствие
	code = btokCVCCheck2(cvc, cvca);
	ERR_CALL_HANDLE(code, blobClose(stack));
	// проверить дату
	if (date)
	{
		if (!tmDateIsValid2(date))
			code = ERR_BAD_DATE;
		else if (!tmDateLeq2(cvc->from, date) || !tmDateLeq2(date, cvc->until))
			code = ERR_OUTOFRANGE;
	}
	// завершить
	blobClose(stack);
	return code;
}

err_t btokCVCVal2(btok_cvc_t* cvc, const octet cert[], size_t cert_len,
	const btok_cvc_t* cvca, const octet* date)
{
	err_t code;
	void* stack = 0;
	// входной контроль
	if (!memIsNullOrValid(cvc, sizeof(btok_cvc_t)) || 
		!memIsValid(cvca, sizeof(btok_cvc_t)) ||
		!memIsNullOrValid(date, 6))
		return ERR_BAD_INPUT;
	// выделить память
	if (!cvc)
	{
		stack = blobCreate(sizeof(btok_cvc_t));
		if (!stack)
			return ERR_OUTOFMEMORY;
		cvc = (btok_cvc_t*)stack;
	}
	// разобрать сертификат
	code = btokCVCUnwrap(cvc, cert, cert_len, cvca->pubkey, cvca->pubkey_len);
	ERR_CALL_HANDLE(code, blobClose(stack));
	// проверить соответствие
	code = btokCVCCheck2(cvc, cvca);
	ERR_CALL_HANDLE(code, blobClose(stack));
	// проверить дату
	if (date)
	{
		if (!tmDateIsValid2(date))
			code = ERR_BAD_DATE;
		else if (!tmDateLeq2(cvc->from, date) || !tmDateLeq2(date, cvc->until))
			code = ERR_OUTOFRANGE;
	}
	// завершить
	blobClose(stack);
	return code;
}

/*
*******************************************************************************
Проверка соответствия CV-сертификата
*******************************************************************************
*/

err_t btokCVCMatch(const octet cert[], size_t cert_len, const octet privkey[],
	size_t privkey_len)
{
	err_t code;
	btok_cvc_t* cvc;
	// выделить память
	cvc = (btok_cvc_t*)blobCreate(sizeof(btok_cvc_t));
	if (!cvc)
		return ERR_OUTOFMEMORY;
	// разобрать сертификат
	code = btokCVCUnwrap(cvc, cert, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, blobClose(cvc));
	// проверить соответствие
	code = btokKeypairVal(privkey, privkey_len, cvc->pubkey, cvc->pubkey_len);
	// завершить
	blobClose(cvc);
	return code;
}
