/*
*******************************************************************************
\file bpki.c
\brief STB 34.101.78 (bpki): PKI helpers
\project bee2 [cryptographic library]
\created 2021.04.03
\version 2022.07.07
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/der.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bels.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bpki.h"
#include "bee2/crypto/bign.h"
#include "bee2/crypto/brng.h"

/*
*******************************************************************************
Макросы кодирования
*******************************************************************************
*/

#define derEncStep(step, ptr, count)\
do {\
	size_t t = step;\
	ASSERT(t != SIZE_MAX);\
	ptr = ptr ? ptr + t : 0;\
	count += t;\
} while(0)\

#define derDecStep(step, ptr, count)\
do {\
	size_t t = step;\
	if (t == SIZE_MAX)\
		return SIZE_MAX;\
	ptr += t, count -= t;\
} while(0)\

/*
*******************************************************************************
Идентификаторы
*******************************************************************************
*/

static const char oid_bign_pubkey[] = "1.2.112.0.2.0.34.101.45.2.1";
static const char oid_bign_curve256v1[] = "1.2.112.0.2.0.34.101.45.3.1";
static const char oid_bign_curve384v1[] = "1.2.112.0.2.0.34.101.45.3.2";
static const char oid_bign_curve512v1[] = "1.2.112.0.2.0.34.101.45.3.3";
static const char oid_bels_share[] = "1.2.112.0.2.0.34.101.60.11";
static const char oid_bels_m0128v1[] = "1.2.112.0.2.0.34.101.60.2.1";
static const char oid_bels_m0192v1[] = "1.2.112.0.2.0.34.101.60.2.2";
static const char oid_bels_m0256v1[] = "1.2.112.0.2.0.34.101.60.2.3";
static const char oid_id_pbes2[] = "1.2.840.113549.1.5.13";
static const char oid_id_pbkdf2[] = "1.2.840.113549.1.5.12";
static const char oid_belt_kwp256[] = "1.2.112.0.2.0.34.101.31.73";
static const char oid_hmac_hbelt[] = "1.2.112.0.2.0.34.101.47.12";

/*
*******************************************************************************
Контейнер с личным ключом / частичным секретом (PKI): кодирование

SEQ PrivateKeyInfo
  SIZE(0)
  SEQ BignAlgorithmIdentifier | BelsAlgorithmIdentifier
    OID(bign-pubkey | bels-share)
    OID(bign-curveXXX | bels-m0XXX)
  OCT -- key
*******************************************************************************
*/

static size_t bpkiPrivkeyEnc(octet pki[], const octet privkey[],
	size_t privkey_len)
{
	der_anchor_t PKI[1];
	der_anchor_t BignAlgId[1];
	size_t count = 0;
	// проверить ключи
	ASSERT(privkey_len == 32 || privkey_len == 48 || privkey_len == 64);
	ASSERT(memIsNullOrValid(privkey, privkey_len));
	// кодировать
	derEncStep(derSEQEncStart(PKI, pki, count), pki, count);
	 derEncStep(derSIZEEnc(pki, 0), pki, count);
	 derEncStep(derSEQEncStart(BignAlgId, pki, count), pki, count);
	  derEncStep(derOIDEnc(pki, oid_bign_pubkey), pki, count);
	  if (privkey_len == 32)
		  derEncStep(derOIDEnc(pki, oid_bign_curve256v1), pki, count);
	  else if (privkey_len == 48)
		  derEncStep(derOIDEnc(pki, oid_bign_curve384v1), pki, count);
	  else
		  derEncStep(derOIDEnc(pki, oid_bign_curve512v1), pki, count);
	 derEncStep(derSEQEncStop(pki, count, BignAlgId), pki, count);
	 derEncStep(derOCTEnc(pki, privkey, privkey_len), pki, count);
	derEncStep(derSEQEncStop(pki, count, PKI), pki, count);
	// возвратить длину DER-кода
	return count;
}

static size_t bpkiPrivkeyDec(octet privkey[], size_t* privkey_len,
	const octet pki[], size_t count)
{
	der_anchor_t PKI[1];
	der_anchor_t BignAlgId[1];
	const octet* ptr = pki;
	size_t t, len;
	// декодировать
	derDecStep(derSEQDecStart(PKI, ptr, count), ptr, count);
	 derDecStep(derSIZEDec2(ptr, count, 0), ptr, count);
	 derDecStep(derSEQDecStart(BignAlgId, ptr, count), ptr, count);
	  derDecStep(derOIDDec2(ptr, count, oid_bign_pubkey), ptr, count);
	  if ((t = derOIDDec2(ptr, count, oid_bign_curve256v1)) != SIZE_MAX)
		  len = 32;
	  else if ((t = derOIDDec2(ptr, count, oid_bign_curve384v1)) != SIZE_MAX)
		  len = 48;
	  else if ((t = derOIDDec2(ptr, count, oid_bign_curve512v1)) != SIZE_MAX)
		  len = 64;
	  else
		  return SIZE_MAX;
	  ptr += t, count -= t;
	 derDecStep(derSEQDecStop(ptr, BignAlgId), ptr, count);
	 derDecStep(derOCTDec2(privkey, ptr, count, len), ptr, count);
	derDecStep(derSEQDecStop(ptr, PKI), ptr, count);
	// возвратить длину ключа
	if (privkey_len)
	{
		ASSERT(memIsValid(privkey_len, O_PER_S));
		*privkey_len = len;
	}
	// возвратить точную длину DER-кода
	return ptr - pki;
}

static size_t bpkiShareEnc(octet pki[], const octet share[], size_t share_len)
{
	der_anchor_t PKI[1];
	der_anchor_t BelsAlgId[1];
	size_t count = 0;
	// проверить ключи
	ASSERT(share_len == 17 || share_len == 25 || share_len == 33);
	ASSERT(memIsNullOrValid(share, share_len));
	ASSERT(!share || 1 <= share[0] && share[0] <= 16);
	// кодировать
	derEncStep(derSEQEncStart(PKI, pki, count), pki, count);
	 derEncStep(derSIZEEnc(pki, 0), pki, count);
	 derEncStep(derSEQEncStart(BelsAlgId, pki, count), pki, count);
	  derEncStep(derOIDEnc(pki, oid_bels_share), pki, count);
	  if (share_len == 17)
		  derEncStep(derOIDEnc(pki, oid_bels_m0128v1), pki, count);
	  else if (share_len == 25)
		  derEncStep(derOIDEnc(pki, oid_bels_m0192v1), pki, count);
	  else
		  derEncStep(derOIDEnc(pki, oid_bels_m0256v1), pki, count);
	 derEncStep(derSEQEncStop(pki, count, BelsAlgId), pki, count);
	 derEncStep(derOCTEnc(pki, share, share_len), pki, count);
	derEncStep(derSEQEncStop(pki, count, PKI), pki, count);
	// возвратить длину DER-кода
	return count;
}

static size_t bpkiShareDec(octet share[], size_t* share_len,
	const octet pki[], size_t count)
{
	der_anchor_t PKI[1];
	der_anchor_t BelsAlgId[1];
	const octet* ptr = pki;
	size_t t, len;
	// декодировать
	derDecStep(derSEQDecStart(PKI, ptr, count), ptr, count);
	 derDecStep(derSIZEDec2(ptr, count, 0), ptr, count);
	 derDecStep(derSEQDecStart(BelsAlgId, ptr, count), ptr, count);
	  derDecStep(derOIDDec2(ptr, count, oid_bels_share), ptr, count);
	  if ((t = derOIDDec2(ptr, count, oid_bels_m0128v1)) != SIZE_MAX)
		  len = 17;
	  else if ((t = derOIDDec2(ptr, count, oid_bels_m0192v1)) != SIZE_MAX)
		  len = 25;
	  else if ((t = derOIDDec2(ptr, count, oid_bels_m0256v1)) != SIZE_MAX)
		  len = 33;
	  else
		  return SIZE_MAX;
	  ptr += t, count -= t;
	 derDecStep(derSEQDecStop(ptr, BelsAlgId), ptr, count);
	 derDecStep(derOCTDec2(share, ptr, count, len), ptr, count);
	derDecStep(derSEQDecStop(ptr, PKI), ptr, count);
	// возвратить длину частичного секрета
	if (share_len)
	{
		ASSERT(memIsValid(share_len, O_PER_S));
		*share_len = len;
	}
	// возвратить точную длину DER-кода
	return ptr - pki;
}

/*
*******************************************************************************
Контейнер с защищенными данными (EPKI): кодирование

SEQ EncryptedPrivateKeyInfo
  SEQ EncryptionAlgorithmIdentifier
    OID(id-PBES2),
    SEQ PBES2-params
	  SEQ PBKDF2AlgorithmIdentifier
        OID(id-pbkdf2)
        SEQ PBKDF2-params
          OCT(SIZE(8)) -- salt
          SIZE(10000..MAX) -- iterCount
          SEQ PrfAlgorithmIdentifier
            OID(hmac-hbelt)
            NULL
      SEQ BeltKwpAlgorithmIdentifier
        OID(belt-kwp256)
        NULL
  OCT -- encData
*******************************************************************************
*/

static size_t bpkiEdataEnc(octet epki[], const octet edata[], size_t edata_len,
	const octet salt[8], size_t iter)
{
	der_anchor_t EPKI[1];
	der_anchor_t EncryptionAlgId[1];
	der_anchor_t PBES2_params[1];
	der_anchor_t PBKDF2AlgId[1];
	der_anchor_t PBKDF2_params[1];
	der_anchor_t PrfAlgId[1];
	der_anchor_t BeltKwpAlgId[1];
	size_t count = 0;
	// кодировать
	derEncStep(derSEQEncStart(EPKI, epki, count), epki, count);
	 derEncStep(derSEQEncStart(EncryptionAlgId, epki, count), epki, count);
	  derEncStep(derOIDEnc(epki, oid_id_pbes2), epki, count);
	  derEncStep(derSEQEncStart(PBES2_params, epki, count), epki, count);
	   derEncStep(derSEQEncStart(PBKDF2AlgId, epki, count), epki, count);
	    derEncStep(derOIDEnc(epki, oid_id_pbkdf2), epki, count);
	    derEncStep(derSEQEncStart(PBKDF2_params, epki, count), epki, count);
	     derEncStep(derOCTEnc(epki, salt, 8), epki, count);
		 derEncStep(derSIZEEnc(epki, iter), epki, count);
		 derEncStep(derSEQEncStart(PrfAlgId, epki, count), epki, count);
		  derEncStep(derOIDEnc(epki, oid_hmac_hbelt), epki, count);
		  derEncStep(derNULLEnc(epki), epki, count);
		 derEncStep(derSEQEncStop(epki, count, PrfAlgId), epki, count);
		derEncStep(derSEQEncStop(epki, count, PBKDF2_params), epki, count);
	   derEncStep(derSEQEncStop(epki, count, PBKDF2AlgId), epki, count);
	   derEncStep(derSEQEncStart(BeltKwpAlgId, epki, count), epki, count);
	    derEncStep(derOIDEnc(epki, oid_belt_kwp256), epki, count);
	    derEncStep(derNULLEnc(epki), epki, count);
	  derEncStep(derSEQEncStop(epki, count, BeltKwpAlgId), epki, count);
	  derEncStep(derSEQEncStop(epki, count, PBES2_params), epki, count);
	  derEncStep(derSEQEncStop(epki, count, EncryptionAlgId), epki, count);
	 derEncStep(derOCTEnc(epki, edata, edata_len), epki, count);
	derEncStep(derSEQEncStop(epki, count, EPKI), epki, count);
	// возвратить длину DER-кода
	return count;
}

static size_t bpkiEdataDec(octet edata[], size_t* edata_len, octet salt[8],
	size_t* iter, const octet epki[], size_t count)
{
	der_anchor_t EPKI[1];
	der_anchor_t EncryptionAlgId[1];
	der_anchor_t PBES2_params[1];
	der_anchor_t PBKDF2AlgId[1];
	der_anchor_t PBKDF2_params[1];
	der_anchor_t PrfAlgId[1];
	der_anchor_t BeltKwpAlgId[1];
	const octet* ptr = epki;
	// декодировать
	derDecStep(derSEQDecStart(EPKI, ptr, count), ptr, count);
	 derDecStep(derSEQDecStart(EncryptionAlgId, ptr, count), ptr, count);
	  derDecStep(derOIDDec2(ptr, count, oid_id_pbes2), ptr, count);
	  derDecStep(derSEQDecStart(PBES2_params, ptr, count), ptr, count);
	   derDecStep(derSEQDecStart(PBKDF2AlgId, ptr, count), ptr, count);
	    derDecStep(derOIDDec2(ptr, count, oid_id_pbkdf2), ptr, count);
	    derDecStep(derSEQDecStart(PBKDF2_params, ptr, count), ptr, count);
	     derDecStep(derOCTDec2(salt, ptr, count, 8), ptr, count);
	     derDecStep(derSIZEDec(iter, ptr, count), ptr, count);
	     derDecStep(derSEQDecStart(PrfAlgId, ptr, count), ptr, count);
	      derDecStep(derOIDDec2(ptr, count, oid_hmac_hbelt), ptr, count);
	      derDecStep(derNULLDec(ptr, count), ptr, count);
	     derDecStep(derSEQDecStop(ptr, PrfAlgId), ptr, count);
	    derDecStep(derSEQDecStop(ptr, PBKDF2_params), ptr, count);
	   derDecStep(derSEQDecStop(ptr, PBKDF2AlgId), ptr, count);
	   derDecStep(derSEQDecStart(BeltKwpAlgId, ptr, count), ptr, count);
	    derDecStep(derOIDDec2(ptr, count, oid_belt_kwp256), ptr, count);
	    derDecStep(derNULLDec(ptr, count), ptr, count);
	   derDecStep(derSEQDecStop(ptr, BeltKwpAlgId), ptr, count);
	  derDecStep(derSEQDecStop(ptr, PBES2_params), ptr, count);
	 derDecStep(derSEQDecStop(ptr, EncryptionAlgId), ptr, count);
	 derDecStep(derOCTDec(edata, edata_len, ptr, count), ptr, count);
	derDecStep(derSEQDecStop(ptr, EPKI), ptr, count);
	// возвратить длину DER-кода
	return ptr - epki;
}

/*
*******************************************************************************
Контейнер с личным ключом
*******************************************************************************
*/

err_t bpkiPrivkeyWrap(octet epki[], size_t* epki_len, const octet privkey[],
	size_t privkey_len, const octet pwd[], size_t pwd_len,
	const octet salt[8], size_t iter)
{
	size_t pki_len, edata_len, count;
	octet* key;
	err_t code;
	// проверить входные данные
	if (iter < 10000)
		return ERR_BAD_INPUT;
	if (privkey_len != 32 && privkey_len != 48 && privkey_len != 64)
		return ERR_BAD_PRIVKEY;
	// определить длину epki
	pki_len = bpkiPrivkeyEnc(0, privkey, privkey_len);
	if (pki_len == SIZE_MAX)
		return ERR_BAD_FORMAT;
	edata_len = pki_len + 16;
	count = bpkiEdataEnc(0, 0, edata_len, 0, iter);
	if (count == SIZE_MAX)
		return ERR_BAD_FORMAT;
	if (epki_len)
	{
		if (!memIsValid(epki_len, O_PER_S))
			return ERR_BAD_INPUT;
		*epki_len = count;
	}
	if (!epki)
		return ERR_OK;
	// проверить указатели
	if (!memIsValid(privkey, privkey_len) ||
		!memIsValid(epki, count) ||
			!memIsValid(pwd, pwd_len) ||
		!memIsValid(salt, 8))
		return ERR_BAD_INPUT;
	// сгенерировать ключ
	key = (octet*)blobCreate(32);
	if (!key)
		return ERR_OUTOFMEMORY;
	code = beltPBKDF2(key, pwd, pwd_len, iter, salt, 8);
	ERR_CALL_HANDLE(code, blobClose(key));
	// кодировать pki
	pki_len = bpkiPrivkeyEnc(epki + count - pki_len, privkey, privkey_len);
	code = pki_len != SIZE_MAX ? ERR_OK : ERR_BAD_PRIVKEY;
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// зашифровать pki
	code = beltKWPWrap(epki + count - pki_len - 16,
		epki + count - pki_len,	pki_len, 0, key, 32);
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// кодировать edata и epki
	count = bpkiEdataEnc(epki, epki + count - edata_len, edata_len,
		salt, iter);
	code = count != SIZE_MAX ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// все нормально
	blobClose(key);
	return ERR_OK;
}

err_t bpkiPrivkeyUnwrap(octet privkey[], size_t* privkey_len,
	const octet epki[], size_t epki_len, const octet pwd[], size_t pwd_len)
{
	size_t edata_len, pki_len, count, iter;
	void* state;
	octet* salt;
	octet* key;
	octet* edata;
	err_t code;
	// проверить входные данные
	if (epki_len == SIZE_MAX || !memIsValid(epki, epki_len) ||
		!memIsValid(pwd, pwd_len) ||
		privkey_len && !memIsValid(privkey_len, O_PER_S))
		return ERR_BAD_INPUT;
	// определить размер edata
	count = bpkiEdataDec(0, &edata_len, 0, 0, epki, epki_len);
	if (count != epki_len)
		return ERR_BAD_FORMAT;
	// подготовить буферы для параметров PBKDF2
	state = blobCreate(8 + 32 + edata_len);
	if (!state)
		return ERR_OUTOFMEMORY;
	salt = (octet*)state;
	key = salt + 8;
	edata = key + 32;
	// выделить edata
	count = bpkiEdataDec(edata, 0, salt, &iter, epki, epki_len);
	ASSERT(count == epki_len);
	// построить ключ защиты 
	code = beltPBKDF2(key, pwd, pwd_len, iter, salt, 8);
	ERR_CALL_HANDLE(code, blobClose(state));
	// снять защиту
	code = beltKWPUnwrap(edata, edata, edata_len, 0, key, 32);
	ERR_CALL_HANDLE(code, blobClose(state));
	pki_len = edata_len - 16;
	// определить длину privkey
	count = bpkiPrivkeyDec(privkey, &edata_len, edata, pki_len);
	code = count == pki_len ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// проверить указатель share 
	code = memIsNullOrValid(privkey, edata_len) ? ERR_OK : ERR_BAD_INPUT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// декодировать pki
	count = bpkiPrivkeyDec(privkey, privkey_len, edata, pki_len);
	ASSERT(count == pki_len);
	// завершить
	blobClose(state);
	return code;
}

/*
*******************************************************************************
Контейнер с частичным секретом
*******************************************************************************
*/

err_t bpkiShareWrap(octet epki[], size_t* epki_len, const octet share[],
	size_t share_len, const octet pwd[], size_t pwd_len,
	const octet salt[8], size_t iter)
{
	size_t pki_len, edata_len, count;
	octet* key;
	err_t code;
	// проверить входные данные
	if (iter < 10000)
		return ERR_BAD_INPUT;
	if (share_len != 17 && share_len != 25 && share_len != 33 ||
		share && (!memIsValid(share, 1) || share[0] == 0 || share[0] > 16))
		return ERR_BAD_SECKEY;
	// определить длину epki
	pki_len = bpkiShareEnc(0, share, share_len);
	if (pki_len == SIZE_MAX)
		return ERR_BAD_FORMAT;
	edata_len = pki_len + 16;
	count = bpkiEdataEnc(0, 0, edata_len, 0, iter);
	if (count == SIZE_MAX)
		return ERR_BAD_FORMAT;
	if (epki_len)
	{
		if (!memIsValid(epki_len, O_PER_S))
			return ERR_BAD_INPUT;
		*epki_len = count;
	}
	if (!epki)
		return ERR_OK;
	// проверить указатели
	if (!memIsValid(share, share_len) ||
		!memIsValid(epki, count) ||
		!memIsValid(pwd, pwd_len) ||
		!memIsValid(salt, 8))
		return ERR_BAD_INPUT;
	// сгенерировать ключ
	key = (octet*)blobCreate(32);
	if (!key)
		return ERR_OUTOFMEMORY;
	code = beltPBKDF2(key, pwd, pwd_len, iter, salt, 8);
	ERR_CALL_HANDLE(code, blobClose(key));
	// кодировать pki
	pki_len = bpkiShareEnc(epki + count - pki_len, share, share_len);
	code = pki_len != SIZE_MAX ? ERR_OK : ERR_BAD_PRIVKEY;
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// зашифровать pki
	code = beltKWPWrap(epki + count - pki_len - 16,
		epki + count - pki_len, pki_len, 0, key, 32);
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// кодировать edata и epki
	count = bpkiEdataEnc(epki, epki + count - edata_len, edata_len,
		salt, iter);
	code = count != SIZE_MAX ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// все нормально
	blobClose(key);
	return ERR_OK;
}

err_t bpkiShareUnwrap(octet share[], size_t* share_len,
	const octet epki[], size_t epki_len, const octet pwd[], size_t pwd_len)
{
	size_t edata_len, pki_len, count, iter;
	void* state;
	octet* salt;
	octet* key;
	octet* edata;
	err_t code;
	// проверить входные данные
	if (epki_len == SIZE_MAX || !memIsValid(epki, epki_len) ||
		!memIsValid(pwd, pwd_len) ||
		share_len && !memIsValid(share_len, O_PER_S))
		return ERR_BAD_INPUT;
	// определить размер edata
	count = bpkiEdataDec(0, &edata_len, 0, 0, epki, epki_len);
	if (count != epki_len)
		return ERR_BAD_FORMAT;
	// подготовить буферы для параметров PBKDF2
	state = blobCreate(8 + 32 + edata_len);
	if (!state)
		return ERR_OUTOFMEMORY;
	salt = (octet*)state;
	key = salt + 8;
	edata = key + 32;
	// выделить edata
	count = bpkiEdataDec(edata, 0, salt, &iter, epki, epki_len);
	ASSERT(count == epki_len);
	// построить ключ защиты 
	code = beltPBKDF2(key, pwd, pwd_len, iter, salt, 8);
	ERR_CALL_HANDLE(code, blobClose(state));
	// снять защиту
	code = beltKWPUnwrap(edata, edata, edata_len, 0, key, 32);
	ERR_CALL_HANDLE(code, blobClose(state));
	pki_len = edata_len - 16;
	// определить длину share
	count = bpkiShareDec(share, &edata_len, edata, pki_len);
	code = count == pki_len ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// проверить указатель share 
	code = memIsNullOrValid(share, edata_len) ? ERR_OK : ERR_BAD_INPUT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// декодировать pki
	count = bpkiShareDec(share, share_len, edata, pki_len);
	ASSERT(count == pki_len);
	// проверить первый октет share
	code = !share || 1 <= share[0] && share[0] <= 16 ?
		ERR_OK : ERR_BAD_SHAREKEY;
	// завершить
	blobClose(state);
	return code;
}
