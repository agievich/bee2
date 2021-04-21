/*
*******************************************************************************
\file bpki.c
\brief STB 34.101.78 (bpki): PKI helpers
\project bee2/bpki
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2021.04.03
\version 2021.04.20
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/der.h"
#include "bee2/core/oid.h"
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

SEQUENCE PrivateKeyInfo
  INTEGER(0)
  SEQUENCE BignAlgorithmIdentifier | BelsAlgorithmIdentifier
    OID -- (bign-pubkey | bels-share)
    OID -- (bign-curveXXX | bels-m0XXX)
  OCTET STRING -- key
*******************************************************************************
*/

static size_t bpkiEncPrivkey(octet pki[], const octet privkey[],
	size_t privkey_len)
{
	der_anchor PKI[1];
	der_anchor BignAlgId[1];
	size_t count = 0;
	// проверить ключи
	ASSERT(privkey_len == 32 || privkey_len == 48 || privkey_len == 64);
	ASSERT(memIsNullOrValid(privkey, privkey_len));
	// кодировать
	derEncStep(derEncSEQStart(PKI, pki, count), pki, count);
	 derEncStep(derEncSIZE(pki, 0), pki, count);
	 derEncStep(derEncSEQStart(BignAlgId, pki, count), pki, count);
	  derEncStep(derEncOID(pki, oid_bign_pubkey), pki, count);
	  if (privkey_len == 32)
		  derEncStep(derEncOID(pki, oid_bign_curve256v1), pki, count);
	  else if (privkey_len == 48)
		  derEncStep(derEncOID(pki, oid_bign_curve384v1), pki, count);
	  else
		  derEncStep(derEncOID(pki, oid_bign_curve512v1), pki, count);
	 derEncStep(derEncSEQStop(pki, count, BignAlgId), pki, count);
	 derEncStep(derEncOCT(pki, privkey, privkey_len), pki, count);
	derEncStep(derEncSEQStop(pki, count, PKI), pki, count);
	// возвратить длину DER-кода
	return count;
}

static size_t bpkiDecPrivkey(octet privkey[], size_t* privkey_len,
	const octet pki[], size_t count)
{
	der_anchor PKI[1];
	der_anchor BignAlgId[1];
	const octet* ptr = pki;
	size_t t, len;
	// декодировать
	derDecStep(derDecSEQStart(PKI, ptr, count), ptr, count);
	 derDecStep(derDecSIZE2(ptr, count, 0), ptr, count);
	 derDecStep(derDecSEQStart(BignAlgId, ptr, count), ptr, count);
	  derDecStep(derDecOID2(ptr, count, oid_bign_pubkey), ptr, count);
	  if ((t = derDecOID2(ptr, count, oid_bign_curve256v1)) != SIZE_MAX)
		  len = 32;
	  else if ((t = derDecOID2(ptr, count, oid_bign_curve384v1)) != SIZE_MAX)
		  len = 48;
	  else if ((t = derDecOID2(ptr, count, oid_bign_curve512v1)) != SIZE_MAX)
		  len = 64;
	  else
		  return SIZE_MAX;
	  ptr += t, count -= t;
	 derDecStep(derDecSEQStop(ptr, BignAlgId), ptr, count);
	 derDecStep(derDecOCT2(privkey, ptr, count, len), ptr, count);
	derDecStep(derDecSEQStop(ptr, PKI), ptr, count);
	// возвратить длину ключа
	if (privkey_len)
	{
		ASSERT(memIsValid(privkey_len, O_PER_S));
		*privkey_len = len;
	}
	// возвратить точную длину DER-кода
	return ptr - pki;
}

static size_t bpkiEncShare(octet pki[], const octet share[], size_t share_len)
{
	der_anchor PKI[1];
	der_anchor BelsAlgId[1];
	size_t count = 0;
	// проверить ключи
	ASSERT(share_len == 33 || share_len == 49 || share_len == 65);
	ASSERT(memIsNullOrValid(share, share_len));
	ASSERT(!share || 1 <= share[0] && share[0] <= 16);
	// кодировать
	derEncStep(derEncSEQStart(PKI, pki, count), pki, count);
	 derEncStep(derEncSIZE(pki, 0), pki, count);
	 derEncStep(derEncSEQStart(BelsAlgId, pki, count), pki, count);
	  derEncStep(derEncOID(pki, oid_bels_share), pki, count);
	  if (share_len == 33)
		  derEncStep(derEncOID(pki, oid_bels_m0128v1), pki, count);
	  else if (share_len == 49)
		  derEncStep(derEncOID(pki, oid_bels_m0192v1), pki, count);
	  else
		  derEncStep(derEncOID(pki, oid_bels_m0256v1), pki, count);
	 derEncStep(derEncSEQStop(pki, count, BelsAlgId), pki, count);
	 derEncStep(derEncOCT(pki, share, share_len), pki, count);
	derEncStep(derEncSEQStop(pki, count, PKI), pki, count);
	// возвратить длину DER-кода
	return count;
}

static size_t bpkiDecShare(octet share[], size_t* share_len,
	const octet pki[], size_t count)
{
	der_anchor PKI[1];
	der_anchor BelsAlgId[1];
	const octet* ptr = pki;
	size_t t, len;
	// декодировать
	derDecStep(derDecSEQStart(PKI, ptr, count), ptr, count);
	 derDecStep(derDecSIZE2(ptr, count, 0), ptr, count);
	 derDecStep(derDecSEQStart(BelsAlgId, ptr, count), ptr, count);
	  derDecStep(derDecOID2(ptr, count, oid_bels_share), ptr, count);
	  if ((t = derDecOID2(ptr, count, oid_bels_m0128v1)) != SIZE_MAX)
		  len = 33;
	  else if ((t = derDecOID2(ptr, count, oid_bels_m0192v1)) != SIZE_MAX)
		  len = 49;
	  else if ((t = derDecOID2(ptr, count, oid_bels_m0256v1)) != SIZE_MAX)
		  len = 65;
	  else
		  return SIZE_MAX;
	  ptr += t, count -= t;
	 derDecStep(derDecSEQStop(ptr, BelsAlgId), ptr, count);
	 derDecStep(derDecOCT2(share, ptr, count, len), ptr, count);
	derDecStep(derDecSEQStop(ptr, PKI), ptr, count);
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

SEQUENCE EncryptedPrivateKeyInfo
  SEQUENCE EncryptionAlgorithmIdentifier
    OID(id-PBES2),
    SEQUENCE PBES2-params
	  SEQUENCE PBKDF2AlgorithmIdentifier
        OID(id-pbkdf2)
        SEQUENCE PBKDF2-params
          OCTET STRING(SIZE(8)) -- salt
          INTEGER(10000..MAX) -- iterCount
          SEQUENCE PrfAlgorithmIdentifier
            OID(hmac-hbelt)
            NULL
      SEQUENCE BeltKwpAlgorithmIdentifier
        OID(belt-kwp256)
        NULL
  OCTET STRING -- encData
*******************************************************************************
*/

static size_t bpkiEncEdata(octet epki[], const octet edata[], size_t edata_len,
	const octet salt[8], size_t iter)
{
	der_anchor EPKI[1];
	der_anchor EncryptionAlgId[1];
	der_anchor PBES2_params[1];
	der_anchor PBKDF2AlgId[1];
	der_anchor PBKDF2_params[1];
	der_anchor PrfAlgId[1];
	der_anchor BeltKwpAlgId[1];
	size_t count = 0;
	// кодировать
	derEncStep(derEncSEQStart(EPKI, epki, count), epki, count);
	 derEncStep(derEncSEQStart(EncryptionAlgId, epki, count), epki, count);
	  derEncStep(derEncOID(epki, oid_id_pbes2), epki, count);
	  derEncStep(derEncSEQStart(PBES2_params, epki, count), epki, count);
	   derEncStep(derEncSEQStart(PBKDF2AlgId, epki, count), epki, count);
	    derEncStep(derEncOID(epki, oid_id_pbkdf2), epki, count);
	    derEncStep(derEncSEQStart(PBKDF2_params, epki, count), epki, count);
	     derEncStep(derEncOCT(epki, salt, 8), epki, count);
		 derEncStep(derEncSIZE(epki, iter), epki, count);
		 derEncStep(derEncSEQStart(PrfAlgId, epki, count), epki, count);
		  derEncStep(derEncOID(epki, oid_hmac_hbelt), epki, count);
		  derEncStep(derEncNULL(epki), epki, count);
		 derEncStep(derEncSEQStop(epki, count, PrfAlgId), epki, count);
		derEncStep(derEncSEQStop(epki, count, PBKDF2_params), epki, count);
	   derEncStep(derEncSEQStop(epki, count, PBKDF2AlgId), epki, count);
	   derEncStep(derEncSEQStart(BeltKwpAlgId, epki, count), epki, count);
	    derEncStep(derEncOID(epki, oid_belt_kwp256), epki, count);
	    derEncStep(derEncNULL(epki), epki, count);
	  derEncStep(derEncSEQStop(epki, count, BeltKwpAlgId), epki, count);
	  derEncStep(derEncSEQStop(epki, count, PBES2_params), epki, count);
	  derEncStep(derEncSEQStop(epki, count, EncryptionAlgId), epki, count);
	 derEncStep(derEncOCT(epki, edata, edata_len), epki, count);
	derEncStep(derEncSEQStop(epki, count, EPKI), epki, count);
	// возвратить длину DER-кода
	return count;
}

static size_t bpkiDecEdata(octet edata[], size_t* edata_len, octet salt[8],
	size_t* iter, const octet epki[], size_t count)
{
	der_anchor EPKI[1];
	der_anchor EncryptionAlgId[1];
	der_anchor PBES2_params[1];
	der_anchor PBKDF2AlgId[1];
	der_anchor PBKDF2_params[1];
	der_anchor PrfAlgId[1];
	der_anchor BeltKwpAlgId[1];
	const octet* ptr = epki;
	// декодировать
	derDecStep(derDecSEQStart(EPKI, ptr, count), ptr, count);
	 derDecStep(derDecSEQStart(EncryptionAlgId, ptr, count), ptr, count);
	  derDecStep(derDecOID2(ptr, count, oid_id_pbes2), ptr, count);
	  derDecStep(derDecSEQStart(PBES2_params, ptr, count), ptr, count);
	   derDecStep(derDecSEQStart(PBKDF2AlgId, ptr, count), ptr, count);
	    derDecStep(derDecOID2(ptr, count, oid_id_pbkdf2), ptr, count);
	    derDecStep(derDecSEQStart(PBKDF2_params, ptr, count), ptr, count);
	     derDecStep(derDecOCT2(salt, ptr, count, 8), ptr, count);
	     derDecStep(derDecSIZE(iter, ptr, count), ptr, count);
	     derDecStep(derDecSEQStart(PrfAlgId, ptr, count), ptr, count);
	      derDecStep(derDecOID2(ptr, count, oid_hmac_hbelt), ptr, count);
	      derDecStep(derDecNULL(ptr, count), ptr, count);
	     derDecStep(derDecSEQStop(ptr, PrfAlgId), ptr, count);
	    derDecStep(derDecSEQStop(ptr, PBKDF2_params), ptr, count);
	   derDecStep(derDecSEQStop(ptr, PBKDF2AlgId), ptr, count);
	   derDecStep(derDecSEQStart(BeltKwpAlgId, ptr, count), ptr, count);
	    derDecStep(derDecOID2(ptr, count, oid_belt_kwp256), ptr, count);
	    derDecStep(derDecNULL(ptr, count), ptr, count);
	   derDecStep(derDecSEQStop(ptr, BeltKwpAlgId), ptr, count);
	  derDecStep(derDecSEQStop(ptr, PBES2_params), ptr, count);
	 derDecStep(derDecSEQStop(ptr, EncryptionAlgId), ptr, count);
	 derDecStep(derDecOCT(edata, edata_len, ptr, count), ptr, count);
	derDecStep(derDecSEQStop(ptr, EPKI), ptr, count);
	// возвратить длину DER-кода
	return ptr - epki;
}

/*
*******************************************************************************
Контейнер с личным ключом
*******************************************************************************
*/

err_t bpkiWrapPrivkey(octet epki[], size_t* epki_len, const octet privkey[],
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
	pki_len = bpkiEncPrivkey(0, privkey, privkey_len);
	if (pki_len == SIZE_MAX)
		return ERR_BAD_FORMAT;
	edata_len = pki_len + 16;
	count = bpkiEncEdata(0, 0, edata_len, 0, iter);
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
	pki_len = bpkiEncPrivkey(epki + count - pki_len, privkey, privkey_len);
	code = pki_len != SIZE_MAX ? ERR_OK : ERR_BAD_PRIVKEY;
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// зашифровать pki
	code = beltKWPWrap(epki + count - pki_len - 16,
		epki + count - pki_len,	pki_len, 0, key, 32);
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// кодировать edata и epki
	count = bpkiEncEdata(epki, epki + count - edata_len, edata_len,
		salt, iter);
	code = count != SIZE_MAX ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// все нормально
	blobClose(key);
	return ERR_OK;
}

err_t bpkiUnwrapPrivkey(octet privkey[], size_t* privkey_len,
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
	count = bpkiDecEdata(0, &edata_len, 0, 0, epki, epki_len);
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
	count = bpkiDecEdata(edata, 0, salt, &iter, epki, epki_len);
	ASSERT(count == epki_len);
	// построить ключ защиты 
	code = beltPBKDF2(key, pwd, pwd_len, iter, salt, 8);
	ERR_CALL_HANDLE(code, blobClose(state));
	// снять защиту
	code = beltKWPUnwrap(edata, edata, edata_len, 0, key, 32);
	ERR_CALL_HANDLE(code, blobClose(state));
	pki_len = edata_len - 16;
	// определить длину privkey
	count = bpkiDecPrivkey(privkey, &edata_len, edata, pki_len);
	code = count == pki_len ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// проверить указатель share 
	code = memIsNullOrValid(privkey, edata_len) ? ERR_OK : ERR_BAD_INPUT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// декодировать pki
	count = bpkiDecPrivkey(privkey, privkey_len, edata, pki_len);
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

err_t bpkiWrapShare(octet epki[], size_t* epki_len, const octet share[],
	size_t share_len, const octet pwd[], size_t pwd_len,
	const octet salt[8], size_t iter)
{
	size_t pki_len, edata_len, count;
	octet* key;
	err_t code;
	// проверить входные данные
	if (iter < 10000)
		return ERR_BAD_INPUT;
	if (share_len != 33 && share_len != 49 && share_len != 65 ||
		share && (!memIsValid(share, 1) || share[0] == 0 || share[0] > 16))
		return ERR_BAD_SECKEY;
	// определить длину epki
	pki_len = bpkiEncShare(0, share, share_len);
	if (pki_len == SIZE_MAX)
		return ERR_BAD_FORMAT;
	edata_len = pki_len + 16;
	count = bpkiEncEdata(0, 0, edata_len, 0, iter);
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
	pki_len = bpkiEncShare(epki + count - pki_len, share, share_len);
	code = pki_len != SIZE_MAX ? ERR_OK : ERR_BAD_PRIVKEY;
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// зашифровать pki
	code = beltKWPWrap(epki + count - pki_len - 16,
		epki + count - pki_len, pki_len, 0, key, 32);
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// кодировать edata и epki
	count = bpkiEncEdata(epki, epki + count - edata_len, edata_len,
		salt, iter);
	code = count != SIZE_MAX ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, (memWipe(epki, count), blobClose(key)));
	// все нормально
	blobClose(key);
	return ERR_OK;
}

err_t bpkiUnwrapShare(octet share[], size_t* share_len,
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
	count = bpkiDecEdata(0, &edata_len, 0, 0, epki, epki_len);
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
	count = bpkiDecEdata(edata, 0, salt, &iter, epki, epki_len);
	ASSERT(count == epki_len);
	// построить ключ защиты 
	code = beltPBKDF2(key, pwd, pwd_len, iter, salt, 8);
	ERR_CALL_HANDLE(code, blobClose(state));
	// снять защиту
	code = beltKWPUnwrap(edata, edata, edata_len, 0, key, 32);
	ERR_CALL_HANDLE(code, blobClose(state));
	pki_len = edata_len - 16;
	// определить длину share
	count = bpkiDecShare(share, &edata_len, edata, pki_len);
	code = count == pki_len ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// проверить указатель share 
	code = memIsNullOrValid(share, edata_len) ? ERR_OK : ERR_BAD_INPUT;
	ERR_CALL_HANDLE(code, blobClose(state));
	// декодировать pki
	count = bpkiDecShare(share, share_len, edata, pki_len);
	ASSERT(count == pki_len);
	// проверить первый октет share
	code = !share || 1 <= share[0] && share[0] <= 16 ?
		ERR_OK : ERR_BAD_SHAREKEY;
	// завершить
	blobClose(state);
	return code;
}

