/*
*******************************************************************************
\file pkcs5.c
\brief PKCS#5 EncryptedPrivateKeyInfo
\project bee2 [cryptographic library]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2021.04.03
\version 2021.04.03
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/der.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/prng.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/pkcs5.h"

// PrivateKeyInfo ::= 
// SEQUENCE
//   INTEGER(0)
//   SEQUENCE
//     OID -- (bels-share | bign-pubkey | gsum-master)
//     OID -- (bels-m | bign-curve | gsum-v1)
//   OCTET STRING -- key
// 
// EncryptedPrivateKeyInfo ::= 
// SEQUENCE EncryptedPrivateKeyInfo
//   SEQUENCE EncryptionAlgorithmIdentifier
//     OID(id-PBES2),
//     SEQ PBES2-params
//       SEQ PBKDF2AlgorithmIdentifier
//         OID(ID-pbkdf2)
//         SEQ PBKDF2-params
//           OCTET STRING(SIZE(8)) -- salt
//           INTEGER(10000..MAX) -- iterCount
//           SEQ PrfAlgorithmIdentifier
//             OID(hmac-belt)
//             NULL
//       SEQ BeltKeywrapAlgorithmIdentifier
//         OID(belt-keywrap256)
//         NULL
// OCTET STRING -- encData

#define derTagNULL 5
#define derTagOCT 4
#define derTagOID 6
#define derTagINT 2
#define derTagSEQ (16 | (1 << 6))

static size_t derLen_size_t(size_t n) {
  size_t i = 0;
  size_t h = 0x80;
  for(; n; n = n >> 8, ++i) h = n & 0x80;
  return i + (h >> 7);
}
static size_t derEnc_size_t(octet *der, size_t n) {
  size_t i = 0;
  size_t h = 0x80;
  for(; n; n = n >> 8, ++i) {
    *--der = (octet)(n & 0xff);
    h = n & 0x80;
  }
  if(h)
    *--der = 0;
  return i + (h >> 7);
}
static size_t derDec_size_t(octet const *der, size_t len) {
  size_t n = 0;
  for(; len--;)
    n = (n << 8) | (size_t)*der++;
  return n;
}

#define derLenTL(tag, value_len) \
  len += derLenT(tag) + derLenL(value_len)
#define derLenTLV(tag, value_len) \
  len += derLenT(tag) + derLenL(value_len) + value_len
#define derLenNULL() \
  derLenTL(derTagNULL, 0)
#define derLenOCT(octets_len) \
  derLenTLV(derTagOCT, octets_len)
#define derLenOID_der(oid_der_len) \
  len += oid_der_len
#define derLenOID(oid) \
  len += oidToDER(0, oid)
#define derLenINT(num) \
  derLenTLV(derTagINT, derLen_size_t(num))
#define derLenSEQ_end(seqEnd) \
  do { size_t seqEnd = len
#define derLenSEQ(seqEnd) \
  len += derLenT(derTagSEQ) + derLenL(len - seqEnd); } while(0)

#define derEncTL(tag, len) \
  do { \
    size_t _count; \
    _count = derLenL(len); \
    derEncodeL(p -= _count, len, _count); \
    _count = derLenT(tag); \
    derEncodeT(p -= _count, tag, _count); \
  } while(0)
#define derEncTLV(tag, len, value) \
  do { \
    memCopy(p -= len, value, len); \
    derEncTL(tag, len); \
  } while(0)
#define derEncNULL() \
  derEncTL(derTagNULL, 0)
#define derEncOCT(octets_len, octets) \
  derEncTLV(derTagOCT, octets_len, octets)
#define derEncOID(oid) \
  p -= oidToDER(0, oid); oidToDER(p, oid)
#define derEncINT(num) \
  do { \
    size_t _len = derEnc_size_t(p, num); \
    p -= _len; \
    derEncTL(derTagINT, _len); \
  } while(0)
#define derEncSEQ_end(seqEnd) \
  do { octet const *seqEnd = p
#define derEncSEQ(seqEnd) \
    do { \
      size_t _len = seqEnd - p; \
      derEncTL(derTagSEQ, _len); \
    } while(0); \
  } while(0)

#define derDecT_eq(tag) \
  do { \
    u32 _tag = 0; \
    size_t _count; \
    if(end == p) { e = ERR_BAD_LENGTH; goto err; } \
    _count = derDecodeT(&_tag, p, end-p); \
    if(_tag != tag) { e = ERR_BAD_FORMAT; goto err; } \
    ASSERT(p + _count <= end); \
    p += _count; \
  } while(0)
#define derDecL(len) \
  do { \
    size_t _count; \
    if(end == p) { e = ERR_BAD_LENGTH; goto err; } \
    _count = derDecodeL(&len, p, end-p); \
    ASSERT(p + _count <= end); \
    p += _count; \
    if(p + len > end) { e = ERR_BAD_LENGTH; goto err; } \
  } while(0)
#define derDecL_eq(len) \
  do { \
    size_t _len = 0; \
    derDecL(_len); \
    if(_len != len) { e = ERR_BAD_LENGTH; goto err; } \
  } while(0)
#define derDecNULL() \
  do { \
    derDecT_eq(derTagNULL); \
    derDecL_eq(0); \
  } while(0)
#define derDecSEQ(seq) \
  do { \
    octet const *seq = end; \
    do { \
      size_t _len = 0; \
      derDecT_eq(derTagSEQ); \
      derDecL(_len); \
      end = p + _len; \
    } while(0)
#define derDecSEQ_end(seq) \
    end = seq; \
  } while(0)
#define derDecINT(num) \
  do { \
    size_t _len = 0; \
    derDecT_eq(derTagINT); \
    derDecL(_len); \
    num = derDec_size_t(p, _len); \
    p += _len; \
  } while(0)
#define derDecINT_eq(num) \
  do { \
    size_t _num = 0; \
    derDecINT(_num); \
    if(num != _num) { e = ERR_BAD_FORMAT; goto err; } \
  } while(0)
#define derDecOCT(len, value) \
  do { \
    derDecT_eq(derTagOCT); \
    derDecL(len); \
    value = p; \
    p += len; \
  } while(0)
#define derDecOID(poid) \
  do { \
    octet const *_oid_der = p; \
    size_t _len = 0; \
    size_t _oid_size; \
    derDecT_eq(derTagOID); \
    derDecL(_len); \
    _oid_size = oidFromDER(0, _oid_der, (p - _oid_der) + _len); \
    if(_oid_size == SIZE_MAX) { e = ERR_BAD_OID; goto err; } \
    *poid = memAlloc(_oid_size); \
    if(!*poid) { e = ERR_OUTOFMEMORY; goto err; } \
    oidFromDER(*poid, _oid_der, (p - _oid_der) + _len); \
    p += _len; \
  } while(0)
#define derDecOID_eq(oid) \
  do { \
    size_t _len = 0; \
    derDecT_eq(derTagOID); \
    derDecL(_len); \
    if(!oidEqDER(p, _len, oid)) { e = ERR_BAD_OID; goto err; } \
    p += _len; \
  } while(0)

size_t pkcs8Size(
	size_t key_size,				/*!< [in] размер ключа */
	char const *oid_alg,		/*!< [in] OID алгоритма ключа */
	char const *oid_param		/*!< [in] OID параметров алгоритма ключа */
) {
  size_t len = 0;

  derLenSEQ_end(PrivateKeyInfo);
    derLenOCT(key_size);
    derLenSEQ_end(KeyAlgorithm);
      derLenOID(oid_param);
      derLenOID(oid_alg);
      derLenSEQ(KeyAlgorithm);
    derLenINT(0);
    derLenSEQ(PrivateKeyInfo);

  return len;
}

err_t pkcs8Wrap(
  size_t *pkcs8_size,			/*!< [out] размер выходного контейнера */
  octet **pkcs8,					/*!< [out] выходной контейнер PrivateKeyInfo */
	size_t key_size,				/*!< [in] размер ключа */
	const octet* key,				/*!< [in] ключ */
	char const *oid_alg,		/*!< [in] OID алгоритма ключа */
	char const *oid_param		/*!< [in] OID параметров алгоритма ключа */
) {
  size_t len;
  octet *p = NULL, *q = NULL;

  if(!pkcs8_size)
    return ERR_BAD_INPUT;

  len = pkcs8Size(key_size, oid_alg, oid_param);
  if(!pkcs8) {
    *pkcs8_size = len;
    return ERR_OK;
  }

  p = *pkcs8;
  if(!p) {
    p = memAlloc(len);
    if(!p)
      return ERR_OUTOFMEMORY;
    *pkcs8_size = len;
    *pkcs8 = p;
  } else if(*pkcs8_size != len)
    return ERR_BAD_INPUT;

  q = p; // for debug purposes only
  p += len;

  derEncSEQ_end(PrivateKeyInfo);
    derEncOCT(key_size, key);
    derEncSEQ_end(KeyAlgorithm);
      derEncOID(oid_param);
      derEncOID(oid_alg);
      derEncSEQ(KeyAlgorithm);
    derEncINT(0);
    derEncSEQ(PrivateKeyInfo);

  ASSERT(p == *pkcs8);
  return ERR_OK;
}

err_t pkcs8Unwrap(
  size_t *key_size,
  octet const **key,
  char **oid_alg,
  char **oid_param,
  size_t pkcs8_size,
  octet const *pkcs8
) {
  err_t e = ERR_OK;
  octet const *p = pkcs8, *end = p + pkcs8_size;

  derDecSEQ(PrivateKeyInfo);
    derDecINT_eq(0);
    derDecSEQ(KeyAlgorithm);
      derDecOID(oid_alg);
      derDecOID(oid_param);
      derDecSEQ_end(KeyAlgorithm);
    derDecOCT(*key_size, *key);
  derDecSEQ_end(PrivateKeyInfo);
  ASSERT(p == end);
  ASSERT(p == pkcs8 + pkcs8_size);

err:
  return e;
}

err_t pkcs8Unwrap2(
  size_t *key_size,
  octet const **key,
  char const *oid_alg,
  char const *oid_param,
  size_t pkcs8_size,
  octet const *pkcs8
) {
  err_t e = ERR_OK;
  octet const *p = pkcs8, *end = p + pkcs8_size;

  derDecSEQ(PrivateKeyInfo);
    derDecINT_eq(0);
    derDecSEQ(KeyAlgorithm);
      derDecOID_eq(oid_alg);
      derDecOID_eq(oid_param);
      derDecSEQ_end(KeyAlgorithm);
    derDecOCT(*key_size, *key);
  derDecSEQ_end(PrivateKeyInfo);
  ASSERT(p == end);
  ASSERT(p == pkcs8 + pkcs8_size);

err:
  return e;
}

size_t pkcs5Size(
	size_t pkcs8_size,				
	size_t iter_count
) {
  size_t len = 0;

  derLenSEQ_end(EncryptedPrivateKeyInfo);
    derLenOCT(pkcs8_size + 16);

    derLenSEQ_end(EncryptionAlgorithmIdentifier);
      derLenSEQ_end(PBES2_params);
        derLenSEQ_end(BeltKeywrapAlgorithmIdentifier);
          derLenNULL();
          derLenOID(oid_belt_kwp256);
          derLenSEQ(BeltKeywrapAlgorithmIdentifier);

        derLenSEQ_end(PBKDF2AlgorithmIdentifier);
          derLenSEQ_end(PBKDF2_params);
            derLenSEQ_end(PrfAlgorithmIdentifier);
              derLenNULL();
              derLenOID(oid_hmac_hbelt);
              derLenSEQ(PrfAlgorithmIdentifier);
            derLenINT(iter_count);
            derLenOCT(8);
            derLenSEQ(PBKDF2_params);

          derLenOID(oid_id_pbkdf2);
          derLenSEQ(PBKDF2AlgorithmIdentifier);
      
        derLenSEQ(PBES2_params);

      derLenOID(oid_id_pbes2);
      derLenSEQ(EncryptionAlgorithmIdentifier);

    derLenSEQ(EncryptedPrivateKeyInfo);

  return len;
}

err_t pkcs5Wrap(
	size_t *pkcs5_size,
	octet **pkcs5,			/*!< [out] общий ключ */
	size_t pkcs8_size,				
	const octet* pkcs8,				/*!< [in] долговременные параметры */
	size_t pwd_size,				
	const octet* pwd,				
	size_t salt_size,				
	const octet* salt,			
	size_t iter_count
) {
  err_t e = ERR_OK;
  size_t len = 0;
  octet *p = NULL, *q = NULL;
  octet key[32];
  octet header[16];

  if(!pkcs8_size || !pkcs8 || !pwd || !salt || salt_size != 8 || iter_count < 10000)
    return ERR_BAD_INPUT;

  len = pkcs5Size(pkcs8_size, iter_count);
  if(!pkcs5) {
    *pkcs5_size = len;
    return ERR_OK;
  }

  p = *pkcs5;
  if(!p) {
    p = memAlloc(len);
    if(!p)
      return ERR_OUTOFMEMORY;
    *pkcs5_size = len;
    *pkcs5 = p;
  } else if(*pkcs5_size != len)
    return ERR_BAD_INPUT;

  q = p; // for debug purposes only
  p += len;

  derEncSEQ_end(EncryptedPrivateKeyInfo);
    //derEncOCT(encData, len, epkcs8);
    e = beltPBKDF2(key, pwd, pwd_size, iter_count, salt, salt_size);
    ASSERT(e == ERR_OK);
    memSetZero(header, 16);
    e = beltKWPWrap(p -= (pkcs8_size + 16), pkcs8, pkcs8_size, header, key, 32);
    memSetZero(key, 32);
    ASSERT(e == ERR_OK);
    derEncTL(derTagOCT, pkcs8_size + 16);

    derEncSEQ_end(EncryptionAlgorithmIdentifier);
      derEncSEQ_end(PBES2_params);
        derEncSEQ_end(BeltKeywrapAlgorithmIdentifier);
          derEncNULL();
          derEncOID(oid_belt_kwp256);
          derEncSEQ(BeltKeywrapAlgorithmIdentifier);

        derEncSEQ_end(PBKDF2AlgorithmIdentifier);
          derEncSEQ_end(PBKDF2_params);
            derEncSEQ_end(PrfAlgorithmIdentifier);
              derEncNULL();
              derEncOID(oid_hmac_hbelt);
              derEncSEQ(PrfAlgorithmIdentifier);
            derEncINT(iter_count);
            derEncOCT(salt_size, salt);
            derEncSEQ(PBKDF2_params);

          derEncOID(oid_id_pbkdf2);
          derEncSEQ(PBKDF2AlgorithmIdentifier);
      
        derEncSEQ(PBES2_params);

      derEncOID(oid_id_pbes2);
      derEncSEQ(EncryptionAlgorithmIdentifier);

    derEncSEQ(EncryptedPrivateKeyInfo);

  ASSERT(p == *pkcs5);
  return ERR_OK;
}

err_t pkcs5Unwrap(
	size_t *pkcs8_size,
	octet **pkcs8,			/*!< [out] общий ключ */
	size_t pkcs5_size,				
	const octet* pkcs5,				/*!< [in] долговременные параметры */
	size_t pwd_size,				
	const octet* pwd				
) {
  err_t e = ERR_OK;
  size_t salt_size = 0;
  octet const *salt = NULL;
  size_t epkcs8_size = 0;
  octet const *epkcs8 = NULL;
  size_t iter_count = 0;
  octet const *p = NULL, *end = NULL;
  octet key[32];
  octet header[16];

  if(!pkcs8_size || !pkcs8 || !pkcs5 || !pwd)
    return ERR_BAD_INPUT;

  p = pkcs5;
  end = p + pkcs5_size;

  derDecSEQ(EncryptedPrivateKeyInfo);
    derDecSEQ(EncryptionAlgorithmIdentifier);
      derDecOID_eq(oid_id_pbes2);

      derDecSEQ(PBES2_params);
        derDecSEQ(PBKDF2AlgorithmIdentifier);
          derDecOID_eq(oid_id_pbkdf2);

          derDecSEQ(PBKDF2_params);
            derDecOCT(salt_size, salt);
            if(salt_size != 8) { e = ERR_BAD_FORMAT; goto err; }
            derDecINT(iter_count);
            if(iter_count < 10000) { e = ERR_BAD_FORMAT; goto err; }
            derDecSEQ(PrfAlgorithmIdentifier);
              derDecOID_eq(oid_hmac_hbelt);
              derDecNULL();
              derDecSEQ_end(PrfAlgorithmIdentifier);
            derDecSEQ_end(PBKDF2_params);
          derDecSEQ_end(PBKDF2AlgorithmIdentifier);
      
        derDecSEQ(BeltKeywrapAlgorithmIdentifier);
          derDecOID_eq(oid_belt_kwp256);
          derDecNULL();
          derDecSEQ_end(BeltKeywrapAlgorithmIdentifier);

        derDecSEQ_end(PBES2_params);
      derDecSEQ_end(EncryptionAlgorithmIdentifier);

    derDecOCT(epkcs8_size, epkcs8);
    if(epkcs8_size < 16) { e = ERR_BAD_FORMAT; goto err; }

    e = beltPBKDF2(key, pwd, pwd_size, iter_count, salt, salt_size);
    ASSERT(e == ERR_OK);
    memSetZero(header, 16);

    *pkcs8 = memAlloc(epkcs8_size - 16);
    if(!*pkcs8) { e = ERR_OUTOFMEMORY; goto err; }
    *pkcs8_size = epkcs8_size - 16;

    e = beltKWPUnwrap(*pkcs8, epkcs8, epkcs8_size, header, key, 32);
    memSetZero(key, 32);
    if(e != ERR_OK) { e = ERR_BAD_KEYTOKEN; goto err; }

  derDecSEQ_end(EncryptedPrivateKeyInfo);
  ASSERT(p == end);
  ASSERT(p == pkcs5 + pkcs5_size);

err:
  return e;
}