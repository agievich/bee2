/*
*******************************************************************************
\file pkcs5.h
\brief PKCS#5 EncryptedPrivateKeyInfo
\project bee2 [cryptographic library]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2021.04.03
\version 2021.04.03
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file pkcs5.h
\brief PKCS#5
*******************************************************************************
*/

#ifndef __BEE2_PKCS5_H
#define __BEE2_PKCS5_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"

/*!
*******************************************************************************
\file pkcs5.h

\section pkcs5-common PKCS#5: Общие положения

EncryptedPrivateKeyInfo. 

\expect{ERR_BAD_INPUT} Все входные указатели корректны.

\safe todo
*******************************************************************************
*/

static char const *oid_belt_kwp256			= "1.2.112.0.2.0.34.101.31.73";
static char const *oid_hmac_hbelt				= "1.2.112.0.2.0.34.101.47.12";
static char const *oid_bign_pubkey			= "1.2.112.0.2.0.34.101.45.2.1";
static char const *oid_bign_curve256v1 	= "1.2.112.0.2.0.34.101.45.3.1";
static char const *oid_bign_curve384v1	= "1.2.112.0.2.0.34.101.45.3.2";
static char const *oid_bign_curve512v1	= "1.2.112.0.2.0.34.101.45.3.3";
static char const *oid_bels_share				= "1.2.112.0.2.0.34.101.60.11";
static char const *oid_bels_m0128v1			= "1.2.112.0.2.0.34.101.60.2.1";
static char const *oid_bels_m0192v1			= "1.2.112.0.2.0.34.101.60.2.1";
static char const *oid_bels_m0256v1			= "1.2.112.0.2.0.34.101.60.2.1";
static char const *oid_id_pbkdf2				= "1.2.840.113549.1.5.12";
static char const *oid_id_pbes2					= "1.2.840.113549.1.5.13";

size_t pkcs8Size(
	size_t key_size,				/*!< [in] размер ключа */
	char const *oid_alg,		/*!< [in] OID алгоритма ключа */
	char const *oid_param		/*!< [in] OID параметров алгоритма ключа */
);

err_t pkcs8Wrap(
  size_t *pkcs8_size,			/*!< [out] размер выходного контейнера */
  octet **pkcs8,					/*!< [out] выходной контейнер PrivateKeyInfo */
	size_t key_size,				/*!< [in] размер ключа */
	const octet* key,				/*!< [in] ключ */
	char const *oid_alg,		/*!< [in] OID алгоритма ключа */
	char const *oid_param		/*!< [in] OID параметров алгоритма ключа */
);

err_t pkcs8Unwrap(
  size_t *key_size,
  octet const **key,
  char **oid_alg,
  char **oid_param,
  size_t pkcs8_size,
  octet const *pkcs8
);

err_t pkcs8Unwrap2(
  size_t *key_size,
  octet const **key,
  char const *oid_alg,
  char const *oid_param,
  size_t pkcs8_size,
  octet const *pkcs8
);

size_t pkcs5Size(
	size_t pkcs8_size,			/*!< [in] размер PrivateKeyInfo */
	size_t iter_count				/*!< [in] число итераций при построении ключа по паролю */
);

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
);

err_t pkcs5Unwrap(
	size_t *pkcs8_size,
	octet **pkcs8,			/*!< [out] общий ключ */
	size_t pkcs5_size,				
	const octet* pkcs5,				/*!< [in] долговременные параметры */
	size_t pwd_size,				
	const octet* pwd				
);

#if 0
err_t pkcs8Wrap(
  size_t *container_size,			/*!< [out] размер выходного контейнера */
  octet **container,					/*!< [out] выходной контейнер PrivateKeyInfo */
	size_t key_size,						/*!< [in] размер ключа */
	const octet* key,						/*!< [in] ключ */
	size_t alg_size,						/*!< [in] размер DER-представления OID'а алгоритма ключа */
	const octet* alg_oid_der,		/*!< [in] DER-представление OID'а алгоритма ключа */
	size_t param_size,					/*!< [in] размер DER-представления OID'а параметров алгоритма ключа */
	const octet* param_oid_der	/*!< [in] DER-представление OID'а параметров алгоритма ключа */
);

/*!	\brief Построение общего ключа протокола MTI

	При долговременных параметрах params по личному ключу 
	[O_OF_B(r)]privkey, одноразовому личному ключу [O_OF_B(r)]privkey1,
	открытому ключу [O_OF_B(l)]pubkey противоположной стороны 
	и одноразовому открытому ключу [O_OF_B(l)]pubkey противоположной стороны 
	строится общий ключ [O_OF_B(n)]sharekey. Общий ключ 
	определяется как n битов числа
	\code
		pubkey1^(privkey) \xor pubkey^(privkey1).
	\endcode
	что соответствует протоколу Диффи -- Хеллмана.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_PUBKEY} Открытый ключ pubkey корректен.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\return ERR_OK, если общий ключ успешно построен, и код ошибки
	в противном случае.
	\remark Функция поддерживает протокол с аутентификацией сторон (4.2)
	при следующих соглашениях:
	\code
		privkey = xa, privkey1 = ua, pubkey = yb, pubkey1 = vb || 
		privkey = xb, privkey1 = ub, pubkey = ya, pubkey1 = va. 
	\endcode
	\remark Протокол 4.2 построен по схеме MTI (Matsumoto, Takashima, Imai),
	чем и объясняется название функции.
*/
err_t pkcs5Wrap(
  size_t *container_size,	/*!< [out] размер EncryptedPrivateKeyInfo */
	octet **container,			/*!< [out] EncryptedPrivateKeyInfo */
  size_t key_size,				/*!< [in] размер ключа */
	const octet* key,				/*!< [in] ключ */
  size_t pwd_size,				/*!< [in] размер пароля */
  const octet* pwd,				/*!< [in] пароль */
  size_t salt_size,				/*!< [in] размер синхропосылки */
  const octet* salt,			/*!< [in] синхропосылка */
  size_t iter_count				/*!< [in] число итераций */
);

err_t pkcs5Unwrap(
  size_t *key_size,				
	octet** key,						/*!< [in] долговременные параметры */
  size_t container_size,	
	const octet *container,	/*!< [out] общий ключ */
  size_t pwd_size,				
  const octet* pwd				
);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_PKCS5_H */
