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

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/pkcs5.h>

bool_t pkcs5Test()
{
  bool_t r = FALSE;
  err_t e;
  octet const key[32] = { 
    0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0,
    1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0, 0,
  };
  octet const salt[8] = { 11, 12, 13, 14, 15, 16, 17, 18, };
  octet const pwd[6] = { 21, 22, 23, 24, 25, 26, };

  size_t const iter_count = 10000;
  size_t pkcs8_size = 0;
  octet *pkcs8 = NULL;
  size_t pkcs5_size = 0;
  octet *pkcs5 = NULL;
  size_t depkcs8_size = 0;
  octet *depkcs8 = NULL;
  char *oid_alg = NULL;
  char *oid_param = NULL;
  size_t key_size = 0;
  octet const *pkey = NULL;

  do {
    e = pkcs8Wrap(&pkcs8_size, &pkcs8, sizeof(key), key, oid_bels_share, oid_bels_m0256v1);
    if(e != ERR_OK) break;
    e = pkcs5Wrap(&pkcs5_size, &pkcs5, pkcs8_size, pkcs8, sizeof(pwd), pwd, sizeof(salt), salt, iter_count);
    if(e != ERR_OK) break;

    e = pkcs5Unwrap(&depkcs8_size, &depkcs8, pkcs5_size, pkcs5, sizeof(pwd), pwd);
    if(e != ERR_OK) break;
    if(depkcs8_size != pkcs8_size) break;
    if(0 != memCmp(depkcs8, pkcs8, pkcs8_size)) break;

    pkey = NULL;
    key_size = 0;
    e = pkcs8Unwrap2(&key_size, &pkey, oid_bels_share, oid_bels_m0256v1, depkcs8_size, depkcs8);
    if(e != ERR_OK) break;
    if(key_size != sizeof(key)) break;
    if(0 != memCmp(key, pkey, key_size)) break;

    pkey = NULL;
    key_size = 0;
    e = pkcs8Unwrap(&key_size, &pkey, &oid_alg, &oid_param, depkcs8_size, depkcs8);
    if(e != ERR_OK) break;
    if(key_size != sizeof(key)) break;
    if(0 != memCmp(key, pkey, key_size)) break;
    if(0 != strCmp(oid_alg, oid_bels_share)) break;
    if(0 != strCmp(oid_param, oid_bels_m0256v1)) break;

    r = TRUE;
  } while(0);

  memFree(oid_alg);
  memFree(oid_param);
  memFree(depkcs8);
  memFree(pkcs5);
  memFree(pkcs8);

  return r;
}
