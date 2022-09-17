#include <stdio.h>
#include "cmd.h"
#include <bee2/defs.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bake.h>
#include <bee2/core/mem.h>
#include <bee2/core/der.h>
#include <bee2/core/rng.h>

#define PKE_HEAD_MAX_DER sizeof(cmd_pkehead_t) + 128

/*!	\brief Кодирование ключевого материала

    \return длина DER-кода или SIZE_MAX в случае ошибки
 */
typedef size_t (*keyload_encode_i)(
        octet* der,                         /*!< [out] DER-код */
        const octet *keload                 /*!< [in]  ключевой материал */
);

/*!	\brief Декодирование ключевого материала

    \return реальная длина DER-кода или SIZE_MAX в случае ошибки
 */
typedef size_t (*keyload_decode_i)(
        octet *keload,                      /*!< [out]  ключевой материал */
        const octet* der,                  /*!< [in]   DER-код */
        size_t count                       /*!< [out]  максимальная длина DER-кода */
);

/*!	\brief Функция сборки ключевого материала

    \return ERR_OK в случае успеха и код ошибки в противном случае
*/
typedef err_t (*keyload_wrap_i)(
        octet *keload,                      /*!< [out] ключевой материал */
        octet *keyload_wrap,                /*!< [in/out] параметры для сборки */
        const octet key[CMD_PKE_KEY_SIZE]   /*!< [in] сеансовый ключ */
);

/*!	\brief Функция разбора ключевого материала

    return ERR_OK в случае успеха и код ошибки в противном случае
*/
typedef err_t (*keyload_unwrap_i)(
        const octet* keyload,               /*!< [in] ключевой материал */
        octet* keyload_unwrap,              /*!< [in/out] параметры для разбора */
        octet key[CMD_PKE_KEY_SIZE]         /*!< [out] сеансовый ключ */
);

/*!	\brief Тип ключевого материала */
typedef const struct {
    const cmd_keyload_id id;                /*!< идентификатор */
    const keyload_encode_i encode;          /*!< функция кодирования*/
    const keyload_decode_i decode;          /*!< функция декодирования */
    const keyload_wrap_i wrap;              /*!< функция сборки */
    const keyload_unwrap_i unwrap;          /*!< функция разбора */
} cmd_keyload_t;

/*
*******************************************************************************
Определение ключевого материала PKE
*******************************************************************************
*/

/*!	\brief Кодирование ключевого материала PKE

    \return длина DER-кода или SIZE_MAX в случае ошибки
 */
static size_t keyloadPkeEncode(
    octet* der,                         /*!< [out] DER-код */
    const keyload_pke_t *keyload        /*!< [in]  ключевой материал */
);

/*!	\brief Декодирование ключевого материала PKE

    \return реальная длина DER-кода или SIZE_MAX в случае ошибки
 */
static size_t keyloadPkeDecode(
        keyload_pke_t *keyload,          /*!< [out]  ключевой материал */
        const octet* der,                /*!< [in]   DER-код */
        size_t count                     /*!< [out]  максимальная длина DER-кода */
);

/*! \brief Сборка ключевого материала PKE

    \return ERR_OK, если ключевой материал собран успешно, и
    код ошибки в обратном случае
 */
static err_t keyloadPkeWrap(
        keyload_pke_t *keyload,              /*!< [out] ключевой материал */
        keyload_pke_wrap_t *keyload_wrap,    /*!< [in/out] параметры для сборки */
        const octet key[CMD_PKE_KEY_SIZE]    /*!< [in] сеансовый ключ */
);

/*! \brief Разбор ключевого материала PKE

    \return ERR_OK, если ключевой материал разобран успешно, и
    код ошибки в обратном случае
 */
static err_t keyloadPkeUnwrap(
        const keyload_pke_t* keyload,       /*!< [in] ключевой материал */
        keyload_pke_unwrap_t* unwrap,       /*!< [in/out] параметры для разбора */
        octet key[CMD_PKE_KEY_SIZE]         /*!< [out] сеансовый ключ */
);

/*! \brief Тип ключевого материала PKE
 */
static const cmd_keyload_t _KeyloadPKE = {
        CMD_KEYLOAD_ID_PKE,
        (keyload_encode_i const) keyloadPkeEncode,
        (keyload_decode_i const) keyloadPkeDecode,
        (keyload_wrap_i const) keyloadPkeWrap,
        (keyload_unwrap_i const) keyloadPkeUnwrap
};

/*
*******************************************************************************
Список доступных типов ключевых материалов
*******************************************************************************
*/

/*! \brief Доступные типы ключевых материалов
 */
static const cmd_keyload_t* _keyloads[] = {
        &_KeyloadPKE
};

/*! \brief Получить тип ключевого материала по идентификатору
 *
 * \return тип в случае успеха и NULL, если тип не найден
 */
static cmd_keyload_t * keyloadForId(cmd_keyload_id id){
    for(size_t i = 0; i< sizeof (_keyloads) / sizeof (cmd_keyload_t*); i++)
        if (_keyloads[i]->id == id)
            return _keyloads[i];

    return 0;
}

/*
*******************************************************************************
Сборка/разбор ключевого материала
*******************************************************************************
*/
err_t cmdPkeWrapKey(
        octet *keload,
        const cmd_keyload_id keyload_id,
        octet *keyload_wrap,
        const octet key[CMD_PKE_KEY_SIZE]
) {

    cmd_keyload_t * kld;
    if (!(kld = keyloadForId(keyload_id)))
        return ERR_BAD_OID;

    return kld->wrap(keload, keyload_wrap, key);
}

err_t cmdPkeUnwrapKey(
        const octet* keyload,
        cmd_keyload_id keyload_id,
        octet* keyload_unwrap,
        octet key[CMD_PKE_KEY_SIZE]
){

    cmd_keyload_t * kld;
    if (!(kld = keyloadForId(keyload_id)))
        return ERR_BAD_OID;

    return kld->unwrap(keyload, keyload_unwrap, key);
}


/*
*******************************************************************************
Кодирование заголовка

  SEQ[APPLICATION 78] Header
    OCT(SIZE(1)) -- keyload_id
    SEQ -- keyload
    OCT(SIZE(16)) -- iv
    SIZE -- itag
*******************************************************************************
*/

#define derEncStep(step, ptr, count)\
{\
	size_t t = step;\
	ASSERT(t != SIZE_MAX);\
	ptr = ptr ? ptr + t : 0;\
	count += t;\
}\

#define derDecStep(step, ptr, count)\
{\
	size_t t = step;\
	if (t == SIZE_MAX)\
		return SIZE_MAX;\
	ptr += t, count -= t;\
}\

/*! \brief Кодирование заголовка

    \return размер DER-кода, если заголовок закодирован успешно, и
    SIZE_MAX в обратном случае
 */
static size_t pkeEncode(
        octet* der,                  /*!< [out] DER-код */
        const cmd_pkehead_t* pke     /*!< [in]  заголовок */
) {

    der_anchor_t Header[1];
    size_t count = 0;
    cmd_keyload_t * kld;

    if (!der || !memIsValid(pke, sizeof(cmd_pkehead_t)))
        return SIZE_MAX;

    derEncStep(derTSEQEncStart(Header, der, count, 0x7F4E), der, count);
    derEncStep(derOCTEnc(der, &pke->keyload_id, sizeof (cmd_keyload_id) / sizeof (octet)), der, count);

    if (!(kld = keyloadForId(pke->keyload_id)))
        return SIZE_MAX;

    derEncStep(kld->encode(der, pke->keyload), der, count)
    derEncStep(derOCTEnc(der,pke->iv, 16), der, count);
    derEncStep(derSIZEEnc(der, pke->itag), der, count);
    derEncStep(derTSEQEncStop(der, count, Header), der, count);

    return count;
}

/*! \brief Декодирование заголовка

    \return реальный размер DER-кода, если заголовок декодирован успешно, и
    SIZE_MAX в обратном случае
 */
static size_t pkeDecode(
        const octet *der,            /*!< [in]  DER-код */
        size_t count,                /*!< [in]  макисальная длина DER-кода */
        cmd_pkehead_t* pke           /*!< [out] заголовок */
){
    der_anchor_t PKE[1];
    const octet * ptr = der;
    cmd_keyload_t * kld;

    if (!der || !memIsValid(pke, sizeof(cmd_pkehead_t)))
        return SIZE_MAX;

    derDecStep(derTSEQDecStart(PKE, ptr, count, 0x7F4E), ptr, count);
    derDecStep(derOCTDec2(&pke->keyload_id, ptr, count, sizeof (cmd_keyload_id)/ sizeof (octet)), ptr, count);

    if (!(kld = keyloadForId(pke->keyload_id)))
        return SIZE_MAX;

    derDecStep(kld->decode(pke->keyload, ptr, count), ptr, count)
    derDecStep(derOCTDec2(pke->iv, ptr, count, 16), ptr, count);
    derDecStep(derSIZEDec(&pke->itag, ptr, count), ptr, count);
    derDecStep(derTSEQDecStop(ptr, PKE), ptr, count);

    return ptr - der;
}

static const char* curveOid(size_t hid)
{
    switch (hid)
    {
        case 128:
            return "1.2.112.0.2.0.34.101.45.3.1";
        case 192:
            return "1.2.112.0.2.0.34.101.45.3.2";
        case 256:
            return "1.2.112.0.2.0.34.101.45.3.3";
        default:
            return NULL;
    }
}

/*
*******************************************************************************
Чтение/запись заголовка зашифрованного файла
 *******************************************************************************
*/
err_t cmdPkeHeaderRead(
        size_t* der_len,
        cmd_pkehead_t* pke,
        const char* file_name
){
    octet der[PKE_HEAD_MAX_DER];
    size_t count;
    cmd_pkehead_t m_pke[1];

    count = cmdFileRead2(der, sizeof (der), file_name);

    if (count == SIZE_MAX)
        return ERR_FILE_READ;

    count = pkeDecode(der, count, m_pke);

    if (count == SIZE_MAX) {
        return ERR_BAD_FILE;
    }

    if (memIsValid(der_len, sizeof (size_t)))
        *der_len = count;

    if (memIsValid(pke, sizeof (cmd_pkehead_t)))
        memCopy(pke, m_pke, sizeof (cmd_pkehead_t));

    return ERR_OK;
}

err_t cmdPkeHeaderWrite(
        size_t* der_len,
        const cmd_pkehead_t* pke,
        const char* file_name
) {
    FILE *fp;
    octet der[PKE_HEAD_MAX_DER];
    size_t count;

    count = pkeEncode(der, pke);

    if (count == SIZE_MAX)
        return ERR_BAD_PARAMS;

    if (memIsValid(der_len, sizeof (size_t)))
        *der_len = count;

    return cmdFileWrite(der, count, file_name);
}

/*
*******************************************************************************
Реализация ключевого материала PKE
*******************************************************************************
*/

static size_t keyloadPkeEncode(
        octet* der,
        const keyload_pke_t *keyload
){
    der_anchor_t Keyload[1];
    size_t count = 0;

    if (!der || !memIsValid(keyload, sizeof(keyload_pke_t)))
        return SIZE_MAX;

    derEncStep(derSEQEncStart(Keyload, der, count), der, count);
    derEncStep(derOCTEnc(der, keyload->key, sizeof (keyload->key)), der, count);
    derEncStep(derSIZEEnc(der, keyload->cert_len), der, count);
    if (keyload->cert_len) {
        derEncStep(derOCTEnc(der, keyload->cert, keyload->cert_len), der, count);
    }
    derEncStep(derSEQEncStop(der, count, Keyload), der, count);

    return count;
}

static size_t keyloadPkeDecode(
        keyload_pke_t *keyload,
        const octet* der,
        size_t count
){
    der_anchor_t Keyload[1];
    const octet * ptr = der;

    if (!der || !memIsValid(keyload, sizeof(keyload_pke_t)))
        return SIZE_MAX;

    derDecStep(derSEQDecStart(Keyload, ptr, count), ptr, count);
    derDecStep(derOCTDec2(keyload->key, ptr, count, sizeof (keyload->key)), ptr, count);
    derDecStep(derSIZEDec(&keyload->cert_len, ptr, count), ptr, count);
    if (keyload->cert_len) {
        derDecStep(derOCTDec2(keyload->cert, ptr, count, keyload->cert_len), ptr, count);
    }
    derDecStep(derTSEQDecStop(ptr, Keyload), ptr, count);

    return ptr - der;
}

static err_t keyloadPkeWrap(
        keyload_pke_t *keyload,
        keyload_pke_wrap_t *keyload_wrap,
        const octet key[CMD_PKE_KEY_SIZE]
){
    bign_params params[1];
    err_t code;

    ASSERT(memIsValid(keyload, sizeof (keyload_pke_t)));
    ASSERT(memIsValid(keyload_wrap, sizeof (keyload_pke_wrap_t)));

    if (!rngIsValid()){
        ERR_CALL_CHECK(cmdRngStart(1));
        // ERR_CALL_CHECK(cmdRngTest())
    }
    code = bignStdParams(params, curveOid(keyload_wrap->pubkey_len * 2));
    ERR_CALL_CHECK(code)

    keyload->cert_len = keyload_wrap->cert_len;
    memCopy(keyload->cert, keyload_wrap->cert, keyload->cert_len);

    return bignKeyWrap(keyload->key, params, key, CMD_PKE_KEY_SIZE,
                       0, keyload_wrap->pubkey, rngStepR, 0);
}

static err_t keyloadPkeUnwrap(
        const keyload_pke_t* keyload,
        keyload_pke_unwrap_t* unwrap,
        octet key[CMD_PKE_KEY_SIZE]
){
    err_t code;
    bign_params params[1];

    ASSERT(memIsValid(keyload, sizeof(keyload_pke_t)));
    ASSERT(memIsValid(unwrap, sizeof(keyload_pke_unwrap_t)));

    code = bignStdParams(params, curveOid(unwrap->privkey_len * 4));
    ERR_CALL_CHECK(code)

    unwrap->cert_len = keyload->cert_len;
    memCopy(unwrap->cert, keyload->cert, keyload->cert_len);

    return bignKeyUnwrap(key, params, keyload->key,
                         CMD_PKE_KEY_SIZE + unwrap->privkey_len + 16,
                         0, unwrap->privkey);
}