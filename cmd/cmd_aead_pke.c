#include "cmd.h"
#include "bee2/crypto/btok.h"
#include <bee2/crypto/bign.h>
#include <bee2/core/util.h>
#include <bee2/core/mem.h>
#include <bee2/core/der.h>
#include <bee2/core/rng.h>

/*
*******************************************************************************
Реализация ключевого материала PKE
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

static size_t keyloadPkeEncode(
    octet* der,
    const keyload_pke_t *keyload
){
    size_t count = 0;

    if (!der || !memIsValid(keyload, sizeof(keyload_pke_t)))
        return SIZE_MAX;

    derEncStep(derOCTEnc(der, keyload->ekey, 64 + 16 + CMD_AEAD_KEY_SIZE), der, count);
    derEncStep(derSIZEEnc(der, keyload->cert_len), der, count);
    if (keyload->cert_len)
        derEncStep(derOCTEnc(der, keyload->cert, keyload->cert_len), der, count);

    return count;
}

static size_t keyloadPkeDecode(
    const octet* der,
    keyload_pke_t *keyload,
    size_t count
){
    const octet * ptr = der;

    if (!der || !memIsValid(keyload, sizeof(keyload_pke_t)))
        return SIZE_MAX;

    derDecStep(derOCTDec2(keyload->ekey, ptr, count, 64 + 16 + CMD_AEAD_KEY_SIZE), ptr, count);
    derDecStep(derSIZEDec(&keyload->cert_len, ptr, count), ptr, count);
    if (keyload->cert_len)
        derDecStep(derOCTDec2(keyload->cert, ptr, count, keyload->cert_len), ptr, count);

    return ptr - der;
}

static err_t keyloadPkeWrap(
    keyload_pke_t *keyload,
    const keyload_pke_wrap_t *keyload_wrap,
    const octet key[CMD_AEAD_KEY_SIZE]
){
    bign_params params[1];
    err_t code;

    ASSERT(memIsValid(keyload, sizeof (keyload_pke_t)));
    ASSERT(memIsValid(keyload_wrap, sizeof (keyload_pke_wrap_t)));
    ASSERT(memIsValid(key, CMD_AEAD_KEY_SIZE));

    memSetZero(keyload, sizeof (keyload_pke_t));

    code = bignStdParams(params, curveOid(keyload_wrap->pubkey_len * 2));
    ERR_CALL_CHECK(code)

    keyload->cert_len = keyload_wrap->cert_len;
    memCopy(keyload->cert, keyload_wrap->cert, keyload->cert_len);

    if (!rngIsValid())
    {
        code = cmdRngStart(1);
        ERR_CALL_CHECK(code);
    }

    return bignKeyWrap(keyload->ekey, params, key, CMD_AEAD_KEY_SIZE,
                       0, keyload_wrap->pubkey, rngStepR, 0);
}

static err_t keyloadPkeUnwrap(
    const keyload_pke_t* keyload,
    const keyload_pke_unwrap_t* unwrap,
    octet key[CMD_AEAD_KEY_SIZE]
){
    err_t code;
    bign_params params[1];
    btok_cvc_t cvc;

    ASSERT(memIsValid(keyload, sizeof(keyload_pke_t)));
    ASSERT(memIsValid(unwrap, sizeof(keyload_pke_unwrap_t)));
    ASSERT(memIsValid(key, CMD_AEAD_KEY_SIZE));

    code = bignStdParams(params, curveOid(unwrap->privkey_len * 4));
    ERR_CALL_CHECK(code)

    //проверить, что открытый ключ в сертификате соответствует личному ключу получателя
    if (keyload->cert_len > 0){
        code = btokCVCUnwrap(&cvc, keyload->cert, keyload->cert_len, 0,0);
        ERR_CALL_CHECK(code)
        if (cvc.pubkey_len != unwrap->privkey_len*2)
            return ERR_BAD_CERT;
        code = bignValKeypair(params, unwrap->privkey, cvc.pubkey);
        ERR_CALL_CHECK(code)
    }

    return bignKeyUnwrap(key, params, keyload->ekey,
                         CMD_AEAD_KEY_SIZE + unwrap->privkey_len + 16,
                         0, unwrap->privkey);
}

static const cmd_keyload_t _KeyloadPKE = {
    CMD_KEYLOAD_TAG_PKE,
    (keyload_encode_i const) keyloadPkeEncode,
    (keyload_decode_i const) keyloadPkeDecode,
    (keyload_wrap_i const) keyloadPkeWrap,
    (keyload_unwrap_i const) keyloadPkeUnwrap
};

const cmd_keyload_t* cmdAeadKeyloadPKE(){
    return &_KeyloadPKE;
}
