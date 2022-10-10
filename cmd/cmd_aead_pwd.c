
#include "cmd.h"
#include <bee2/core/mem.h>
#include <bee2/core/der.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Реализация ключевого материала PWD
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

static size_t keyloadPwdEncode(
    octet* der,
    const keyload_pwd_t *keyload
){
    size_t count = 0;

    ASSERT(memIsValid(keyload, sizeof (keyload_pwd_t)));

    derEncStep(derOCTEnc(der,keyload->salt, sizeof (keyload->salt)), der, count);
    derEncStep(derSIZEEnc(der,keyload->iter), der, count);
    derEncStep(derOCTEnc(der,keyload->ekey, sizeof (keyload->ekey)), der, count);

    return count;
}

static size_t keyloadPwdDecode(
    const octet* der,
    keyload_pwd_t *keyload,
    size_t count
){
    const octet * ptr = der;

    ASSERT(memIsValid(keyload, sizeof (keyload_pwd_t)));
    ASSERT(der);

    derDecStep(derOCTDec2(keyload->salt, ptr, count, sizeof (keyload->salt)), ptr, count)
    derDecStep(derSIZEDec(&keyload->iter, ptr, count), ptr, count)
    derDecStep(derOCTDec2(keyload->ekey, ptr, count, sizeof (keyload->ekey)), ptr, count)

    return ptr - der;
}

static err_t keyloadPwdWrap(
    keyload_pwd_t *keyload,
    const keyload_pwd_wrap_t *keyload_wrap,
    const octet key[CMD_AEAD_KEY_SIZE]
){
    err_t code;
    octet pwd_key[32];

    ASSERT(memIsValid(keyload, sizeof (keyload_pwd_t)));
    ASSERT(memIsValid(keyload_wrap, sizeof (keyload_pwd_wrap_t)));
    ASSERT(memIsValid(key, CMD_AEAD_KEY_SIZE));

    memSetZero(keyload, sizeof (keyload_pwd_t));

    code = beltPBKDF2(pwd_key, keyload_wrap->pwd, keyload_wrap->pwd_len,
                      keyload_wrap->iter, keyload_wrap->salt, sizeof (keyload_wrap->salt));
    ERR_CALL_CHECK(code);

    keyload->iter = keyload_wrap->iter;
    ASSERT(sizeof (keyload_wrap->salt) == sizeof (keyload->salt));
    memCopy(keyload->salt, keyload_wrap->salt ,sizeof (keyload_wrap->salt));

    return beltKWPWrap(
        keyload->ekey,
        key, CMD_AEAD_KEY_SIZE,
        0,
        pwd_key, sizeof (pwd_key)
    );
}

static err_t keyloadPwdUnwrap(
    const keyload_pwd_t * keyload,
    const keyload_pwd_unwrap_t* keyload_unwrap,
    octet key[CMD_AEAD_KEY_SIZE]
){
    err_t code;
    octet pwd_key[32];

    ASSERT(memIsValid(keyload, sizeof (keyload_pwd_t)));
    ASSERT(memIsValid(keyload_unwrap, sizeof (keyload_pwd_unwrap_t)));
    ASSERT(memIsValid(key, CMD_AEAD_KEY_SIZE));

    code = beltPBKDF2(pwd_key, keyload_unwrap->pwd, keyload_unwrap->pwd_len,
                      keyload->iter, keyload->salt, sizeof (keyload->salt));
    ERR_CALL_CHECK(code);

    return beltKWPUnwrap(
        key,
        keyload->ekey, sizeof (keyload->ekey),
        0,
        pwd_key, sizeof (pwd_key)
    );
}

static const cmd_keyload_t _KeyloadPWD = {
    CMD_KEYLOAD_TAG_PWD,
    (keyload_encode_i const) keyloadPwdEncode,
    (keyload_decode_i const) keyloadPwdDecode,
    (keyload_wrap_i const) keyloadPwdWrap,
    (keyload_unwrap_i const) keyloadPwdUnwrap
};

const cmd_keyload_t* cmdAeadKeyloadPWD(){
    return &_KeyloadPWD;
}