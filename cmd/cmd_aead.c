#include <stdio.h>
#include "cmd.h"
#include "bee2/crypto/belt.h"
#include <bee2/defs.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bake.h>
#include <bee2/core/mem.h>
#include <bee2/core/der.h>
#include <bee2/core/rng.h>

// Размер блока шифрования, должен быть степенью двойки
#define BLOCK_SIZE 4096

/*
*******************************************************************************
Сборка/разбор ключевого материала
*******************************************************************************
*/
err_t cmdAeadWrapKey(
    octet *keload,
    const cmd_keyload_t* keyload_type,
    const void *keyload_wrap,
    const octet key[CMD_AEAD_KEY_SIZE]
) {
    ASSERT(memIsValid(keyload_type, sizeof (cmd_keyload_t)));
    return keyload_type->wrap(keload, keyload_wrap, key);
}

err_t cmdAeadUnwrapKey(
    const octet* keyload,
    const cmd_keyload_t* keyload_type,
    const void* keyload_unwrap,
    octet key[CMD_AEAD_KEY_SIZE]
){
    ASSERT(memIsValid(keyload_type, sizeof (cmd_keyload_t)));
    return keyload_type->unwrap(keyload, keyload_unwrap, key);
}


/*
*******************************************************************************
Кодирование заголовка

  SEQ[APPLICATION 78] Header
    SEQ[KEYLOAD_TAG] -- keyload
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

static size_t derKldEnc(
    octet* der,
    const octet *keyload,
    const cmd_keyload_t* keyload_type
){
    der_anchor_t Keyload[1];
    size_t count = 0;

    ASSERT(memIsValid(keyload_type, sizeof (cmd_keyload_t)));

    derEncStep(derTSEQEncStart(Keyload, der, count, keyload_type->tag), der, count);
    derEncStep(keyload_type->encode(der, keyload), der, count);
    derEncStep(derTSEQEncStop(der,count, Keyload),der, count);

    return count;
}

static size_t derKldDec(
    octet *keyload,
    const cmd_keyload_t* keyload_type,
    const octet* der,
    size_t count
){
    der_anchor_t Keyload[1];
    const octet * ptr = der;

    ASSERT(memIsValid(keyload_type, sizeof (cmd_keyload_t)));

    derDecStep(derTSEQDecStart(Keyload, ptr, count, keyload_type->tag), ptr, count);
    derDecStep(keyload_type->decode(ptr, keyload, count), ptr, count)
    derDecStep(derTSEQDecStop(ptr, Keyload), ptr, count);

    return ptr - der;
}


/*! \brief Кодирование заголовка

    \return размер DER-кода, если заголовок закодирован успешно, и
    SIZE_MAX в обратном случае
 */
static size_t aeadEncode(
    octet* der,                           /*!< [out] DER-код */
    const cmd_keyload_t* keyload_type,    /*!< [in] тип ключевого материала */
    const cmd_aeadhead_t* header             /*!< [in]  заголовок */
) {

    der_anchor_t Header[1];
    size_t count = 0;

    ASSERT(memIsValid(keyload_type, sizeof (cmd_keyload_t)));

    if (!der || !memIsValid(header, sizeof(cmd_aeadhead_t)))
        return SIZE_MAX;

    derEncStep(derTSEQEncStart(Header, der, count, 0x7F4E), der, count);
    derEncStep(derKldEnc(der, header->keyload, keyload_type), der, count);
    derEncStep(derOCTEnc(der, header->iv, 16), der, count);
    derEncStep(derSIZEEnc(der, header->itag), der, count);
    derEncStep(derTSEQEncStop(der, count, Header), der, count);

    return count;
}

/*! \brief Декодирование заголовка

    \return реальный размер DER-кода, если заголовок декодирован успешно, и
    SIZE_MAX в обратном случае
 */
static size_t aeadDecode(
    const octet *der,                      /*!< [in]  DER-код */
    size_t count,                          /*!< [in]  макисальная длина DER-кода */
    const cmd_keyload_t* keyload_type,     /*!< [in]  тип ключевого материала */
    cmd_aeadhead_t* header                 /*!< [out] заголовок */
){
    der_anchor_t Header[1];
    const octet * ptr = der;
//    cmd_keyload_t* kld;

    ASSERT(memIsValid(keyload_type, sizeof (cmd_keyload_t)));

    if (!der || !memIsValid(header, sizeof(cmd_aeadhead_t)))
        return SIZE_MAX;

    memSetZero(header, sizeof (cmd_keyload_t));

    derDecStep(derTSEQDecStart(Header, ptr, count, 0x7F4E), ptr, count);
    derDecStep(derKldDec(header->keyload, keyload_type, ptr, count), ptr, count);
    derDecStep(derOCTDec2(header->iv, ptr, count, 16), ptr, count);
    derDecStep(derSIZEDec(&header->itag, ptr, count), ptr, count);
    derDecStep(derTSEQDecStop(ptr, Header), ptr, count);

    return ptr - der;
}

static const char* curveOid(size_t l)
{
    switch (l)
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
err_t cmdAeadHeaderRead(
    size_t* der_len,
    octet* der,
    cmd_aeadhead_t* header,
    const cmd_keyload_t* keyload_type,
    const char* file_name
){
    octet mDer[AEAD_HEAD_MAX_DER];
    size_t count;
    cmd_aeadhead_t m_header[1];
    memSetZero(m_header, sizeof (cmd_aeadhead_t));

    count = cmdFileRead2(mDer, sizeof (mDer), file_name);

    if (count == SIZE_MAX)
        return ERR_FILE_READ;

    count = aeadDecode(mDer, count, keyload_type, m_header);

    if (count == SIZE_MAX)
        return ERR_BAD_FILE;

    if (memIsValid(der_len, sizeof (size_t)))
        *der_len = count;

    if (memIsValid(der, count))
        memCopy(der, mDer, count);

    if (memIsValid(header, sizeof (cmd_aeadhead_t)))
        memCopy(header, m_header, sizeof (cmd_aeadhead_t));

    return ERR_OK;
}

err_t cmdAeadHeaderWrite(
    size_t* der_len,
    octet* der,
    const cmd_aeadhead_t* header,
    const cmd_keyload_t* keyload_type,
    const char* file_name
) {
    octet mDer[AEAD_HEAD_MAX_DER];
    size_t count;

    count = aeadEncode(mDer, keyload_type, header);

    if (count == SIZE_MAX)
        return ERR_BAD_PARAMS;

    if (memIsValid(der_len, sizeof (size_t)))
        *der_len = count;

    if (memIsValid(der, count))
        memCopy(der, mDer, count);

    return cmdFileWrite(mDer, count, file_name);
}

static err_t aeadGen(octet* key, size_t size)
{
    err_t code;
    if (!rngIsValid())
    {
        code = cmdRngStart(1);
        ERR_CALL_CHECK(code);
    }
    rngStepR(key, size, 0);

    return ERR_OK;
}

static err_t aeadProtectAdata(const char* adata, octet* state) {

    FILE *fp;
    octet buf[BLOCK_SIZE];
    size_t count;

    ASSERT(adata);

    fp = fopen(adata, "rb");
    if (!fp) {
        return ERR_FILE_OPEN;
    }

    while (TRUE) {

        count = fread(buf, 1, BLOCK_SIZE, fp);
        if (count == 0) {
            if (ferror(fp))
                return ERR_FILE_READ;
            break;
        }
        beltCHEStepI(&buf, count, state);
    }
    fclose(fp);
    return ERR_OK;
}

err_t cmdAeadEncrypt(
    const char* file,
    const char* encrypted_file,
    size_t itag,
    const cmd_keyload_t* keyload_type,
    const void* wrap_params,
    const char* adata
) {
    err_t code;
    octet key[32];
    octet *state = NULL;
    size_t count;
    octet buf[BLOCK_SIZE];
    octet mac[8];
    FILE *fp = NULL;
    FILE *enc_fp = NULL;
    cmd_aeadhead_t header;
    size_t file_size;
    size_t total_read = 0;
    size_t der_len;
    octet der[AEAD_HEAD_MAX_DER];

    file_size = cmdFileSize(file);

    if (file_size == SIZE_MAX)
        return ERR_FILE_READ;

    header.itag = itag;

    //сгенерировать сеансовый ключ
    code = aeadGen(key, sizeof(key));
    ERR_CALL_CHECK(code)

    //сгенерировать синхропосылку
    code = aeadGen(header.iv, sizeof(header.iv));
    ERR_CALL_CHECK(code)

    //защитить ключ
    code = cmdAeadWrapKey(header.keyload, keyload_type, wrap_params, key);
    ERR_CALL_CHECK(code)

    //записать заголовок
    code = cmdAeadHeaderWrite(&der_len, der, &header, keyload_type, encrypted_file);

    ERR_CALL_CHECK(code)
    
    //открыть шифруемый файл
    fp = fopen(file, "rb");
    if (!fp)
    {
        return ERR_FILE_NOT_FOUND;
    }

    //открыть файл для записи зашифрованных данных
    enc_fp = fopen(encrypted_file, "ab");
    if (!enc_fp)
    {
        code = ERR_FILE_WRITE;
        goto final;
    }

    //создать сотсояние
    state = blobCreate(beltCHE_keep());
    if (!state)
    {
        code = ERR_OUTOFMEMORY;
        goto final;
    }

    //инициализировать алгоритм
    beltCHEStart(state, key, sizeof(key), header.iv);

    //имитозащита заголовка
    if (der_len > 0)
        beltCHEStepI(&der, der_len, state);

    // имитозащита дополнительных данных
    if (adata)
    {
        code = aeadProtectAdata(adata, state);
        if (code != ERR_OK)
            goto final;
    }

    while (total_read < file_size)
    {
        // прочитать блок
        count = fread(buf, 1, BLOCK_SIZE, fp);
        total_read += count;

        if (count == 0)
        {
            if (ferror(fp))
            {
                code = ERR_FILE_READ;
                goto final;
            }
            break;
        }

        // зашифровать блок
        beltCHEStepE(buf, count, state);
        // выполнить имитозащиту блока
        beltCHEStepA(buf, count, state);

        //записать зашифрованный фрагмент
        if (fwrite(buf, 1, count, enc_fp) != count)
        {
            code = ERR_OUTOFMEMORY;
            goto final;
        }

        //посчитать и записать промежуточную имитовставку, если нужно
        if (itag && total_read != file_size && total_read % (1024 * 1024 * itag) == 0)
        {
            beltCHEStepG(mac, state);
            if (fwrite(mac, 1, sizeof(mac), enc_fp) != sizeof(mac))
            {
                code = ERR_OUTOFMEMORY;
                goto final;
            }
        }
    }

    //посчитать конечную имитовставку
    beltCHEStepG(mac, state);

    //записать конечную имитовставку
    code = fwrite(mac, 1, sizeof(mac), enc_fp) == sizeof(mac)
           ? ERR_OK : ERR_OUTOFMEMORY;

    //завершить
    final:
    fclose(fp);
    fclose(enc_fp);
    blobClose(state);
    return code;
}

err_t cmdAeadDecrypt(
    const char* file,
    const char* decrypted_file,
    const cmd_keyload_t* keyload_type,
    const void* unwrap_params,
    const char* adata
){
    err_t  code;
    octet key[CMD_AEAD_KEY_SIZE];
    size_t header_len;
    cmd_aeadhead_t header[1];
    FILE *fp = NULL;
    FILE *dec_fp = NULL;
    octet *state = NULL;
    octet buf[BLOCK_SIZE];
    size_t count;
    octet mac[8];
    size_t file_size;
    size_t total_read = 0;
    size_t total_read_without_itag = 0;
    octet der[AEAD_HEAD_MAX_DER];

    //прочитать заголовок
    code = cmdAeadHeaderRead(&header_len, der, header, keyload_type, file);
    ERR_CALL_CHECK(code)

    // разобрать сеансовый ключ
    code = cmdAeadUnwrapKey(header->keyload, keyload_type, unwrap_params, key);
    ERR_CALL_CHECK(code)

    // определить размер файла
    file_size = cmdFileSize(file) ;

    if (file_size == SIZE_MAX)
        return ERR_FILE_READ;

    file_size = file_size- header_len - sizeof (mac);

    // открыть шифруемый файл
    fp = fopen((const char *) file, "rb");
    if (!fp)
        return ERR_FILE_NOT_FOUND;

    fseek(fp, (long) header_len, SEEK_SET);

    // открыть файл для записи зашифрованных данных
    dec_fp = fopen(decrypted_file, "wb");
    if (!dec_fp)
        return ERR_FILE_CREATE;

    // создать состояние
    state = blobCreate(beltCHE_keep());
    if (!state)
    {
        code = ERR_OUTOFMEMORY;
        goto final;
    }

    // инициализировать beltCHE
    beltCHEStart(state, key, sizeof (key), header->iv);

    // проверка заголовка
    if (header_len > 0)
        beltCHEStepI(&der, header_len, state);

    // проверка дополнительных данных
    if (adata)
    {
        code = aeadProtectAdata(adata, state);
        if (code != ERR_OK)
            goto final;
    }

    while (total_read < file_size)
    {
        // прочитать блок
        count = fread(buf, 1, MIN2(BLOCK_SIZE, file_size-total_read), fp);
        total_read += count;
        total_read_without_itag+=count;
        if (count == 0)
        {
            if (ferror(fp))
            {
                code =  ERR_FILE_READ;
                goto final;
            }
            break;
        }

        // расшифровать блок блок
        beltCHEStepA(buf, count, state);
        // выполнить имитозащиту блока
        beltCHEStepD(buf, count, state);

        //проверить промежуточную имитовставку, если нужно
        if (header->itag &&
            total_read_without_itag != file_size &&
            total_read_without_itag % (1024 * 1024 * header->itag) == 0
        ){
            if (fread(mac,1,sizeof (mac), fp) != sizeof (mac) ||
                !beltCHEStepV(mac,state))
            {
                code = ERR_BAD_FILE;
                goto final;
            }
            total_read+=sizeof (mac);
        }

        // записать расшифрованный фрагмент
        if (fwrite(buf, 1, count, dec_fp) != count)
        {
            code = ERR_OUTOFMEMORY;
            goto final;
        }
    }

    //прочитать финальную имитовставку
    if (fread(mac,1,sizeof (mac), fp) != sizeof (mac))
    {
        code = ERR_BAD_FILE;
        goto final;
    }

    // проверить финальную имитовставку
    code = beltCHEStepV(mac, state) ? ERR_OK : ERR_BAD_FILE;

    final:
    fclose(fp);
    fclose(dec_fp);
    blobClose(state);

    return code;
}

