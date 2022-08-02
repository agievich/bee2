#include <stdio.h>
#include <bee2/core/err.h>
#include <bee2/core/der.h>
#include <bee2/core/blob.h>
#include <bee2/core/util.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/tm.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/btok.h>
#include "cmd.h"


extern err_t cmdCVCRead(octet cert[], size_t* cert_len, const char* file);

/*
*******************************************************************************
Кодирование подписи

  SEQ[APPLICATION 78] Signature
    SIZE[APPLICATION 41] -- sig_len
    OCT(SIZE(96)) -- sig
    OCT(SIZE(sizeof(size_t) * SIG_MAX_CERT)) - cert_len
    OCT - certs
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


static size_t sigEnc(
        octet buf[],
        cmd_sig_t* sig,
        const octet certs[]
){

    der_anchor_t Signature[1];
    der_anchor_t Certs[1];
    size_t certs_total_len = 0;
    size_t count = 0;

    if (!memIsValid(sig, sizeof(cmd_sig_t)))
        return SIZE_MAX;

    for (size_t i =0 ; i < SIG_MAX_CERTS && sig->certs_len[i] != 0;i++){
        certs_total_len += sig->certs_len[i];
    }

    if (!memIsValid(certs, certs_total_len))
        return SIZE_MAX;

    derEncStep(derTSEQEncStart(Signature, buf, count, 0x7F4E), buf, count);

    derEncStep(derTSIZEEnc(buf, 0x5F29, sig->sig_len), buf, count);

    derEncStep(derOCTEnc(buf, sig->sig, sig->sig_len), buf, count);

    derEncStep(derOCTEnc(buf, sig->certs_len, sizeof(size_t) * SIG_MAX_CERTS), buf, count);

    derEncStep(derOCTEnc(buf, certs, certs_total_len), buf, count);

    derEncStep(derTSEQEncStop(buf, count, Signature), buf,count);

    return count;
}

static size_t sigDec(
        octet der[],
        size_t count,
        cmd_sig_t* sig,
        octet certs[]
){

    der_anchor_t Signature[1];
    der_anchor_t Certs[1];
    octet *ptr = der;
    cmd_sig_t m_sig[1];
    octet m_certs[SIG_MAX_CERTS * SIG_MAX_CERT_SIZE];
    size_t certs_total_len = 0;

    if (!memIsNullOrValid(sig, sizeof(cmd_sig_t)))
        return SIZE_MAX;

    derDecStep(derTSEQDecStart(Signature, ptr, count, 0x7F4E), ptr, count);

    derDecStep(derTSIZEDec(&m_sig->sig_len,ptr,count, 0x5F29), ptr, count);

    derDecStep(derOCTDec2(m_sig->sig, ptr, count , m_sig->sig_len), ptr, count);

    derDecStep(derOCTDec2((octet*)m_sig->certs_len, ptr, count, sizeof(size_t) * SIG_MAX_CERTS), ptr, count);

    for (size_t i =0 ; i < SIG_MAX_CERTS && m_sig->certs_len[i] != 0; i++){
        certs_total_len += m_sig->certs_len[i];
    }

    derDecStep(derOCTDec2(m_certs, ptr, count, certs_total_len), ptr, count);

    derDecStep(derTSEQDecStop(ptr, Signature), ptr, count);

    if (memIsValid(sig, sizeof (cmd_sig_t)))
        memCopy(sig, m_sig, sizeof (cmd_sig_t));

    if (memIsValid(certs, certs_total_len))
        memCopy(certs, m_certs, certs_total_len);

    return ptr - der;
}

/*
*******************************************************************************
Чтение / запись цепочки сертификатов
*******************************************************************************
*/
static err_t sigReadCerts(
        const char* names,
        octet certs[],
        size_t certs_lens[SIG_MAX_CERTS]
){
    size_t m_certs_cnt;
    size_t m_certs_lens[SIG_MAX_CERTS];
    octet m_certs[SIG_MAX_CERTS * SIG_MAX_CERT_SIZE];
    size_t certs_total_len = 0;
    char* blob = blobCreate(strLen(names));
    char* m_names = blob;
    err_t  code;
    strCopy(m_names, names);

    m_certs_cnt = 0;
    bool_t stop = FALSE;
    while (!stop) {
        size_t i = 0;
        for (; m_names[i] != '\0' && m_names[i] != CERTS_DELIM; i++);
        if (m_names[i] == '\0')
            stop = TRUE;
        else
            m_names[i] = '\0';

        code = cmdCVCRead(
                m_certs + certs_total_len,
                m_certs_lens + m_certs_cnt, m_names);

        ERR_CALL_HANDLE(code, blobClose(blob));
        m_names += i + 1;
        certs_total_len += m_certs_lens[m_certs_cnt];
        m_certs_cnt++;
    }

    if (memIsValid(certs, certs_total_len))
        memCopy(certs, m_certs, certs_total_len);

    if (certs_lens){
        for (size_t i =0; i < SIG_MAX_CERTS; i++){
            certs_lens[i] = i < m_certs_cnt ? m_certs_lens[i] : 0;
        }
    }


    blobClose(blob);
    return ERR_OK;
}

static err_t sigWriteCerts(
        const char* names,
        const octet certs[],
        const size_t certs_lens[],
        size_t certs_cnt
){

    if (!names || !strLen(names) && certs_cnt > 0)
        return ERR_BAD_NAME;

    char* blob = blobCreate(strLen(names));
    char* m_certs = blob;
    strCopy(m_certs, names);
    size_t m_certs_cnt = 0;
    size_t m_total_certs_len = 0;
    bool_t stop = FALSE;
    FILE* fp;
    while (!stop){

        if (m_certs_cnt >= certs_cnt){
            blobClose(blob);
            return ERR_BAD_PARAMS;
        }
        size_t i = 0;
        for (; m_certs[i] != '\0' && m_certs[i] != CERTS_DELIM; i++);
        if (m_certs[i] == '\0')
            stop = TRUE;
        else
            m_certs[i] = '\0';

        if (cmdFileValNotExist(1, &m_certs) == ERR_OK) {
            fp = fopen(m_certs, "wb");
            if (!fp)
                return ERR_FILE_OPEN;
            fwrite(certs + m_total_certs_len, 1, certs_lens[m_certs_cnt], fp);
            m_total_certs_len += certs_lens[m_certs_cnt];
            fclose(fp);
        }
        m_certs += i+1;
        m_certs_cnt++;
    }

    blobClose(blob);

    return m_certs_cnt == certs_cnt ? ERR_OK : ERR_BAD_PARAMS;
}


/*
*******************************************************************************
Чтение подписи из файла
*******************************************************************************
*/
err_t cmdSigRead(
        size_t* der_len,
        cmd_sig_t* sig,
        octet certs[],
        const char* file
){

    ASSERT(memIsNullOrValid(sig, sizeof (cmd_sig_t)));

    FILE* fp;
    size_t der_count = SIG_MAX_DER;
    octet buf[SIG_MAX_DER];
    octet m_certs[SIG_MAX_CERTS * SIG_MAX_CERT_SIZE];
    octet * der = buf;
    size_t file_size = cmdFileSize(file);
    cmd_sig_t m_sig[1];
    size_t total_certs_len = 0;
    if (der_count > file_size){
        der += der_count - file_size;
        der_count = file_size;
    }

    if (file_size == SIZE_MAX)
        return ERR_FILE_OPEN;

    fp = fopen(file, "rb");

    if (!fp)
        return ERR_FILE_NOT_FOUND;

    memSetZero(buf, sizeof(buf));
    fseek(fp, - (signed) der_count, SEEK_END);
    fread(der, 1,der_count,fp);
    memRev(buf, sizeof (buf));

    if ((der_count = sigDec(buf, sizeof (buf), m_sig, m_certs)) == SIZE_MAX)
        return ERR_BAD_SIG;

    if(memIsValid(sig, sizeof (cmd_sig_t))) {
        memCopy(sig, m_sig, sizeof(cmd_sig_t));
    }

    for (size_t i =0; i < SIG_MAX_CERTS && m_sig->certs_len[i]; i++)
        total_certs_len += m_sig->certs_len[i];

    if(memIsValid(certs, total_certs_len))
        memCopy(certs, m_certs, total_certs_len);

    if (der_len)
        *der_len = der_count;

    return ERR_OK;
}


/*
*******************************************************************************
Запись подписи в файл
*******************************************************************************
*/
err_t cmdSigWrite(
        cmd_sig_t* sig,
        octet certs[],
        const char* file,
        bool_t append
){

    size_t count;
    octet der[SIG_MAX_DER];
    FILE* fp;

    if (!append)
        ERR_CALL_CHECK(cmdFileValNotExist(1, &file));

    count = sigEnc(der, sig, certs);
    fp = fopen(file, append ? "ab" : "wb");


    if (!fp)
        return ERR_FILE_OPEN;

    memRev(der, sizeof (der));
    if (fwrite(der + SIG_MAX_DER - count, 1, count, fp) != count)
        return ERR_OUTOFMEMORY;

    fclose(fp);

    return ERR_OK;
}

/*
*******************************************************************************
 Хэширование файла с учетом отступа для встроенной подписи
*******************************************************************************
*/
static int bsumHashFileWithOffset(
        octet hash[],
        size_t hid,
        const char* filename,
        unsigned end_offset
){
    size_t file_size;
    size_t total_readed;
    bool_t eof_reached;
    FILE* fp;
    octet state[4096];
    octet buf[4096];
    size_t count;
    // открыть файл

    if (end_offset > 0)
        file_size = cmdFileSize(filename);
    else
        file_size = 0;

    if (file_size == SIZE_MAX)
        return -1;

    fp = fopen(filename, "rb");

    if (!fp)
    {
        printf("ERROR : failed to open file '%s'\n", filename);
        return -1;
    }

    total_readed = 0;
    eof_reached = FALSE;

    // хэшировать
    ASSERT(beltHash_keep() <= sizeof(state));
    ASSERT(bashHash_keep() <= sizeof(state));
    hid ? bashHashStart(state, hid / 2) : beltHashStart(state);
    while (!eof_reached)
    {
        count = fread(buf, 1, sizeof(buf), fp);

        if (end_offset > 0 && total_readed + count >= file_size - end_offset)
        {
            count = (file_size - end_offset) - total_readed;
            eof_reached = TRUE;
        }
        if (count == 0)
        {
            if (ferror(fp))
            {
                fclose(fp);
                printf("%s: FAILED [read]\n", filename);
                return -1;
            }
            break;
        }
        hid ? bashHashStepH(buf, count, state) :
        beltHashStepH(buf, count, state);

        total_readed += count;
    }
    // завершить
    fclose(fp);
    hid ? bashHashStepG(hash, hid / 8, state) : beltHashStepG(hash, state);
    return 0;
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

static const char* hashOid(size_t hid)
{
    switch (hid)
    {
        case 128:
            return "1.2.112.0.2.0.34.101.31.81";
        case 192:
            return "1.2.112.0.2.0.34.101.77.12";
        case 256:
            return "1.2.112.0.2.0.34.101.77.13";
        default:
            return NULL;
    }
}

/*!
    \brief Проверка цепочки сертификатов

    Проверка завершается успешно, если
    - Доверенный сертификат совпадает с первым сертификатом в цепочке
      и дальнейшая цепочка корректна.
    - Первый сертификат в цепочке признается действительным на anchor
      и дальнейшая цепочка корректна
    - Первый сертификат в цепочке признается действительным на pubkey
      и дальнейшая цепочка корректна

    \remark Если anchor = NULL и pubkey = NULL, то первый сертификат в
    цепочке считается дверенным. Пустая цепочка вызывает ошибку ERR_BAD_CERT

    \return ERR_OR, если цепочка корректна. Код ошибки в обратном случае
 */
static err_t cmdValCerts(
        btok_cvc_t *last_cert,              /*!< [out] последний сертификат */
        octet * anchor,                     /*!< [in]  доверенный сертификат (optional) */
        size_t anchor_len,                  /*!< [in]  длина доверенного сертификата */
        const octet *pubkey,                /*!< [in]  открытый ключ издателя (optional) */
        size_t pubkey_len,                  /*!< [in]  длина ключа издателя*/
        const octet  certs[],               /*!< [in] сертификаты для проверки */
        const size_t certs_lens[]           /*!< [in] длины всех сертификатов */
){

    btok_cvc_t cvc_anchor[1];
    btok_cvc_t cvc_current[1];
    octet date[6];
    err_t code;
    bool_t same_anchor;
    size_t certs_total_len = 0;

    if (!tmDate2(date))
        return ERR_BAD_DATE;

    if (!certs_lens[0])
        return ERR_BAD_CERT;

    if (!anchor && !certs_lens[1])
        return ERR_OK;

    same_anchor = anchor && anchor_len == certs_lens[0] &&
                  memEq(anchor, certs, anchor_len);

    // доверенный сертификат совпадает с первым в цепочке
    if (!certs_lens[1] && same_anchor)
    {
        code = btokCVCUnwrap(cvc_anchor, anchor, anchor_len, 0, 0);
        if (memIsValid(last_cert, sizeof (btok_cvc_t)))
            memCopy(last_cert, cvc_anchor, sizeof (btok_cvc_t));

        return code;
    }

    if (anchor && !same_anchor)
    {
        code = btokCVCUnwrap(cvc_anchor, anchor, anchor_len, 0, 0);
    } else
    {
        code = btokCVCUnwrap(cvc_anchor, certs, certs_lens[0], pubkey ? pubkey : 0,pubkey? pubkey_len : 0);
        certs_total_len += certs_lens[0];
        certs_lens++;
    }
    ERR_CALL_CHECK(code)

    for (size_t i = 0;  i < SIG_MAX_CERTS && certs_lens[i]; i++)
    {
        code = btokCVCVal2(cvc_current, certs + certs_total_len, certs_lens[i], cvc_anchor, date);
        ERR_CALL_CHECK(code)
        memCopy(cvc_anchor, cvc_current, sizeof (btok_cvc_t));
        certs_total_len+= certs_lens[i];
    }

    if (memIsValid(last_cert, sizeof (btok_cvc_t)))
        memCopy(last_cert, cvc_anchor, sizeof (btok_cvc_t));

    return code;
}

/*
*******************************************************************************
Проверка подписи
*******************************************************************************
*/
err_t cmdSigVerify(
        octet* pubkey,
        octet* anchor_cert,
        size_t anchor_cert_len,
        const char* file,
        const char* sig_file
){
    err_t code;
    size_t der_len;
    cmd_sig_t sig[1];
    octet certs[SIG_MAX_CERTS * SIG_MAX_CERT_SIZE];
    octet hash[64];
    size_t hid;
    octet oid_der[128];
    size_t oid_len;
    bign_params params[1];

    btok_cvc_t last_cert[1];


    memSetZero(sig, sizeof (sig));
    code = cmdSigRead(&der_len, sig, certs,sig_file);
    ERR_CALL_CHECK(code)

    if (!sig->certs_len[0] && !pubkey)
        return ERR_BAD_SIG;

    if (sig->certs_len[0])
    {
        code = cmdValCerts(last_cert, anchor_cert ? anchor_cert : 0, anchor_cert_len,
                           pubkey ? pubkey : 0, sig->sig_len * 2 / 3, certs,
                           sig->certs_len);
        ERR_CALL_CHECK(code)
    }

    hid = sig->sig_len * 8/3 ;

    memSetZero(hash, sizeof (hash));
    code = bsumHashFileWithOffset(hash, hid, file, strEq(file, sig_file) ? der_len : 0);
    ERR_CALL_CHECK(code)

    code = bignStdParams(params, curveOid(hid));
    ERR_CALL_CHECK(code)

    oid_len = sizeof(oid_der);
    code = bignOidToDER(oid_der, &oid_len, hashOid(hid));
    ERR_CALL_CHECK(code);

    return bignVerify(params, oid_der, oid_len, hash, sig->sig, pubkey ? pubkey : last_cert->pubkey);
}

/*
*******************************************************************************
Выработка подписи
*******************************************************************************
*/

err_t cmdSigSign(
        cmd_sig_t * sig,
        const octet * privkey,
        size_t privkey_len,
        const octet* certs,
        const size_t certs_lens[SIG_MAX_CERTS],
        const char* file
){
    octet hash[64];
    octet oid_der[128];
    size_t oid_len;
    bign_params params;
    err_t code;
    octet t[64];
    size_t t_len;

    ASSERT(memIsValid(sig, sizeof (cmd_sig_t)));

    if (certs){
        memCopy(sig->certs_len, certs_lens, sizeof (size_t) * SIG_MAX_CERTS);
    } else {
        memSetZero(sig ->certs_len, sizeof (size_t) * SIG_MAX_CERTS);
    }

    if (sig->certs_len[0])
    {
        code = cmdValCerts(0, 0, 0, 0, 0, certs, sig->certs_len);
        ERR_CALL_CHECK(code);
    }

    memSetZero(hash, sizeof (hash));
    bsumHashFileWithOffset(hash, privkey_len * 4, file, 0);

    code = bignStdParams(&params, curveOid(privkey_len * 4));
    ERR_CALL_CHECK(code);

    oid_len = sizeof(oid_der);
    code = bignOidToDER(oid_der, &oid_len, hashOid(privkey_len * 4));
    ERR_CALL_CHECK(code);

    memSetZero(sig->sig, 96);

    sig->sig_len = privkey_len * 3 / 2;

    if (rngIsValid())
        rngStepR(t, t_len = privkey_len, 0);
    else
        t_len = 0;

    return bignSign2(sig->sig, &params, oid_der, oid_len,hash, privkey, t, t_len);
}
