#include <stdio.h>
#include <bee2/core/err.h>
#include <bee2/core/der.h>
#include <bee2/core/blob.h>
#include <bee2/core/util.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/tm.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/btok.h>
#include "../cmd.h"

#define SIG_MAX_CERTS 16
#define SIG_MAX_CERT_SIZE 512
#define CERTS_DELIM ','

#define ARG_CERT "-cert"
#define ARG_ANCHOR "-anchor"
#define ARG_PASS "-pass"
#define ARG_PUBKEY "-pubkey"
#define ARG_VFY "vfy"
#define ARG_SIGN "sign"
#define ARG_PRINT "print"

/*
*******************************************************************************
Утилита sig

Функционал:
- выработка ЭЦП;
- проверка ЭЦП;
- печать ЭЦП.

Примеры:

  Подготовка сертификатов:
    bee2cmd kg gen -l256 -pass pass:root privkey0
    bee2cmd kg gen -l192 -pass pass:trent privkey1
    bee2cmd kg gen -pass pass:alice privkey2
    bee2cmd cvc root -authority BYCA0000 -from 220707 -until 990707 \
	  -pass pass:root -eid EEEEEEEEEE -esign 7777 privkey0 cert0
    bee2cmd cvc print cert0
    bee2cmd cvc req -pass pass:trent  -authority BYCA0000 -holder BYCA1000 \
	  -from 220712 -until 221130 -eid DDDDDDDDDD -esign 3333 privkey1 req1
    bee2cmd cvc iss -pass pass:root privkey0 cert0 req1 cert1
    bee2cmd cvc req -authority BYCA1000 -from 220712 -until 391231 -esign 1111 \
  	  -holder "590082394654" -pass pass:alice -eid 8888888888 privkey2 req2
    bee2cmd cvc iss -pass pass:trent privkey1 cert1 req2 cert2

  Внешняя подпись:
    bee2cmd sig sign -cert "cert1,cert2" -pass pass:alice privkey2 file_to_sign.pdf file_to_store_sig.bin
    bee2cmd sig vfy -anchor cert0 file_to_sign.pdf file_to_store_sig.bin
    bee2cmd sig vfy -pubkey <cert0.pubkey> file_to_sign.pdf file_to_store_sig.bin
    bee2cmd sig print -cert "save_cert1,save_cert2" file_to_store_sig.bin

  Встраивание подписи:
    bee2cmd sig sign -cert "cert1,cert2" -pass pass:alice privkey2 file_to_sign.exe file_to_sign.exe
    bee2cmd sig vfy -anchor cert0 file_to_sign.exe file_to_sign.exe
    bee2cmd sig vfy -pubkey <cert0.pubkey> file_to_sign.exe file_to_sign.exe
    bee2cmd sig print -cert "save_cert1,save_cert2" file_to_sign

*******************************************************************************
*/

extern err_t cmdCVCRead(octet cert[], size_t* cert_len, const char* file);


typedef struct {
    size_t sig_len;	                    /*!< длина подписи в октетах */
    octet sig[96];	                    /*!< подпись */
    size_t certs_cnt;				    /*!< количество сертификатов */
    size_t certs_len[SIG_MAX_CERTS];    /*!< длины сертификатов */
} cmd_sig_t;

static const char _name[] = "sig";
static const char _descr[] = "sign and verify files";



static int sigUsage(){
    printf(
            "bee2cmd/%s: %s\n"
            "Usage:\n"
            "  %s %s [%s <certa,certb,...,cert> ] [%s <scheme>] <privkey> <file> <sig>\n"
            "    sign <file> using <privkey> and write signature to <sig>\n"
            "  options:\n"
            "    %s <certa,certb,...,cert> -- certificate sequence (optional)\n"
            "    %s <scheme> -- scheme of the private key password\n"
            "  %s %s [%s <pubkey> | %s <anchor>] <file> <sig>\n"
            "    verify <file> signature stored in <sig>\n"
            "  options:\n"
            "    %s <pibkey> -- verification public key\n"
            "    %s <anchor> -- trusted certificate"
            "  %s %s [%s <save_certa,save_certb,...,save_cert>] <sig>\n"
            "    print <sig> to the console\n"
            "  options:\n"
            "    %s <ave_certa,save_certb,...,save_cert> -- files to save certificates (if signature contains it)\n"
            ,
            _name, _descr,
            _name, ARG_SIGN, ARG_CERT, ARG_PASS,
            ARG_CERT, ARG_PASS,
            _name, ARG_VFY, ARG_PUBKEY, ARG_ANCHOR,
            ARG_PUBKEY, ARG_ANCHOR,
            _name, ARG_PRINT, ARG_CERT, ARG_CERT
    );
    return -1;
}


/*
*******************************************************************************
Кодирование подписи

  SEQ[APPLICATION 78] Signature
    SIZE[APPLICATION 41] -- sig_len
    SIZE[APPLICATION 42] -- cert_cnt
    OCT(SIZE(96)) -- sig
    OCT(SIZE(sizeof(size_t) * SIG_MAX_CERT)) - cert_len
    SEQ[APPLICATION 75] Cert
      OCT - cert[i]
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
}                                   \

/*!
    \brief Декодирование подписи

    \return Длина der-кода
*/
size_t sigEnc(
    octet buf[],                        /*!< [out] закодированная подпись с сертификатами*/
    cmd_sig_t* sig,                     /*!< [in] подпись */
    octet certs[][SIG_MAX_CERT_SIZE]    /*!< [in] сертификаты */
){

    der_anchor_t Signature[1];
    der_anchor_t Certs[1];

    size_t count = 0;

    if (!memIsValid(sig, sizeof(cmd_sig_t)))
        return SIZE_MAX;

    for (size_t i = 0; i < sig->certs_cnt; i++)
        if (!memIsValid(certs[i], sig->certs_len[i]))
            return SIZE_MAX;

    derEncStep(derTSEQEncStart(Signature, buf, count, 0x7F4E), buf, count);

    derEncStep(derTSIZEEnc(buf, 0x5F29, sig->sig_len), buf, count);

    derEncStep(derOCTEnc(buf, sig->sig, sig->sig_len), buf, count);

    derEncStep(derTSIZEEnc(buf, 0x5F2A, sig->certs_cnt), buf, count);

    derEncStep(derOCTEnc(buf, sig->certs_len, sizeof(size_t) * SIG_MAX_CERTS), buf, count);

    derEncStep(derTSEQEncStart(Certs, buf, count, 0x7F4B), buf, count);
    for (size_t i = 0; i < sig->certs_cnt;i++)
        derEncStep(derOCTEnc(buf, certs[i], sig->certs_len[i]), buf, count);

    derEncStep(derTSEQEncStop(buf, count, Certs), buf, count);
    derEncStep(derTSEQEncStop(buf, count, Signature), buf,count);

    return count;
}

/*!
    \brief Кодирование подписи

    \return Реальная длина der-кода
*/
size_t sigDec(
    octet der[],                        /*!< [in] закодированная подпись */
    size_t count,                       /*!< [in] предполагаемая длина der-кода*/
    cmd_sig_t* sig,                     /*!< [out] подпись */
    octet certs[][SIG_MAX_CERT_SIZE]    /*!< [out] сертефикаты */
){

    der_anchor_t Signature[1];
    der_anchor_t Certs[1];
    octet *ptr = der;

    if (!memIsNullOrValid(sig, sizeof(cmd_sig_t)))
        return SIZE_MAX;

    derDecStep(derTSEQDecStart(Signature, ptr, count, 0x7F4E), ptr, count);

    derDecStep(derTSIZEDec(&sig->sig_len,ptr,count, 0x5F29), ptr, count);
    derDecStep(derOCTDec2(sig->sig, ptr, count ,sig->sig_len), ptr, count);

    derDecStep(derTSIZEDec(&sig->certs_cnt,ptr,count, 0x5F2A), ptr, count);

    derDecStep(derOCTDec2((octet*)sig->certs_len, ptr, count, sizeof(size_t) * SIG_MAX_CERTS), ptr, count);

    derDecStep(derTSEQDecStart(Certs, ptr, count, 0x7F4B), ptr, count);
    for (size_t i = 0; i < sig->certs_cnt;i++)
    {
        if (!memIsValid(certs[i], sig->certs_len[i]))
            return SIZE_MAX;

        derDecStep(derOCTDec2(certs[i],ptr, count, sig->certs_len[i]), ptr, count);
    }
    derDecStep(derTSEQDecStop(ptr, Certs), ptr, count);
    derDecStep(derTSEQDecStop(ptr, Signature), ptr, count);

    return ptr - der;
}



/*
*******************************************************************************
Чтение / запись цепочки сертификатов
*******************************************************************************
*/
static err_t sigReadCerts(
    const char* names,
    octet certs[][SIG_MAX_CERT_SIZE],
    size_t certs_lens[],
    size_t * certs_cnt
){
    size_t m_certs_cnt;
    char* blob = blobCreate(strLen(names));
    char* m_certs = blob;

    strCopy(m_certs, names);

    m_certs_cnt = 0;
    bool_t stop = FALSE;
    while (!stop) {
        size_t i = 0;
        for (; m_certs[i] != '\0' && m_certs[i] != CERTS_DELIM; i++);
        if (m_certs[i] == '\0')
            stop = TRUE;
        else
            m_certs[i] = '\0';
        ERR_CALL_HANDLE(cmdCVCRead(certs + m_certs_cnt, certs_lens + m_certs_cnt, m_certs), blobClose(blob));
        m_certs += i+1;
        m_certs_cnt++;
    }

    if (certs_cnt){
        *certs_cnt = m_certs_cnt;
    }

    blobClose(blob);
    return ERR_OK;
}

static err_t sigWriteCerts(const char* names, octet certs[][SIG_MAX_CERT_SIZE], size_t certs_lens[], size_t certs_cnt){

    if (!names || !strLen(names) && certs_cnt > 0)
        return ERR_BAD_NAME;

    char* blob = blobCreate(strLen(names));
    char* m_certs = blob;
    strCopy(m_certs, names);
    size_t m_certs_cnt = 0;
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
            fwrite(certs[m_certs_cnt], 1, certs_lens[m_certs_cnt], fp);
            fclose(fp);
        }
        m_certs += i+1;
        m_certs_cnt++;
    }

    blobClose(blob);

    return m_certs_cnt == certs_cnt ? ERR_OK : ERR_BAD_PARAMS;
}



/*!
    \brief Чтение подписи из файла
    \return ERR_OK, если подпись прочитана успешно. Код ошибки в обратном случае.
 */
err_t cmdSigRead(
    size_t* der_len,                                      /*!< [out] длина der-кода */
    cmd_sig_t* sig,                                       /*!< [out] подпись. Может быть NULL, тогда подпись не возвращается */
    octet certs[SIG_MAX_CERT_SIZE][SIG_MAX_CERT_SIZE],    /*!< [out] сертификаты. Может быть NULL, тогда сертификаты не возвращаются */
    const char* file                                      /*!< [in]  файл, содержащий подпись*/
){

    ASSERT(memIsNullOrValid(sig, sizeof (cmd_sig_t)));

    FILE* fp;
    size_t der_count = SIG_MAX_CERTS * SIG_MAX_CERT_SIZE + 96 + 16;
    octet buf[SIG_MAX_CERTS * SIG_MAX_CERT_SIZE + 96 + 16];
    octet m_certs[SIG_MAX_CERTS][SIG_MAX_CERT_SIZE];
    octet * der = buf;
    size_t file_size = cmdFileSize(file);
    cmd_sig_t m_sig;

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

    if ((der_count = sigDec(buf, sizeof (buf), &m_sig, m_certs)) == SIZE_MAX)
        return ERR_BAD_SIG;

    if(memIsValid(sig, sizeof (cmd_sig_t)))
        memCopy(sig, &m_sig, sizeof (cmd_sig_t));

    if (certs) {
        for (int i = 0; i < m_sig.certs_cnt; i++)
        {
            if (memIsValid(certs[i], m_sig.certs_len[i]))
                memCopy(certs[i], m_certs[i], m_sig.certs_len[i]);
        }
    }

    if (der_len)
        *der_len = der_count;

    return ERR_OK;
}


/*! \brief Запись подписи в файл

    \return ERR_OK, если подпись записана успешно. Код ошибки в обратном случае.

    \remark Подпись читается с конца, поэтому может быть дописана в непустой,
    в частности исполняемый файл (при указании append = true)
 */
err_t cmdSigWrite(
    cmd_sig_t* sig,                          /*!< [in] подпись */
    octet certs[][SIG_MAX_CERT_SIZE],        /*!< [in] сертификаты */
    const char* file,                        /*!< [in] файл для записи */
    bool_t append                            /*!< [in] дописать[TRUE]/перезаписать[FALSE] подпись */
){

    size_t count;
    const size_t max_der = SIG_MAX_CERTS * SIG_MAX_CERT_SIZE + 128;
    octet der[max_der];
    FILE* fp;

    if (!append)
        ERR_CALL_CHECK(cmdFileValNotExist(1, &file));

    count = sigEnc(der, sig, certs);
    fp = fopen(file, append ? "ab" : "wb");

    if (!fp)
        return ERR_FILE_OPEN;

    memRev(der, sizeof (der));
    if (fwrite(der + max_der - count, 1, count, fp) != count)
        return ERR_OUTOFMEMORY;

    fclose(fp);

    return ERR_OK;
}


/*
*******************************************************************************
 Разбор опций командной строки

 Опции возвращаются по адресам
 privkey [privkey_len],
 pubkey [pubkey_len],
 anchor_cert [anchor_cert_len],
 file, sig_file, certs
 has_certs
 Любой из адресов может быть нулевым, и тогда соответствующая опция не возвращается.
 Более того, ее указаниев командной строке считается ошибкой.

 В случае успеха по адресу readc возвращается число обработанных аргументов.
*******************************************************************************
*/

static err_t sigParseOptions(
        int argc,
        char** argv,
        octet* privkey,
        size_t * privkey_len,
        octet* pubkey,
        size_t * pubkey_len,
        octet* anchor_cert,
        size_t* anchor_cert_len,
        char* file,
        char* sig_file,
        char* certs,
        bool_t* has_certs
){
    cmd_pwd_t pwd;
    bool_t pwd_provided = FALSE;
    size_t m_privkey_len;
    size_t m_pubkey_len;

    if (has_certs)
        *has_certs = FALSE;

    char* command = argv[0];
    if (!strEq(command, ARG_SIGN) &&
            !strEq(command, ARG_VFY) &&
            !strEq(command, ARG_PRINT))
        return ERR_CMD_PARAMS;

    --argc;
    ++argv;

    while (argc >0 && strStartsWith(*argv, "-"))
    {

        if (argc < 2)
            return ERR_CMD_PARAMS;


        // прочитать схему защиты личного ключа
        if (strEq(*argv, ARG_PASS))
        {
            if ((cmdPwdRead(&pwd, argv[1]) != ERR_OK))
                return ERR_CMD_PARAMS;
            pwd_provided = TRUE;
        }

        // прочитать доверенный сертификат
        if (strEq(*argv, ARG_ANCHOR))
        {
            if (!anchor_cert)
                return ERR_CMD_PARAMS;

            ASSERT(memIsValid(anchor_cert_len, sizeof(size_t)));

            if (cmdCVCRead(anchor_cert, anchor_cert_len, argv[1]) != ERR_OK)
                return ERR_CMD_PARAMS;

        }

        // прочитать открытый ключ
        if (strEq(*argv, ARG_PUBKEY))
        {
            if (!pubkey)
                return ERR_CMD_PARAMS;


            FILE* fp = fopen(argv[1], "rb");
            if (!fp)
            {
                printf("ERROR: failed to open public key file '%s'\n", argv[1]);
                return ERR_FILE_OPEN;
            }
            m_pubkey_len = fread(pubkey, 1, 128, fp);

            fclose(fp);
            if (m_pubkey_len != 128 && m_pubkey_len != 96 && m_pubkey_len != 64)
                return ERR_BAD_PUBKEY;

            if (memIsValid(pubkey_len, sizeof (size_t)))
                *pubkey_len = m_pubkey_len;

        }


        // прочитать сертификаты
        if (strEq(*argv, ARG_CERT))
        {
            if (!memIsValid(certs, strLen(argv[1])))
                return ERR_CMD_PARAMS;

            if (has_certs)
                *has_certs = TRUE;

            memCopy(certs, argv[1], strLen(argv[1]));
        }

        argc -= 2;
        argv += 2;
    }

    if (strEq(command, ARG_SIGN))
    {
        if (argc != 3 || !privkey)
            return ERR_CMD_PARAMS;

        m_privkey_len = 0;
        if (pwd_provided)
        {
            if(cmdPrivkeyRead(privkey, &m_privkey_len, argv[0], pwd) != ERR_OK)
                return ERR_CMD_PARAMS;

        } else
        {
            //если схема пароля не предоставлена, личный ключ читается как открытый
            FILE *fp = fopen(argv[0],"rb");
            if (!fp)
            {
                printf("ERROR: failed to open private key container '%s'\n", argv[0]);
                return ERR_FILE_OPEN;
            }
            *privkey_len = fread(privkey, 1, 64, fp);
            fclose(fp);
        }

        if (m_privkey_len != 64 && m_privkey_len != 48 && m_privkey_len != 32)
            return ERR_BAD_PRIVKEY;

        if (memIsValid(privkey_len, sizeof (size_t)))
            *privkey_len = m_privkey_len;

        //прочитать имя подписываемого файла
        strCopy(file, argv[1]);

        //прочитать имя файла c подписью
        strCopy(sig_file, argv[2]);

    }
    else if (strEq(command, ARG_VFY))
    {
        if (argc != 2)
            return ERR_CMD_PARAMS;

        //прочитать имя подписанного файла
        strCopy(file, argv[0]);

        //прочитать имя файла c подписью
        strCopy(sig_file, argv[1]);
    }
    else if (strEq(command, ARG_PRINT))
    {
        if (argc != 1 || !memIsValid(sig_file, strlen(argv[0])))
            return ERR_CMD_PARAMS;

        // прочитать имя файла c подписью
        strCopy(sig_file, argv[0]);

    }

    return ERR_OK;
}


/*!
    \brief Хэширование файла с учетом отступа для встроенной подписи

    \remark При hid = 0 используется belt-hash, иначе bash-hash.

    \return 0, если хэширование выполнено успешно и -1 в обратном случае
 */
int bsumHashFileWithOffset(
    octet hash[],                /*!< [out] хэш-значение. */
    size_t hid,                  /*!< [in] уровень стойкости */
    const char* filename,        /*!< [in] хэшируемый файл*/
    unsigned end_offset          /*!< [in] отступ с конца */
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
err_t cmdValCerts(
        btok_cvc_t *last_cert,              /*!< [out] последний сертификат */
        octet * anchor,                     /*!< [in]  доверенный сертификат (optional) */
        size_t anchor_len,                  /*!< [in]  длина доверенного сертификата */
        octet *pubkey,                      /*!< [in]  открытый ключ издателя (optional) */
        size_t pubkey_len,                  /*!< [in]  длина ключа издателя*/
        octet  certs[][SIG_MAX_CERT_SIZE],  /*!< [in] сертификаты для проверки */
        size_t* certs_lens,                 /*!< [in] длины всех сертификатов */
        size_t certs_cnt                    /*!< [in] количество сертификатов */
){

    btok_cvc_t cvc_anchor[1];
    btok_cvc_t cvc_current[1];
    octet date[6];
    err_t code;
    bool_t same_anchor;

    if (!tmDate2(date))
        return ERR_BAD_DATE;

    if (certs_cnt <= 0)
        return ERR_BAD_CERT;

    if (!anchor && certs_cnt == 1)
        return ERR_OK;

    same_anchor = anchor && anchor_len == certs_lens[0] &&
                   memEq(anchor, certs[0], anchor_len);

    // доверенный сертификат совпадает с первым в цепочке
    if (certs_cnt == 1 && same_anchor)
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
        code = btokCVCUnwrap(cvc_anchor, certs[0], certs_lens[0], pubkey ? pubkey : 0,pubkey? pubkey_len : 0);
        certs ++;
        certs_lens++;
        certs_cnt--;
    }
    ERR_CALL_CHECK(code)

    for (size_t i = 0; i < certs_cnt; i++)
    {
        code = btokCVCVal2(cvc_current, certs[i], certs_lens[i], cvc_anchor, date);
        ERR_CALL_CHECK(code)
        memCopy(cvc_anchor, cvc_current, sizeof (btok_cvc_t));
    }

    if (memIsValid(last_cert, sizeof (btok_cvc_t)))
        memCopy(last_cert, cvc_anchor, sizeof (btok_cvc_t));

    return code;
}


/*!
    \brief Проверка подписи
    \return ERR_OK, если подпись корректна. Код ошибки в обратном случае.
 */
err_t cmdSigVerify(
        octet* pubkey,                          /*!< [in] открытый ключ (optional) */
        octet* anchor_cert,                     /*!< [in] доверенный сертификат (optional) */
        size_t anchor_cert_len,                 /*!< [in] длина доверенного сертификата */
        const char* file,                       /*!< [in] проверяемый файл */
        const char* sig_file                    /*!< [in] файл с подписью */
){
    cmd_sig_t sig;
    octet certs[SIG_MAX_CERTS][SIG_MAX_CERT_SIZE];
    octet hash[64];
    size_t hid;
    octet oid_der[128];
    size_t oid_len;
    bign_params params[1];

    btok_cvc_t last_cert[1];

    err_t code;

    size_t der_len;
    code = cmdSigRead(&der_len, &sig, certs,sig_file);
    ERR_CALL_CHECK(code)

    if (sig.certs_cnt == 0 && !pubkey)
        return ERR_BAD_SIG;

    if (sig.certs_cnt > 0)
    {
        code = cmdValCerts(last_cert, anchor_cert ? anchor_cert : 0, anchor_cert_len,
                           pubkey ? pubkey : 0, sig.sig_len * 2 / 3, certs,
                           sig.certs_len, sig.certs_cnt);
        ERR_CALL_CHECK(code)
    }

    hid = sig.sig_len * 8/3 ;

    memSetZero(hash, sizeof (hash));
    code = bsumHashFileWithOffset(hash, hid, file, strEq(file, sig_file) ? der_len : 0);
    ERR_CALL_CHECK(code)

    code = bignStdParams(params, curveOid(hid));
    ERR_CALL_CHECK(code)

    oid_len = sizeof(oid_der);
    code = bignOidToDER(oid_der, &oid_len, hashOid(hid));
    ERR_CALL_CHECK(code);

    return bignVerify(params, oid_der, oid_len, hash, sig.sig, pubkey ? pubkey : last_cert->pubkey);
}

static err_t sigVfy(int argc, char* argv[])
{

    err_t code;

    octet pubkey[128];
    size_t pubkey_len = 0;

    octet anchor_cert[1024];
    size_t anchor_cert_len = 0;

    char file_name[1024];
    char sig_file_name[1024];

    cmd_sig_t sig[1];
    octet certs[SIG_MAX_CERTS][SIG_MAX_CERT_SIZE];

    code = sigParseOptions(argc, argv, 0, 0, pubkey, &pubkey_len, anchor_cert,
                           &anchor_cert_len, file_name,sig_file_name, 0,0);
    ERR_CALL_CHECK(code)

    return cmdSigVerify(pubkey_len ? pubkey : 0,anchor_cert_len ? anchor_cert : 0,
                        anchor_cert_len, file_name,sig_file_name);
}

/*
*******************************************************************************
 Выработка подписи
*******************************************************************************
*/
static err_t sigSign(int argc, char* argv[])
{
    char file_name[256];
    char sig_file_name[256];
    char certs_names[256 * SIG_MAX_CERTS];
    octet privkey[64];
    size_t privkey_len;
    cmd_sig_t sig[1];
    octet certs[SIG_MAX_CERTS][SIG_MAX_CERT_SIZE];
    octet hash[64];
    octet oid_der[128];
    size_t oid_len;
    bign_params params;
    err_t code;
    octet t[64];
    size_t t_len;
    bool_t has_certs;

    memSetZero(file_name, sizeof(file_name));
    memSetZero(sig_file_name, sizeof(sig_file_name));
    memSetZero(certs_names, sizeof(certs_names));

    code = sigParseOptions(argc, argv, privkey, &privkey_len,0, 0, 0,0,
                           file_name,sig_file_name, certs_names, &has_certs);
    ERR_CALL_CHECK(code)

    if (has_certs)
    {
        code = sigReadCerts(certs_names, certs, sig->certs_len, &sig->certs_cnt);
        ERR_CALL_CHECK(code)
    } else
    {
        sig->certs_cnt = 0;
    }

    memSetZero(hash, sizeof (hash));
    bsumHashFileWithOffset(hash, privkey_len * 4, file_name, 0);

    code = bignStdParams(&params, curveOid(privkey_len * 4));
    ERR_CALL_CHECK(code)

    oid_len = sizeof(oid_der);
    code = bignOidToDER(oid_der, &oid_len, hashOid(privkey_len * 4));
    ERR_CALL_CHECK(code);

    memSetZero(sig->sig, 96);

    sig->sig_len = privkey_len * 3 / 2;

    if (rngIsValid())
        rngStepR(t, t_len = privkey_len, 0);
    else
        t_len = 0;

    if (sig->certs_cnt > 0)
    {
        code = cmdValCerts(0, 0, 0, 0, 0, certs, sig->certs_len, sig->certs_cnt);
        ERR_CALL_CHECK(code)
    }

    code = bignSign2(sig->sig, &params, oid_der, oid_len,hash, privkey, t, t_len);
    ERR_CALL_CHECK(code)

    return cmdSigWrite(sig, certs, sig_file_name, strEq(sig_file_name, file_name));
}


/*
*******************************************************************************
 Печать подписи
*******************************************************************************
*/
static err_t sigPrint(int argc, char * argv[])
{
    err_t code;

    cmd_sig_t sig[1];
    octet certs[SIG_MAX_CERTS][SIG_MAX_CERT_SIZE];
    char sig_file_name[256];
    char cert_names[256 * SIG_MAX_CERTS];
    size_t cert_names_len;
    char sigHex[96*2 + 1];
    bool_t has_certs;

    code = sigParseOptions(argc, argv, 0,0, 0,0,0,0,0,
                           sig_file_name,cert_names, &has_certs);
    ERR_CALL_CHECK(code)

    code = cmdSigRead(0, sig, certs, sig_file_name);
    if (code == ERR_FILE_NOT_FOUND)
    {
        printf("ERROR: file not found '%s'\n", sig_file_name);
        return ERR_FILE_NOT_FOUND;
    }

    if (code != ERR_OK)
    {
        printf("Program is not signed\n");
        return ERR_OK;
    }

    if (has_certs)
    {
        size_t certs_cnt = 1;
        cert_names_len = strLen(cert_names);
        for (size_t i = 0; i < cert_names_len; i++)
        {
            if (cert_names[i] == CERTS_DELIM)
                certs_cnt++;
        }
        if (certs_cnt != sig->certs_cnt)
        {
            printf("WARNING: certificates extraction failed. Signature has %lu certificates, but %lu output files given\n",
                   sig->certs_cnt, certs_cnt);
        } else
        {
            code = sigWriteCerts(cert_names, certs, sig->certs_len, sig->certs_cnt);
            ERR_CALL_CHECK(code)
        }
    }

    hexFrom(sigHex, sig->sig, sig->sig_len);
    printf("%s\n", sigHex);

    return code;
}



/*
*******************************************************************************
  Главная функция
*******************************************************************************
*/
static int sigMain(int argc, char* argv[])
{
    err_t code;

    if (argc < 3)
        return sigUsage();

    --argc;
    ++argv;

    if (strEq(argv[0], ARG_SIGN))
        code = sigSign(argc, argv);
    else if (strEq(argv[0], ARG_VFY))
        code = sigVfy(argc, argv);
    else if (strEq(argv[0], ARG_PRINT))
        code = sigPrint(argc, argv);
    else
        return sigUsage();

    printf("bee2cmd/%s: %s\n", _name, errMsg(code));
    return code == ERR_OK ? 0 : 1;
}

#pragma endregion

err_t sigInit()
{
    return cmdReg(_name, _descr, sigMain);
}