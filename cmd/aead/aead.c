#include <stdlib.h>
#include <stdio.h>
#include "../cmd.h"
#include "bee2/crypto/btok.h"
#include <bee2/defs.h>
#include <bee2/core/util.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/belt.h>
#include <bee2/core/rng.h>

#define ARG_ENC "enc"
#define ARG_DEC "dec"
#define ARG_VAL "val"
#define ARG_ADATA "-adata"
#define ARG_KLD "-kld"
#define ARG_KLD_PKE "PKE"
#define ARG_KLD_PWD "PWD"
#define ARG_PASS "-pass"
#define ARG_PUBKEY "-pubkey"
#define ARG_PRIVKEY "-privkey"
#define ARG_PRIVKEY "-privkey"
#define ARG_CERT "-cert"
#define ARG_ITAG "--itag"
#define ARG_ITER "--iter"


#ifndef FILENAME_MAX
#define FILENAME_MAX 1024
#endif

#define BLOCK_SIZE 4096

static const char _name[] = "aead";
static const char _descr[] = "authenticated encryption with associated data";

/*
*******************************************************************************
Файлы
*******************************************************************************
*/

err_t cmdFileRead(
        octet* buf,
        size_t* buf_len,
        const char * file
) {
    size_t len;

    ASSERT(memIsNullOrValid(buf_len, O_PER_S));
    ASSERT(strIsValid(file));

    len = cmdFileSize(file);
    if (len == SIZE_MAX)
        return ERR_FILE_READ;

    if (buf)
        len = cmdFileRead2(buf, len, file);

    if (len == SIZE_MAX)
        return ERR_FILE_OPEN;

    if (buf_len)
        *buf_len = len;

    return ERR_OK;
}

size_t cmdFileRead2(
        octet* buf,
        size_t buf_len,
        const char * file
) {
    err_t code;
    size_t len;
    FILE* fp;

    ASSERT(strIsValid(file));
    ASSERT(memIsValid(buf, buf_len));

    code = (fp = fopen(file, "rb")) ? ERR_OK : ERR_FILE_OPEN;
    ERR_CALL_CHECK(code);
    len = fread(buf, 1, buf_len, fp);
    fclose(fp);

    return len;
}


/*
*******************************************************************************
Справка по использованию
*******************************************************************************
*/
static int aeadUsage() {
    printf(
        "bee2cmd/%s: %s\n"
        "Usage:\n"
        "  bee2cmd %s %s %s <keyload_name> {keyload_args} [%sNNN] [%s <ad_file>] <file> <enc_file>\n"
        "    encrypt <file> and save it to <enc_file>\n"
        "    options:\n"
        "      %s <keyload_name> -- %s/%s\n"
        "      %sNNN -- [optional, disabled by default] period of intermediate mac in MB\n"
        "      %s <adata_file> -- [optional] additional data file\n"
        "    %s keyload args:\n"
        "      %s <pubkey> -- [optional, if <cert> provided] recipient's public key\n"
        "      %s <cert> -- [optional, if <pubkey> provided] recipient's certificate\n"
        "    %s keyload args:\n"
        "      %s <scheme> -- scheme of the password\n"
        "      %sNNNNNN -- [optional, 10000 by default] PBKDF2 iterations count (>=10000)\n\n"
        "  bee2cmd %s %s %s <keyload_name> {keyload_args} [%s <ad_file>] <file> <dec_file>\n"
        "    decrypt <file> and save to <dec_file>\n"
        "    options:\n"
        "      %s <keyload_name> -- %s/%s\n"
        "      %s <adata_file>  -- [optional; required if adata file is present] additional data file\n"
        "    %s keyload args:\n"
        "      %s <scheme> -- scheme of the private key password\n"
        "      %s <privkey> -- private key container\n"
        "    %s keyload args:\n"
        "      %s <scheme> -- scheme of the password\n\n"
        "  bee2cmd %s %s %s <keyload_name> {keyload_args} <file>\n"
        "    verify the encrypted <file> is destined for you\n"
        "    options:\n"
        "      %s <keyload_name> -- %s/%s\n"
        "    %s keyload args:\n"
        "      %s <scheme> -- scheme of the recipient's private key password. Must be passed before %s arg\n"
        "      %s <privkey> -- recipient's private key container. Validate that file was encrypted\n"
        "                      with the corresponding recipient's public key\n"
        "      %s <cert> -- [optional] recipient's certificate. Validate that file certificate\n"
        "                   matches the recipient's one (if file contains it).\n"
        "    %s keyload args:\n"
        "      %s <scheme> -- scheme of the password\n"
        ,
        _name, _descr,
        _name, ARG_ENC, ARG_KLD, ARG_ITAG, ARG_ADATA,
        ARG_KLD, ARG_KLD_PKE, ARG_KLD_PWD, ARG_ITAG, ARG_ADATA,
        ARG_KLD_PKE, ARG_PUBKEY, ARG_CERT,
        ARG_KLD_PWD, ARG_PASS, ARG_ITER,
        _name, ARG_DEC, ARG_KLD, ARG_ADATA,
        ARG_KLD, ARG_KLD_PKE, ARG_KLD_PWD, ARG_ADATA,
        ARG_KLD_PKE, ARG_PASS, ARG_PRIVKEY,
        ARG_KLD_PWD, ARG_PASS,
        _name, ARG_VAL, ARG_KLD,
        ARG_KLD, ARG_KLD_PKE, ARG_KLD_PWD,
        ARG_KLD_PKE, ARG_PASS, ARG_PRIVKEY, ARG_PRIVKEY, ARG_CERT,
        ARG_KLD_PKE, ARG_PASS
    );

    return -1;
}

static err_t aeadCreateKeyloadUnwrapParams(
    octet* unwrap_params,
    u32 keyload_tag,
    cmd_pwd_t pwd,
    const octet* privkey,
    size_t privkey_len
){
    switch (keyload_tag) {
        //прочитать параметры снятия защиты ключа в режиме PKE
        case CMD_KEYLOAD_TAG_PKE:

            if (!pwd || !memIsValid(unwrap_params, sizeof (keyload_pke_unwrap_t)))
                return ERR_CMD_PARAMS;

            memSetZero(unwrap_params, sizeof (keyload_pke_unwrap_t));
            if (privkey_len == 0)
                return ERR_CMD_PARAMS;
            ((keyload_pke_unwrap_t*)unwrap_params)->privkey_len = privkey_len;
            memCopy(((keyload_pke_unwrap_t*)unwrap_params)->privkey, privkey, privkey_len);
            break;
        //прочитать параметры снятия защиты ключа в режиме PWD
        case CMD_KEYLOAD_TAG_PWD:

            if (!pwd || !memIsValid(unwrap_params, sizeof (keyload_pwd_unwrap_t)))
                return ERR_CMD_PARAMS;

            memSetZero(unwrap_params, sizeof (keyload_pwd_unwrap_t));

            ((keyload_pwd_unwrap_t*) unwrap_params)->pwd_len = strLen(pwd);
            memCopy(((keyload_pwd_unwrap_t*) unwrap_params)->pwd, pwd,
                    ((keyload_pwd_unwrap_t*) unwrap_params)->pwd_len);
            break;
        default:
            return ERR_CMD_PARAMS;
    }

    return ERR_OK;
}

/*
*******************************************************************************
 Разбор опций командной строки

 Любой из адресов может быть нулевым, и тогда соответствующая опция не возвращается.
 Более того, ее указаниев командной строке считается ошибкой.

*******************************************************************************
*/
static err_t aeadParseOptions(
    int argc,
    const char* argv[],
    const cmd_keyload_t ** keyload_type,
    octet * wrap_params,
    octet * unwrap_params,
    size_t* itag,
    char* file,
    char* new_file,
    char * adata_name
) {

    octet pubkey[128];
    size_t pubkey_len = 0;
    octet privkey[64];
    size_t privkey_len = 0;
    octet cert[512];
    size_t cert_len = 0;
    cmd_pwd_t pwd = 0;
    bool_t kld_provided = FALSE;
    size_t iter = 0;
    err_t code;
    btok_cvc_t cvc;

    const char *command = argv[0];

    if (!strEq(command, ARG_DEC) &&
        !strEq(command, ARG_ENC) &&
        !strEq(command, ARG_VAL))
        return ERR_CMD_PARAMS;

    argv++;
    argc--;

    while (argc > 0 && strStartsWith(*argv, "-"))
    {

        if (argc < 2)
            return ERR_CMD_PARAMS;

        // прочитать тип ключевого материала
        if (strEq(*argv, ARG_KLD))
        {
            if (!memIsValid(keyload_type, sizeof (cmd_keyload_t)))
                return ERR_CMD_PARAMS;

            if (strEq(argv[1], ARG_KLD_PKE)){
                *keyload_type = cmdAeadKeyloadPKE();
            } else if (strEq(argv[1], ARG_KLD_PWD)) {
                *keyload_type = cmdAeadKeyloadPWD();
            } else return ERR_CMD_PARAMS;

            kld_provided = TRUE;
        }


        // прочитать схему защиты личного ключа
        if (strEq(*argv, ARG_PASS))
        {
            if ((cmdPwdRead(&pwd, argv[1]) != ERR_OK))
                return ERR_CMD_PARAMS;
        }

        // прочитать личный ключ
        if (strEq(*argv, ARG_PRIVKEY))
        {
            if (!pwd)
                return ERR_CMD_PARAMS;
            if (cmdPrivkeyRead(privkey,&privkey_len, argv[1], pwd) != ERR_OK)
                return ERR_CMD_PARAMS;
        }

        // прочитать открытый ключ
        if (strEq(*argv, ARG_PUBKEY))
        {
            memSetZero(pubkey, sizeof (pubkey));
            code = cmdFileReadAll(0, &pubkey_len, argv[1]);
            ERR_CALL_CHECK(code);
            ASSERT(sizeof (pubkey) >= pubkey_len);
            code = cmdFileReadAll(pubkey, &pubkey_len, argv[1]);
            ERR_CALL_CHECK(code);
        }

        // прочитать сертификат
        if (strEq(*argv, ARG_CERT))
        {
            code = cmdFileRead(cert, &cert_len, argv[1]);
            ERR_CALL_CHECK(code);
        }

        // прочитать имя файла с дополнительными данными
        if (strEq(*argv, ARG_ADATA))
        {
            if (!adata_name)
                return ERR_CMD_PARAMS;
            strCopy(adata_name, argv[1]);
        }

        //прочитать частоту имитовставок
        if (strStartsWith(*argv, ARG_ITAG)) {
            if (!memIsValid(itag, sizeof(size_t)))
                return ERR_CMD_PARAMS;
            *itag = strtoul(*argv + strLen(ARG_ITAG), 0, 10);
            argv-=1;
            argc+=1;
        }

        //прочитать число итераций PBKDF2
        if (strStartsWith(*argv, ARG_ITER)) {
            iter = strtoul(*argv + strLen(ARG_ITER), 0, 10);
            argv-=1;
            argc+=1;
        }

        argv+=2;
        argc-=2;
    }

    //обработать аргументы зашифрования
    if (strEq(command, ARG_ENC))
    {
        if (argc != 2 || !kld_provided)
            return ERR_CMD_PARAMS;

        strCopy(file, argv[0]);
        strCopy(new_file, argv[1]);

        switch ((*keyload_type)->tag)
        {
            //прочитать параметры защиты ключа в режиме PKE
            case CMD_KEYLOAD_TAG_PKE:

                if (!memIsValid(wrap_params, sizeof (keyload_pke_wrap_t)))
                    return ERR_CMD_PARAMS;

                memSetZero(wrap_params, sizeof (keyload_pke_wrap_t));
                if (pubkey_len == 0)
                {
                    if (cert_len == 0)
                        return ERR_CMD_PARAMS;
                    code = btokCVCUnwrap(&cvc, cert,cert_len,0,0);
                    ERR_CALL_CHECK(code)
                    pubkey_len = cvc.pubkey_len;
                    memCopy(pubkey, cvc.pubkey, pubkey_len);
                }
                ((keyload_pke_wrap_t*)wrap_params)->pubkey_len = pubkey_len;
                memCopy(((keyload_pke_wrap_t*)wrap_params)->pubkey, pubkey, pubkey_len);
                if (cert_len>0)
                {
                    ((keyload_pke_wrap_t*)wrap_params)->cert_len = cert_len;
                    memCopy(((keyload_pke_wrap_t*)wrap_params)->cert, cert, cert_len);
                }
                break;
            //прочитать параметры защиты ключа в режиме PWD
            case CMD_KEYLOAD_TAG_PWD:

                if (!memIsValid(wrap_params, sizeof (keyload_pwd_wrap_t)))
                    return ERR_CMD_PARAMS;

                memSetZero(wrap_params, sizeof (keyload_pwd_wrap_t));

                if (!pwd)
                    return ERR_CMD_PARAMS;
                ((keyload_pwd_wrap_t*) wrap_params)->pwd_len = strLen(pwd);
                memCopy(((keyload_pwd_wrap_t*) wrap_params)->pwd, pwd,
                        ((keyload_pwd_wrap_t*) wrap_params)->pwd_len);

                if (iter == 0)
                    iter = 10000;

                ((keyload_pwd_wrap_t*) wrap_params)->iter = iter;
                break;
            default:
                return ERR_CMD_PARAMS;
        }
    }

    //обработать аргументы расшифрованиия
    if (strEq(command, ARG_DEC))
    {
        if (argc != 2)
            return ERR_CMD_PARAMS;

        strCopy(file, argv[0]);
        strCopy(new_file, argv[1]);

        code = aeadCreateKeyloadUnwrapParams(unwrap_params, (*keyload_type)->tag, pwd,
                                             privkey, privkey_len);
        ERR_CALL_CHECK(code);
    }

    //обработать аргументы валидации
    if (strEq(command, ARG_VAL))
    {
        strCopy(file, argv[0]);

        code = aeadCreateKeyloadUnwrapParams(unwrap_params, (*keyload_type)->tag, pwd,
                                             privkey, privkey_len);
        ERR_CALL_CHECK(code);

        switch ((*keyload_type)->tag)
        {
            case CMD_KEYLOAD_TAG_PKE:
                if (memIsValid(wrap_params, sizeof (keyload_pke_t)))
                    memSetZero(wrap_params, sizeof (keyload_pke_t));
                if (cert_len > 0)
                {
                    ASSERT(memIsValid(wrap_params, sizeof (keyload_pke_t)));
                    ((keyload_pke_wrap_t*)wrap_params)->cert_len = cert_len;
                    memCopy(((keyload_pke_wrap_t*)wrap_params)->cert, cert, cert_len);
                }
                break;
        }
    }

    return ERR_OK;
}



/*
*******************************************************************************
Генерация случайной последовательно октетов
*******************************************************************************
*/
static err_t aeadGen(octet* key, size_t size)
{
    err_t code;
    if (!rngIsValid()) {
        code = cmdRngStart(1);
        ERR_CALL_CHECK(code)
        // ERR_CALL_CHECK(cmdRngTest())
    }
    rngStepR(key, size, 0);

    return ERR_OK;
}

/*
*******************************************************************************
  Шифрование
*******************************************************************************
*/
static err_t aeadEnc(int argc, char* argv[])
{

    char file_name[FILENAME_MAX];
    char enc_file_name[FILENAME_MAX];
    char adata_name[FILENAME_MAX];
    err_t code;
    size_t itag = 0;
    const cmd_keyload_t* keyload;
    octet wrap[1024];
	char* files = {enc_file_name};

    ASSERT(sizeof (wrap) >= sizeof (keyload_pke_wrap_t));
    ASSERT(sizeof (wrap) >= sizeof (keyload_pwd_wrap_t));

    memSetZero(wrap, sizeof (wrap));
    memSetZero(adata_name, sizeof (adata_name));

    //разбор командной строки
    code = aeadParseOptions(argc, (const char **) argv, &keyload,
                            wrap,0, &itag,file_name, enc_file_name,adata_name);

    ERR_CALL_CHECK(code);

    //проверить существование файла
    code = cmdFileValNotExist(1, &files);
    ERR_CALL_CHECK(code)

    switch (keyload->tag)
    {
        // сгенерировать соль
        case CMD_KEYLOAD_TAG_PWD:
        {
            keyload_pwd_t k;
            code = aeadGen(((keyload_pwd_wrap_t*)wrap)->salt, sizeof (k.salt));
            ERR_CALL_CHECK(code);
            break;
        }
    }

    //зашифровать
    return cmdAeadEncrypt(file_name, enc_file_name, itag,
                          keyload, wrap, memIsZero(adata_name, sizeof (adata_name)) ? 0 : adata_name);
}

/*
*******************************************************************************
  Расшифрование
*******************************************************************************
*/
static err_t aeadDec(int argc, char* argv[]) {
    err_t code;
    char file_name[FILENAME_MAX];
    char adata_name[FILENAME_MAX];
    char dec_file_name[FILENAME_MAX];
    const cmd_keyload_t* keyload;
    char *files = {dec_file_name};

    octet unwrap[1024];

    ASSERT(sizeof (unwrap) >= sizeof (keyload_pke_unwrap_t));
    ASSERT(sizeof (unwrap) >= sizeof (keyload_pwd_unwrap_t));

    memSetZero(unwrap, sizeof (unwrap));

    memSetZero(adata_name, sizeof (adata_name));

    // разобрать командную строку
    code = aeadParseOptions(argc, (const char **) argv, &keyload, 0,unwrap,
                            0,file_name, dec_file_name,adata_name);
    ERR_CALL_CHECK(code)

    //проверить существование файла
    code = cmdFileValNotExist(1, &files);
    ERR_CALL_CHECK(code)

    //расшифровать
    return cmdAeadDecrypt(file_name, dec_file_name,
                         keyload, unwrap, memIsZero(adata_name, sizeof (adata_name)) ? 0 : adata_name);
}
/*
*******************************************************************************
Валидация
*******************************************************************************
*/
static err_t aeadVal(int argc, char* argv[]){

    err_t code;
    char file[FILENAME_MAX];
    octet key[CMD_AEAD_KEY_SIZE];
    size_t cert_len;
    cmd_aeadhead_t header;
    const cmd_keyload_t* keyload;
    octet wrap[1024];
    octet unwrap[1024];

    ASSERT(sizeof (unwrap) >= sizeof (keyload_pke_unwrap_t));
    ASSERT(sizeof (unwrap) >= sizeof (keyload_pwd_unwrap_t));
    ASSERT(sizeof (wrap) >= sizeof (keyload_pke_wrap_t));
    ASSERT(sizeof (wrap) >= sizeof (keyload_pwd_wrap_t));

    memSetZero(wrap, sizeof (wrap));
    memSetZero(unwrap, sizeof (unwrap));
    // разобрать командную строку
    code = aeadParseOptions(argc, (const char **) argv, &keyload,
                            wrap,unwrap,0,file, 0,0);
    ERR_CALL_CHECK(code)

    //прочитать заголовок
    code = cmdAeadHeaderRead(0, 0, &header,
                             keyload, (const char *) file);
    if (code != ERR_OK)
        return ERR_BAD_FILE;

    //снять защиту ключа
    code = cmdAeadUnwrapKey(header.keyload, keyload,
                            (octet *) &unwrap, key);
    if (code != ERR_OK)
        return ERR_BAD_FILE;

    switch (keyload->tag)
    {
        // дополнительная проверка PKE
        case CMD_KEYLOAD_TAG_PKE :
            cert_len = ((keyload_pke_wrap_t*) wrap)->cert_len;

            // сертификат не проверяется
            if (cert_len == 0)
                break;

            //длины сертификатов не совпадают
            if (cert_len != ((keyload_pke_t*)header.keyload)->cert_len)
                return ERR_BAD_CERT;

            //сертификаты не совпадают
            if (!memEq(
                    ((keyload_pke_wrap_t*) wrap)->cert,
                    ((keyload_pke_t*)header.keyload)->cert,
                    cert_len)
                    ) return ERR_BAD_CERT;
            break;
    }

    return ERR_OK;
}


/*
*******************************************************************************
  Главная функция
*******************************************************************************
*/
static int aeadMain(int argc, char* argv[])
{
    err_t code;
    if (argc < 3)
        return aeadUsage();

    --argc;
    ++argv;

    if (strEq(argv[0], ARG_ENC))
        code = aeadEnc(argc, argv);
    else if (strEq(argv[0], ARG_DEC))
        code = aeadDec(argc, argv);
    else if (strEq(argv[0], ARG_VAL))
        code = aeadVal(argc, argv);
    else
        return aeadUsage();

    printf("bee2cmd/%s: %s\n", _name, errMsg(code));

    return code == ERR_OK ? 0 : 1;
}

err_t aeadInit()
{
    return cmdReg(_name, _descr, aeadMain);
}