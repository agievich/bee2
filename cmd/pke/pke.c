#include <stdlib.h>
#include <stdio.h>
#include "../cmd.h"
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
#define ARG_PASS "-pass"
#define ARG_PUBKEY "-pubkey"
#define ARG_PRIVKEY "-privkey"
#define ARG_CERT "-cert"
#define ARG_ITAG "--itag"


#if !defined FILENAME_MAX
#define FILENAME_MAX 1024
#endif

#define BLOCK_SIZE 4096

static const char _name[] = "pke";
static const char _descr[] = "public key encryption";

/*
*******************************************************************************
Справка по использованию
*******************************************************************************
*/
static int pkeUsage() {
    printf(
            "bee2cmd/%s: %s\n"
            "Usage:\n"
            "  bee2cmd %s %s {%s <pubkey> | %s <cert>} [%s] <file> <enc_file>\n"
            "    encrypt <file> and save it to <enc_file>\n"
            "    options:\n"
            "    %s <pubkey> -- recipient's public key\n"
            "    %s <cert> -- recipient's certificate\n"
            "    %s -- period of intermediate mac\n"
            "  bee2cmd %s %s [%s <scheme>] <privkey> <enc_file> <dec_file>\n"
            "    decrypt <file> and save to <dec_file>\n"
            "    options:\n"
            "    %s <scheme> -- scheme of the private key password\n"
            "  bee2cmd %s %s [%s <cert> | %s <scheme> %s <privkey>] <file>\n"
            "    verify the encrypted <file> is destined for you\n"
            "    options:\n"
            "    %s <cert> -- recipient's certificate. Validate that file certificate\n"
            "                 matches the recipient's one (if file contains it).\n"
            "    %s <scheme> -- scheme of the recipient's private key password. Must be passed before %s arg\n"
            "    %s <privkey> -- recipient's private key container. Validate that file was encrypted\n"
            "                    with the corresponding recipient's public key\n"
            ,
            _name, _descr,
            _name, ARG_ENC, ARG_PUBKEY, ARG_CERT, ARG_ITAG,
            ARG_PUBKEY, ARG_CERT, ARG_ITAG,
            _name, ARG_DEC, ARG_PASS,
            _name, ARG_VAL, ARG_CERT, ARG_PASS, ARG_PRIVKEY,
            ARG_CERT, ARG_PASS, ARG_PRIVKEY, ARG_PRIVKEY,
            ARG_PASS
    );

    return -1;
}

/*
*******************************************************************************
 Разбор опций командной строки

 Опции возвращаются по адресам
 pubkey [pubkey_len],
 itag,
 privkey [privkey_len],
 anchor_cert [anchor_cert_len],
 certs, has_certs
 file, enc_file, dec_file
 Любой из адресов может быть нулевым, и тогда соответствующая опция не возвращается.
 Более того, ее указаниев командной строке считается ошибкой.

 В случае успеха по адресу readc возвращается число обработанных аргументов.
*******************************************************************************
*/
static err_t pkeParseOptions(
        int argc,
        const char* argv[],
        octet* pubkey,
        size_t * pubkey_len,
        size_t* itag,
        octet* privkey,
        size_t* privkey_len,
        char* cert,
        bool_t* has_cert,
        char* file,
        char* enc_file,
        char* dec_file
) {

    cmd_pwd_t pwd;
    bool_t pwd_provided = FALSE;
    size_t m_pubkey_len;
    size_t m_privkey_len;
    char s_pubkey[257];

    if (has_cert)
        *has_cert = FALSE;

    if (privkey_len)
        *privkey_len = 0;

    if (pubkey_len)
        *pubkey_len = 0;

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

        // прочитать схему защиты личного ключа
        if (strEq(*argv, ARG_PASS))
        {
            if ((cmdPwdRead(&pwd, argv[1]) != ERR_OK))
                return ERR_CMD_PARAMS;
            pwd_provided = TRUE;
        }

        // прочитать личный ключ
        if (strEq(*argv, ARG_PRIVKEY))
        {
            m_privkey_len = 0;
            if (!pwd_provided)
                return ERR_CMD_PARAMS;
            if (cmdPrivkeyRead(privkey,&m_privkey_len, argv[1], pwd) != ERR_OK)
                return ERR_CMD_PARAMS;
            if (memIsValid(privkey_len, sizeof (size_t)))
                *privkey_len = m_privkey_len;
        }

        // прочитать открытый ключ
        if (strEq(*argv, ARG_PUBKEY))
        {
            if (!pubkey)
                return ERR_CMD_PARAMS;

            FILE *fp = fopen(argv[1], "rb");
            if (!fp)
            {
                printf("ERROR: failed to open public key file '%s'\n", argv[1]);
                return ERR_FILE_OPEN;
            }

            m_pubkey_len = fread(s_pubkey, 1, 256, fp);
            fclose(fp);

            switch (m_pubkey_len) {
                case 128:
                case 129:
                    s_pubkey[128] = '\0';
                    break;
                case 192:
                case 193:
                    s_pubkey[192] = '\0';
                    break;
                case 256:
                case 257:
                    s_pubkey[256] = '\0';
                    break;
                default:
                    return ERR_BAD_PUBKEY;
            }

            hexTo(pubkey, s_pubkey);

            if (memIsValid(pubkey_len, sizeof(size_t)))
                *pubkey_len = m_pubkey_len / 2;
        }

        // прочитать сертификаты
        if (strEq(*argv, ARG_CERT))
        {
            if (!memIsValid(cert, strLen(argv[1])))
                return ERR_CMD_PARAMS;

            if (has_cert)
                *has_cert = TRUE;

            memCopy(cert, argv[1], strLen(argv[1]));
        }

        //прочитать частоту имитовставок
        if (strStartsWith(*argv, ARG_ITAG)) {
            if (!memIsValid(itag, sizeof(size_t)))
                return ERR_CMD_PARAMS;
            *itag = strtoul(*argv + strLen(ARG_ITAG), 0, 10);
            argv-=1;
            argc+=1;
        }

        argv+=2;
        argc-=2;
    }

    if (strEq(command, ARG_ENC))
    {
        if (argc != 2)
            return ERR_CMD_PARAMS;

        strCopy(file, argv[0]);
        strCopy(enc_file, argv[1]);
    }

    if (strEq(command, ARG_DEC))
    {
        if (argc != 3)
            return ERR_CMD_PARAMS;

        if (!memIsValid(privkey, 64))
            return ERR_CMD_PARAMS;

        m_privkey_len = 0;
        if (!pwd_provided)
            return ERR_CMD_PARAMS;

        if(cmdPrivkeyRead(privkey, &m_privkey_len, argv[0], pwd) != ERR_OK)
            return ERR_CMD_PARAMS;

        if (memIsValid(privkey_len, sizeof (size_t)))
            *privkey_len = m_privkey_len;

        strCopy(file, argv[1]);
        strCopy(dec_file, argv[2]);
    }

    if (strEq(command, ARG_VAL))
    {
        strCopy(file, argv[0]);
    }

    return ERR_OK;
}

/*
*******************************************************************************
Генерация случайной последовательно октетов
*******************************************************************************
*/
static err_t pkeGen(octet* key, size_t size)
{
    if (!rngIsValid()) {
        ERR_CALL_CHECK(cmdRngStart(1))
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
static err_t pkeEnc(int argc, char* argv[])
{

    char file_name[FILENAME_MAX];
    char enc_file_name[FILENAME_MAX];
    char cert_name[FILENAME_MAX];
    err_t code;
    size_t itag = 0;
    bool_t has_cert = FALSE;
    octet key[32];
    octet *state;
    size_t block_size;
    size_t count;
    octet *buf;
    octet mac[8];
    FILE *fp;
    FILE *enc_fp;
    cmd_pkehead_t pke;
    size_t file_size;
    size_t total_readed = 0;
    keyload_pke_wrap_t wrap;

    code = pkeParseOptions(argc, (const char **) argv, wrap.pubkey,
                           &wrap.pubkey_len, &itag, 0, 0,cert_name,
                           &has_cert, file_name, enc_file_name, 0);
    ERR_CALL_CHECK(code)

    if (has_cert)
        cmdFileRead(wrap.cert, &wrap.cert_len, cert_name);
    else
        wrap.cert_len = 0;

    pke.keyload_id = CMD_KEYLOAD_ID_PKE;
    pke.itag = itag;

    char *files = {enc_file_name};
    code = cmdFileValNotExist(1, &files);
    ERR_CALL_CHECK(code)

    file_size = cmdFileSize(file_name);

    block_size = itag ? itag : BLOCK_SIZE;
    ERR_CALL_CHECK(code)

    code = pkeGen(key, sizeof(key));
    ERR_CALL_CHECK(code)

    code = pkeGen(pke.iv, sizeof(pke.iv));
    ERR_CALL_CHECK(code)

    code = cmdPkeWrapKey(pke.keyload,pke.keyload_id,(octet *) &wrap,key);
    ERR_CALL_CHECK(code)

    code = cmdPkeHeaderWrite(0, &pke, enc_file_name);
    ERR_CALL_CHECK(code)

    state = blobCreate(beltCHE_keep());
    if (!state)
        return ERR_OUTOFMEMORY;

    fp = fopen(file_name, "rb");
    if (!fp)
        return ERR_FILE_NOT_FOUND;

    enc_fp = fopen(enc_file_name, "ab");
    if (!enc_fp)
    {
        fclose(fp);
        return ERR_FILE_WRITE;
    }

    buf = blobCreate(block_size);
    if (!buf)
    {
        blobClose(state);
        return ERR_OUTOFMEMORY;
    }

    beltCHEStart(state, key, sizeof(key), pke.iv);

    while (total_readed < file_size)
    {
        count = fread(buf, 1, block_size, fp);
        total_readed+=count;

        if (count == 0)
        {
            if (ferror(fp))
            {
                printf("%s: FAILED [read]\n", file_name);
                code = ERR_FILE_READ;
                goto final;
            }
            break;
        }

        beltCHEStepE(buf, count, state);
        beltCHEStepA(buf, count, state);

        if (fwrite(buf, 1, count, enc_fp) != count)
        {
            code = ERR_OUTOFMEMORY;
            goto final;
        }
        if (itag && total_readed != file_size)
        {
            beltCHEStepG(mac, state);
            if (fwrite(mac, 1, sizeof (mac), enc_fp) != sizeof (mac))
            {
                code = ERR_OUTOFMEMORY;
                goto final;
            }
        }
    }
    beltCHEStepG(mac, state);
    code = fwrite(mac, 1, sizeof(mac), enc_fp) == sizeof (mac)
            ? ERR_OK : ERR_OUTOFMEMORY;

final:
    fclose(fp);
    fclose(enc_fp);
    blobClose(buf);
    blobClose(state);
    return code;
}

/*
*******************************************************************************
  Расшифрование
*******************************************************************************
*/
static err_t pkeDec(int argc, char* argv[])
{
    err_t  code;
    octet key[CMD_PKE_KEY_SIZE];
    char file_name[FILENAME_MAX];
    char dec_file_name[FILENAME_MAX];
    size_t header_len;
    cmd_pkehead_t pke[1];
    FILE *fp;
    FILE *dec_fp;
    octet *state;
    octet * buf;
    size_t block_size;
    size_t count;
    octet mac[8];
    size_t file_size;
    size_t total_read = 0;
    keyload_pke_unwrap_t unwrap;

    code = pkeParseOptions(argc, (const char **) argv, 0, 0, 0, unwrap.privkey,
                           &unwrap.privkey_len,0, 0, file_name, 0, dec_file_name);
    ERR_CALL_CHECK(code)

    code = cmdPkeHeaderRead(&header_len, pke, (const char *) file_name);
    ERR_CALL_CHECK(code)

    code = cmdPkeUnwrapKey(pke->keyload, pke->keyload_id, (octet *) &unwrap,key);
    ERR_CALL_CHECK(code)

    block_size = pke->itag ?: BLOCK_SIZE;
    file_size = cmdFileSize(file_name) - header_len - sizeof (mac);

    fp = fopen((const char *) file_name, "rb");
    if (!fp)
        return ERR_FILE_NOT_FOUND;

    fseek(fp, (long) header_len, SEEK_SET);

    char* files = {dec_file_name};
    code = cmdFileValNotExist(1, &files);
    ERR_CALL_CHECK(code)

    dec_fp = fopen(dec_file_name, "wb");
    if (!dec_fp)
        return ERR_FILE_CREATE;

    state = blobCreate(beltCHE_keep());
    if (!state)
    {
        fclose(fp);
        fclose(dec_fp);
        return ERR_OUTOFMEMORY;
    }

    buf = blobCreate(block_size);
    if (!buf)
    {
        fclose(fp);
        fclose(dec_fp);
        blobClose(state);
        return ERR_OUTOFMEMORY;
    }

    beltCHEStart(state, key, sizeof (key), pke->iv);

    while (total_read < file_size)
    {
        count = fread(buf, 1, MIN2(block_size, file_size-total_read), fp);
        total_read += count;
        if (count == 0)
        {
            if (ferror(fp))
            {
                printf("%s: FAILED [read]\n", file_name);
                code =  ERR_FILE_READ;
                goto final;
            }
            break;
        }

        beltCHEStepA(buf, count, state);
        beltCHEStepD(buf, count, state);

        if (pke->itag && total_read != file_size)
        {
            if (fread(mac,1,sizeof (mac), fp) != sizeof (mac) ||
                    !beltCHEStepV(mac,state))
            {
                code = ERR_BAD_FILE;
                goto final;
            }
            total_read+=sizeof (mac);
        }
        if (fwrite(buf, 1, count, dec_fp) != count)
        {
            code = ERR_OUTOFMEMORY;
            goto final;
        }
    }

    if (fread(mac,1,sizeof (mac), fp) != sizeof (mac))
    {
        code = ERR_BAD_FILE;
        goto final;
    }

    code = beltCHEStepV(mac, state) ? ERR_OK : ERR_BAD_FILE;

final:
    fclose(fp);
    fclose(dec_fp);
    blobClose(buf);
    blobClose(state);

    return code;
}

/*
*******************************************************************************
Валидация
*******************************************************************************
*/
static err_t pkeVal(int argc, char* argv[]){

    err_t code;
    char file[FILENAME_MAX];
    char cert_file[FILENAME_MAX];
    octet key[CMD_PKE_KEY_SIZE];
    octet cert[SIG_MAX_CERT_SIZE];
    size_t cert_len;
    bool_t has_cert;
    cmd_pkehead_t header;
    keyload_pke_unwrap_t unwrap;

    code = pkeParseOptions(argc, (const char **) argv, 0, 0, 0, unwrap.privkey,
                           &unwrap.privkey_len, cert_file, &has_cert, file, 0, 0);
    ERR_CALL_CHECK(code)

    if (unwrap.privkey_len == 0 && !has_cert)
        return ERR_CMD_PARAMS;

    code = cmdPkeHeaderRead(0, &header, (const char *) file);
    ERR_CALL_CHECK(code)


    if (unwrap.privkey_len != 0) {
        code = cmdPkeUnwrapKey(header.keyload, header.keyload_id, (octet *) &unwrap, key);
        if (code != ERR_OK)
            return ERR_BAD_PRIVKEY;
    } else {
        if (header.keyload_id == CMD_KEYLOAD_ID_PKE){
            keyload_pke_t* kld = (keyload_pke_t*) header.keyload;
            unwrap.cert_len = kld->cert_len;
            memCopy(unwrap.cert, kld->cert, kld->cert_len);
        }
    }

    if (has_cert){
        code = cmdFileRead(cert, &cert_len, cert_file);
        ERR_CALL_CHECK(code)

        if (cert_len != unwrap.cert_len || !memEq(cert, unwrap.cert, cert_len))
            return ERR_BAD_CERT;
    }

    return ERR_OK;
}


/*
*******************************************************************************
  Главная функция
*******************************************************************************
*/
static int pkeMain(int argc, char* argv[])
{
    err_t code;
    if (argc < 3)
        return pkeUsage();

    --argc;
    ++argv;

    if (strEq(argv[0], ARG_ENC))
        code = pkeEnc(argc, argv);
    else if (strEq(argv[0], ARG_DEC))
        code = pkeDec(argc, argv);
    else if (strEq(argv[0], ARG_VAL))
        code = pkeVal(argc, argv);
    else
        return pkeUsage();

    printf("bee2cmd/%s: %s\n", _name, errMsg(code));

    return code == ERR_OK ? 0 : 1;
}

err_t pkeInit()
{
    return cmdReg(_name, _descr, pkeMain);
}