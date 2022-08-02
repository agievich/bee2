#include <stdio.h>
#include <bee2/core/err.h>
#include <bee2/core/blob.h>
#include <bee2/core/util.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include "../cmd.h"

#define SIG_MAX_CERTS 16
#define SIG_MAX_CERT_SIZE 512
#define SIG_MAX_DER SIG_MAX_CERTS * SIG_MAX_CERT_SIZE + 96 + 16
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
    octet certs[SIG_MAX_CERTS * SIG_MAX_CERT_SIZE];
    size_t cert_lens[SIG_MAX_CERTS];
    err_t code;
    bool_t has_certs;

    memSetZero(file_name, sizeof(file_name));
    memSetZero(sig_file_name, sizeof(sig_file_name));
    memSetZero(certs_names, sizeof(certs_names));

    code = sigParseOptions(argc, argv, privkey, &privkey_len,0, 0, 0,0,
                           file_name,sig_file_name, certs_names, &has_certs);
    ERR_CALL_CHECK(code)

    if (has_certs)
    {
        code = sigReadCerts(certs_names, certs, cert_lens);
        ERR_CALL_CHECK(code)
    } else
    {
        memSetZero(cert_lens, sizeof (cert_lens));
    }

    code = cmdSigSign(sig, privkey, privkey_len, has_certs ? certs : 0, cert_lens, file_name);
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
    octet certs[SIG_MAX_CERTS * SIG_MAX_CERT_SIZE];
    char sig_file_name[256];
    char cert_names[256 * SIG_MAX_CERTS];
    size_t cert_names_len;
    char sigHex[96*2 + 1];
    bool_t has_certs;
    size_t sig_certs_count;

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
        sig_certs_count =0;
        for (int i=0;i<SIG_MAX_CERTS;i++){
            if (sig->certs_len[i] != 0)
                sig_certs_count++;
        }

        if (certs_cnt != sig_certs_count)
        {
            printf("WARNING: certificates extraction failed. Signature has %lu certificates, but %lu output files given\n",
                   sig_certs_count, certs_cnt);
        } else
        {
            code = sigWriteCerts(cert_names, certs, sig->certs_len, sig_certs_count);
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


err_t sigInit()
{
    return cmdReg(_name, _descr, sigMain);
}