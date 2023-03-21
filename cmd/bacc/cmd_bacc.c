#include <stdio.h>
#include "bee2/crypto/bacc.h"
#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/prng.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/core/dec.h"
#include "bee2/core/rng.h"
#include "../cmd.h"

static const char _name[] = "bacc";
static const char _descr[] = "blind accumulator";

/*
*******************************************************************************
Справка по использованию
*******************************************************************************
*/
static int baccUsage()
{
    printf(
        "bee2cmd/%s: %s\n"
        "Usage:\n"
        "  bacc init [-lNNN] <acc>\n"
        "    initialize accumulator with NNN security level\n\n"
        "  bacc add -pass <scheme> <privkey> <acc>\n"
        "    add <privkey> to the accumulator <acc>. Private keys must have the same security level\n\n"
        "  bacc prvadd -pass <scheme> <privkey> <old_acc> <new_acc> <proof>\n"
        "    create <proof> that <new_acc> is the result of <privkey> addition to the <old_acc>\n\n"
        "  bacc vfyadd <proof> <old_acc> <new_acc>\n"
        "    verify that <new_acc> is constructed by adding privkey to the <old_acc>\n\n"
        "  bacc der -pass <scheme> <privkey> <acc> <pubkey>\n"
        "    create <pubkey> related to <privkey> added to <acc>\n\n"
        "  bacc prvder [-adata <adata>] -pass <scheme> <privkey> <acc> <proof>\n"
        "    create <proof> that pubkey from der is related to some <privkey> added to the <acc>.\n\n"
        "  bacc vfyder [-adata <adata>] <pubkey> <acc> <proof>\n"
        "    verify that some private key related to the <pubkey> was added to the <acc>\n"
        "  .\n"
        "  <privkey>\n"
        "    container with a private key\n"
        "  <pubkey>\n"
        "    file with a public key\n"
        "  <acc>, <new_acc>, <old_acc>\n"
        "    files with accumulator\n"
        "  <proof>\n"
        "    file with proof of accumulator modification or private key presence\n"
        "  options:\n"
        "    -lNNN -- security level (128/192/256)\n"
        "    -pass <scheme> -- password description\n"
        "    -adata <adata> -- file with additional data linked to proof. Proof becomes a signature of <adata>\n",
        _name, _descr
    );
    return -1;
}

static err_t baccCreate(int argc, char* argv[])
{
    octet a[128 + sizeof (u32)];
    u32 len = 0;
    err_t code = ERR_OK;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (strStartsWith(*argv, "-l"))
        {
            char* str = *argv + strLen("-l");
            if (len)
            {
                code = ERR_CMD_DUPLICATE;
                break;
            }
            if (!decIsValid(str) || decCLZ(str) || strLen(str) != 3 ||
                (len = (size_t)decToU32(str)) % 64 || len < 128 || len > 256)
            {
                code = ERR_CMD_PARAMS;
                break;
            }
            ++argv, --argc;
        }
        else
        {
            code = ERR_CMD_PARAMS;
            break;
        }
    }
    if (len == 0)
        len = 128;

    if (code != ERR_OK || argc != 1)
        return ERR_CMD_PARAMS;

    memCopy(a, &len, sizeof (u32));

    if (!rngIsValid())
    {
        code = cmdRngStart(0);
        ERR_CALL_CHECK(code);
    }

    code  = baccDHInit(a + sizeof (u32), len, rngStepR, 0);
    ERR_CALL_CHECK(code);

    return cmdFileWrite(*argv, a, len/2 + sizeof(u32));
}

static err_t baccAdd(int argc, char* argv[])
{

    size_t acc_size;
    size_t privkey_len;
    octet key[64];
    u32 l;
    octet *acc;
    size_t acc_len;
    err_t code = ERR_OK;
    cmd_pwd_t pwd = 0;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (argc < 2)
        {
            code = ERR_CMD_PARAMS;
            break;
        }
        else if (strStartsWith(*argv, "-pass"))
        {
            if (pwd)
            {
                code = ERR_CMD_DUPLICATE;
                break;
            }
            ++argv, --argc;
            ASSERT(argc > 0);
            code = cmdPwdRead(&pwd, *argv);
            if (code != ERR_OK)
                break;
            ASSERT(cmdPwdIsValid(pwd));
            ++argv, --argc;
        }
        else
        {
            code = ERR_CMD_PARAMS;
            break;
        }
    }

    ERR_CALL_HANDLE(code, cmdPwdClose(pwd));

    if (!pwd || argc != 2)
        return ERR_CMD_PARAMS;

    //прочитать личный ключ
    privkey_len = 0;
    code = cmdPrivkeyRead(key, &privkey_len, argv[0], pwd);
    cmdPwdClose(pwd);
    ERR_CALL_CHECK(code);
    argv++;

    //прочитать l
    code = cmdFileRead((octet *) &l, sizeof (u32), *argv);
    ERR_CALL_CHECK(code);


    if (l != 128 && l != 192 && l != 256)
        return ERR_BAD_INPUT;

    if (privkey_len * 4 != l)
        return ERR_BAD_PRIVKEY;

    //размер аккумулятора
    acc_size = cmdFileSize(*argv);
    if (acc_size == SIZE_MAX)
        return ERR_FILE_READ;
    acc_len = (acc_size- sizeof (u32)) / (baccGq_keep(l));

    //память под аккумулятор
    code = cmdBlobCreate(acc, baccDHAdd_keep(l, acc_len));
    ERR_CALL_CHECK(code);
    //прочитать аккумулятор
    code = cmdFileRead(acc, acc_size, *argv);
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    //добавить ключ
    code = baccDHAdd(l, acc + sizeof (u32), &acc_len, key);
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    //обновить аккумулятор
    code = cmdFileWrite(*argv, acc, sizeof (u32) + acc_len * baccGq_keep(l));

    cmdBlobClose(acc);

    return code;
}

static err_t baccPrvAdd(int argc, char* argv[])
{

    err_t code = ERR_OK;
    u32 l;
    octet key[64];
    octet *acc, *acc_new, *proof;
    size_t privkey_len, acc_size, acc_new_size;
    size_t acc_len, acc_new_len;

    cmd_pwd_t pwd = 0;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (argc < 2)
        {
            code = ERR_CMD_PARAMS;
            break;
        }
        else if (strStartsWith(*argv, "-pass"))
        {
            if (pwd)
            {
                code = ERR_CMD_DUPLICATE;
                break;
            }
            ++argv, --argc;
            ASSERT(argc > 0);
            code = cmdPwdRead(&pwd, *argv);
            if (code != ERR_OK)
                break;
            ASSERT(cmdPwdIsValid(pwd));
            ++argv, --argc;
        }
        else
        {
            code = ERR_CMD_PARAMS;
            break;
        }
    }

    ERR_CALL_HANDLE(code, cmdPwdClose(pwd));

    if (!pwd || argc != 4)
    {
        return ERR_CMD_PARAMS;
    }

    // прочитать личный ключ
    privkey_len = 0;
    code = cmdPrivkeyRead(key, &privkey_len, *argv, pwd);
    cmdPwdClose(pwd);
    ERR_CALL_CHECK(code);

    // прочитать l
    code = cmdFileRead((octet *) &l, sizeof(l), *(argv + 1));
    ERR_CALL_CHECK(code);

    if (l != 128 && l != 192 && l != 256)
        return ERR_BAD_INPUT;

    if (privkey_len * 4 != l)
        return ERR_BAD_PRIVKEY;

    //размер аккумулятора
    acc_size = cmdFileSize(*(argv + 1));
    if (acc_size == SIZE_MAX)
        return ERR_FILE_READ;

    //память под аккумулятор
    code = cmdBlobCreate(acc, acc_size);
    ERR_CALL_CHECK(code);

    //прочитать аккумулятор
    code = cmdFileRead(acc, acc_size, *(argv + 1));
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    //длина нового аккумулятора
    acc_new_size = cmdFileSize(*(argv + 2));
    if (acc_new_size == SIZE_MAX)
        ERR_CALL_HANDLE(ERR_FILE_READ, cmdBlobClose(acc))

    //память под новый аккумулятор
    code = cmdBlobCreate(acc_new,acc_new_size);
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    //прочитать новый аккумулятор
    code = cmdFileRead(acc_new, acc_new_size, *(argv + 2));
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(acc_new)))

    acc_len = (acc_size - sizeof (u32)) / (baccGq_keep(l));
    acc_new_len = (acc_new_size - sizeof (u32)) / (baccGq_keep(l));

    //память под proof
    cmdBlobCreate(proof,baccDHPrvAdd_keep(l, acc_len));
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(acc_new)));

    // инициализации ГСЧ
    if (!rngIsValid())
    {
        code = cmdRngStart(0);
        ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(acc_new)));
    }

    //создать proof
    code = baccDHPrvAdd(
            proof, l,
            acc + sizeof(u32), acc_new + sizeof (u32),
            acc_len, acc_new_len,
            key, rngStepR, 0);
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(acc_new)));

    code = cmdFileValNotExist(1,(argv + 3));
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(acc_new)));

    //записать proof в файл
    code = cmdFileWrite(*(argv + 3), proof, baccDHPrvAdd_keep(l, acc_len));

    cmdBlobClose(acc);
    cmdBlobClose(acc_new);
    cmdBlobClose(proof);

    return code;
}

static err_t baccVfyAdd(int argc, char* argv[])
{
    err_t code;
    u32 l;
    octet *acc, *acc_new, *proof,  *stack;
    size_t acc_size, acc_new_size, proof_size;
    size_t acc_len, acc_new_len;

    if (argc != 3)
        return ERR_CMD_PARAMS;

    // прочитать l
    code = cmdFileRead((octet *) &l, sizeof(l), *(argv + 1));
    ERR_CALL_CHECK(code);

    if (l != 128 && l != 192 && l != 256)
        return ERR_BAD_INPUT;

    //размер аккумулятора
    acc_size = cmdFileSize(*(argv + 1));
    if (acc_size == SIZE_MAX)
        return ERR_FILE_READ;

    //память под аккумулятор
    code = cmdBlobCreate(acc,acc_size);
    ERR_CALL_CHECK(code);

    //прочитать аккумулятор
    code = cmdFileRead(acc, acc_size, *(argv + 1));
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    //длина нового аккумулятора
    acc_new_size = cmdFileSize(*(argv+2));
    if (acc_new_size == SIZE_MAX)
        ERR_CALL_HANDLE(ERR_FILE_READ, cmdBlobClose(acc))

    //память под новый аккумулятор
    code= cmdBlobCreate(acc_new,acc_new_size);
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    //прочитать новый аккумулятор
    code = cmdFileRead(acc_new, acc_new_size, *(argv + 2));
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(acc_new)))

    acc_len = (acc_size - sizeof (u32)) / (baccGq_keep(l));
    acc_new_len = (acc_new_size - sizeof (u32)) / (baccGq_keep(l));

    //длина proof
    proof_size = cmdFileSize(*(argv));
    if (proof_size == SIZE_MAX)
        ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(acc_new)));

    //память под proof
    code = cmdBlobCreate(proof,proof_size);
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc), cmdBlobClose(acc_new)));

    code = cmdFileRead(proof, proof_size, *(argv));
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc), cmdBlobClose(acc_new), cmdBlobClose(proof)));

    code = cmdBlobCreate(stack,baccDHVfyAdd_deep(l, acc_len));
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc), cmdBlobClose(acc_new), cmdBlobClose(proof)));

    //проверить proof
    code = baccDHVfyAdd(
            l, proof,
            acc + sizeof(u32), acc_new + sizeof (u32),
            acc_len, acc_new_len,
            stack);
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc), cmdBlobClose(acc_new), cmdBlobClose(proof)));

    cmdBlobClose(acc);
    cmdBlobClose(acc_new);
    cmdBlobClose(proof);
    cmdBlobClose(stack);

    return code;
}

static err_t baccDer(int argc, char* argv[]){
    err_t code;
    u32 l;
    octet privkey[64];
    octet pubkey[128];
    octet *acc;
    size_t privkey_len, acc_size;
    size_t acc_len;

    cmd_pwd_t pwd = 0;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (argc < 2)
        {
            code = ERR_CMD_PARAMS;
            break;
        }
        else if (strStartsWith(*argv, "-pass"))
        {
            if (pwd)
            {
                code = ERR_CMD_DUPLICATE;
                break;
            }
            ++argv, --argc;
            ASSERT(argc > 0);
            code = cmdPwdRead(&pwd, *argv);
            if (code != ERR_OK)
                break;
            ASSERT(cmdPwdIsValid(pwd));
            ++argv, --argc;
        }
        else
        {
            code = ERR_CMD_PARAMS;
            break;
        }
    }

    ERR_CALL_HANDLE(code, cmdPwdClose(pwd));

    if (!pwd || argc != 3)
    {
        return ERR_CMD_PARAMS;
    }

    // прочитать личный ключ
    privkey_len = 0;
    code = cmdPrivkeyRead(privkey, &privkey_len, *argv, pwd);
    cmdPwdClose(pwd);
    ERR_CALL_CHECK(code);

    //инициализация ГСЧ
    if (!rngIsValid())
    {
        code = cmdRngStart(1);
        ERR_CALL_CHECK(code);
    }

    // прочитать l
    code = cmdFileRead((octet *) &l, sizeof(l), *(argv + 1));
    ERR_CALL_CHECK(code);

    if (l != 128 && l != 192 && l != 256)
        return ERR_BAD_INPUT;

    if (privkey_len * 4 != l)
        return ERR_BAD_PRIVKEY;

    //размер аккумулятора
    acc_size = cmdFileSize(*(argv + 1));
    if (acc_size == SIZE_MAX)
        return ERR_FILE_READ;
    acc_len = (acc_size - sizeof (u32)) / (baccGq_keep(l));

    //память под аккумулятор
    code = cmdBlobCreate(acc,acc_size);
    ERR_CALL_CHECK(code);

    //прочитать аккумулятор
    code = cmdFileRead(acc, acc_size, *(argv + 1));
    ERR_CALL_CHECK(code);
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    // создать открытый ключ
    if (baccDHDer(pubkey, l, acc + sizeof (u32), acc_len, privkey) == SIZE_MAX)
        ERR_CALL_HANDLE(ERR_BAD_PRIVKEY, cmdBlobClose(acc));

    code = cmdFileValNotExist(1,(argv + 2));
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    //записать ключ в файл
    code = cmdFileWrite(*(argv+2), pubkey, l / 2);

    cmdBlobClose(acc);

    return code;
}

static err_t baccPrvDer(int argc, char* argv[]){
    err_t code;
    u32 l;
    octet privkey[64];
    octet *acc, *proof, *adata = 0;
    size_t privkey_len, acc_size, adata_size = 0;
    size_t acc_len;
    octet *stack;

    cmd_pwd_t pwd = 0;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (argc < 2)
        {
            code = ERR_CMD_PARAMS;
            break;
        }
        else if (strStartsWith(*argv, "-pass"))
        {
            if (pwd)
            {
                code = ERR_CMD_DUPLICATE;
                break;
            }
            ++argv, --argc;
            ASSERT(argc > 0);
            code = cmdPwdRead(&pwd, *argv);
            if (code != ERR_OK)
                break;
            ASSERT(cmdPwdIsValid(pwd));
            ++argv, --argc;
        }
        else if (strStartsWith(*argv, "-adata"))
        {
            if (adata)
            {
                code = ERR_CMD_DUPLICATE;
                break;
            }
            ++argv, --argc;
            ASSERT(argc > 0);
            code = cmdFileReadAll(0, &adata_size,*argv);
            if (code != ERR_OK)
                break;

            if (adata_size > 0)
            {
                code = cmdBlobCreate(adata, adata_size);
                if (code != ERR_OK)
                    break;
                code = cmdFileReadAll(adata, &adata_size,*argv);
                if (code != ERR_OK)
                {
                    cmdBlobClose(adata);
                    break;
                }
            }

            ++argv, --argc;
        }
        else
        {
            code = ERR_CMD_PARAMS;
            break;
        }
    }

    ERR_CALL_HANDLE(code, (cmdPwdClose(pwd), cmdBlobClose(adata)));

    if (!pwd || argc != 3)
    {
        return ERR_CMD_PARAMS;
    }

    // прочитать личный ключ
    privkey_len = 0;
    code = cmdPrivkeyRead(privkey, &privkey_len, *argv, pwd);
    cmdPwdClose(pwd);
    ERR_CALL_CHECK(code);

    // прочитать l
    code = cmdFileRead((octet *) &l, sizeof(l), *(argv + 1));
    ERR_CALL_CHECK(code);

    if (l != 128 && l != 192 && l != 256)
        ERR_CALL_HANDLE(ERR_BAD_INPUT,cmdBlobClose(adata));

    if (privkey_len * 4 != l)
        ERR_CALL_HANDLE(ERR_BAD_PRIVKEY,cmdBlobClose(adata));

    //размер аккумулятора
    acc_size = cmdFileSize(*(argv + 1));
    if (acc_size == SIZE_MAX)
        ERR_CALL_HANDLE(ERR_FILE_READ,cmdBlobClose(adata));


    //память под аккумулятор
    code = cmdBlobCreate(acc,acc_size);
    ERR_CALL_HANDLE(code,cmdBlobClose(adata));

    //прочитать аккумулятор
    code = cmdFileRead(acc, acc_size, *(argv + 1));
    ERR_CALL_HANDLE(code, (cmdBlobClose(acc),cmdBlobClose(adata)));

    acc_len = (acc_size - sizeof (u32)) / (baccGq_keep(l));

    // инициализация ГСЧ
    if (!rngIsValid())
    {
        code = cmdRngStart(0);
        ERR_CALL_HANDLE(code, (cmdBlobClose(acc),cmdBlobClose(adata)));
    }

    //память под proof
    code = cmdBlobCreate(proof, baccDHPrvDer_keep(l, acc_len));
    ERR_CALL_HANDLE(code, (cmdBlobClose(acc),cmdBlobClose(adata)));

    //память под stack
    code = cmdBlobCreate(stack,baccDHPrvDer_deep(l, acc_len));
    ERR_CALL_HANDLE(code, (cmdBlobClose(acc),cmdBlobClose(adata),cmdBlobClose(proof)));

    //создать доказательство
    code = baccDHPrvDer(proof, l, acc + sizeof (u32), acc_len, privkey, adata,adata_size,rngStepR, 0, stack);
    cmdBlobClose(stack);
    ERR_CALL_HANDLE(code, (cmdBlobClose(acc),cmdBlobClose(adata),cmdBlobClose(proof)));

    code = cmdFileValNotExist(1,(argv + 2));
    ERR_CALL_HANDLE(code, (cmdBlobClose(acc),cmdBlobClose(adata),cmdBlobClose(proof)));

    //записать доказательство в файл
    code = cmdFileWrite(*(argv + 2), proof, baccDHPrvDer_keep(l, acc_len));

    cmdBlobClose(acc);
    cmdBlobClose(proof);
    cmdBlobClose(adata);

    return code;
}

static err_t baccVfyDer(int argc, char* argv[])
{
    err_t code;
    u32 l;
    octet pubkey[128];
    octet *acc, *proof, *adata = 0;
    size_t key_size, acc_size, proof_size, adata_size = 0;
    size_t acc_len;
    octet *stack;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (strStartsWith(*argv, "-adata"))
        {
            if (adata)
            {
                code = ERR_CMD_DUPLICATE;
                break;
            }
            ++argv, --argc;
            ASSERT(argc > 0);
            code = cmdFileReadAll(0, &adata_size, *argv);
            if (code != ERR_OK)
                break;

            if (adata_size > 0)
            {
                code = cmdBlobCreate(adata, adata_size);
                if (code != ERR_OK)
                    break;
                code = cmdFileReadAll(adata, &adata_size, *argv);
                if (code != ERR_OK)
                {
                    cmdBlobClose(adata);
                    break;
                }
            }
            ++argv, --argc;
        }
    }

    if (argc != 3)
        ERR_CALL_HANDLE(ERR_CMD_PARAMS,cmdBlobClose(adata));

    key_size = cmdFileSize(*(argv));
    if (key_size == SIZE_MAX)
        ERR_CALL_HANDLE(ERR_FILE_OPEN,cmdBlobClose(adata));

    // прочитать личный ключ
    code = cmdFileRead(pubkey, key_size, *(argv));
    ERR_CALL_HANDLE(code,cmdBlobClose(adata));

    // прочитать l
    code = cmdFileRead((octet *) &l, sizeof(l), *(argv + 1));
    ERR_CALL_HANDLE(code,cmdBlobClose(adata));

    if (l != 128 && l != 192 && l != 256)
        ERR_CALL_HANDLE(ERR_BAD_INPUT,cmdBlobClose(adata));

    if (key_size * 2 != l)
        ERR_CALL_HANDLE(ERR_BAD_PRIVKEY,cmdBlobClose(adata));

    //размер аккумулятора
    acc_size = cmdFileSize(*(argv+1));
    if (acc_size == SIZE_MAX)
        ERR_CALL_HANDLE(ERR_FILE_READ,cmdBlobClose(adata));

    //память под аккумулятор
    code = cmdBlobCreate(acc,acc_size);
    ERR_CALL_HANDLE(code,cmdBlobClose(adata));

    //прочитать аккумулятор
    code = cmdFileRead(acc, acc_size, *(argv+1));
    ERR_CALL_HANDLE(code, (cmdBlobClose(acc), cmdBlobClose(adata)));

    acc_len = (acc_size - sizeof (u32)) / (baccGq_keep(l));

    proof_size = cmdFileSize(*(argv+2));
    if (proof_size == SIZE_MAX)
        ERR_CALL_HANDLE(code,(cmdBlobClose(acc), cmdBlobClose(adata)));

    //память под proof
    code = cmdBlobCreate(proof,proof_size);
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc), cmdBlobClose(adata)));

    code = cmdFileRead(proof, proof_size, *(argv+2));
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(adata), cmdBlobClose(proof)));

    code = cmdBlobCreate(stack,baccDHVfyDer_deep(l, acc_len));
    ERR_CALL_HANDLE(code,(cmdBlobClose(acc),cmdBlobClose(adata), cmdBlobClose(proof)));

    code = baccDHVfyDer(l, acc + sizeof(u32), acc_len, pubkey,adata, adata_size, proof, stack);
    cmdBlobClose(stack);
    cmdBlobClose(adata);
    cmdBlobClose(acc);
    cmdBlobClose(proof);

    return code;
}

static int baccMain(int argc, char* argv[])
{

    err_t code;
    // справка
    if (argc < 2)
        return baccUsage();
    // разбор команды
    --argc, ++argv;
    if (strEq(argv[0], "init"))
        code = baccCreate(argc - 1, argv + 1);
    else if (strEq(argv[0], "add"))
        code = baccAdd(argc - 1, argv + 1);
    else if (strEq(argv[0], "prvadd"))
        code = baccPrvAdd(argc - 1, argv + 1);
    else if (strEq(argv[0], "vfyadd"))
        code = baccVfyAdd(argc - 1, argv + 1);
    else if (strEq(argv[0], "der"))
        code = baccDer(argc - 1, argv + 1);
    else if (strEq(argv[0], "prvder"))
        code = baccPrvDer(argc - 1, argv + 1);
    else if (strEq(argv[0], "vfyder"))
        code = baccVfyDer(argc - 1, argv + 1);
    else
        code = ERR_CMD_NOT_FOUND;

    if(code == ERR_BAD_PARAMS || code == ERR_CMD_NOT_FOUND)
        return baccUsage();
    // завершить
    if (code != ERR_OK)
        printf("bee2cmd/%s: %s\n", _name, errMsg(code));
    return (int)code;
}

err_t baccInit()
{
    return cmdReg(_name, _descr, baccMain);
}
