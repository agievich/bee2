#include <stdio.h>
#include <stdlib.h>
#include "bee2/crypto/bacc.h"
#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/core/dec.h"
#include "bee2/core/rng.h"
#include "../cmd.h"
#include "bee2/core/der.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/bash.h"

#if defined OS_UNIX
#include <pthread.h>
#include <unistd.h>

#endif

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
        "  bacc init [-lNNN] [-name <name>] <acc>\n"
        "    initialize accumulator with NNN security level. If <name> is passed EC will be built using bakeSWU.\n\n"
        "  bacc add -cert <cert> -pass <scheme> <privkey> -sigpass <scheme> <sig_privkey> <acc>\n"
        "    add <privkey> to the accumulator <acc> and sign the addition using <sig_privkey>.\n"
        "    <privkey> must have the same security level as <acc>\n\n"
        "  bacc validate [-name <name>] <acc> <anchor_cert>\n"
        "    validate that all stored in <acc> private keys were added and signed correctly. \n"
        "    Verify that the accumulator was initialized with given name if <name> is passed\n\n"
        "  bacc extract <acc> <extracted_acc>\n"
        "    extract the last iteration of the accumulator <acc> to the <extracted_acc> file\n\n"
        "  bacc der -pass <scheme> <privkey> <extracted_acc> <pubkey>\n"
        "    create <pubkey> related to <privkey> added to <extracted_acc>\n\n"
        "  bacc prvder [-adata <adata>] -pass <scheme> <privkey> <extracted_acc> <proof>\n"
        "    create <proof> that pubkey from der is related to some <privkey> added to the <extracted_acc>.\n\n"
        "  bacc vfyder [-adata <adata>] <pubkey> <extracted_acc> <proof>\n"
        "    verify that some private key related to the <pubkey> was added to the <extracted_acc>\n"
        "  .\n"
        "  <privkey>\n"
        "    container with a private key\n"
        "  <pubkey>\n"
        "    file with a public key\n"
        "  <acc>\n"
        "    file with accumulator, proofs and signatures\n"
        "  <extracted_acc>\n"
        "    file with the final iteration of accumulator\n"
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


static err_t baccDer(int argc, char* argv[]){
    err_t code;
    u16 l;
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
        code = cmdRngStart(0);
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

    acc_len = (acc_size - sizeof (l)) / (baccGq_keep(l));

    //память под аккумулятор
    code = cmdBlobCreate(acc, acc_size);
    ERR_CALL_CHECK(code);

    //прочитать аккумулятор
    code = cmdFileRead(acc, acc_size, *(argv + 1));
    ERR_CALL_CHECK(code);
    ERR_CALL_HANDLE(code, cmdBlobClose(acc));

    // создать открытый ключ
    if (baccDHDer(pubkey, l, acc + sizeof (l), acc_len, privkey) == SIZE_MAX)
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
    u16 l;
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

    acc_len = (acc_size - sizeof (l)) / (baccGq_keep(l));

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
    code = baccDHPrvDer(proof, l, acc + sizeof (l), acc_len, privkey, adata,adata_size,rngStepR, 0, stack);
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
    u16 l;
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

    acc_len = (acc_size - sizeof (l)) / (baccGq_keep(l));

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

    code = baccDHVfyDer(l, acc + sizeof(l), acc_len, pubkey,adata, adata_size, proof, stack);
    cmdBlobClose(stack);
    cmdBlobClose(adata);
    cmdBlobClose(acc);
    cmdBlobClose(proof);

    return code;
}

static size_t baccWrap(
    octet buf[],
    size_t l,
    const octet* acc,
    size_t acc_len,
    const octet* prvAdd,
    const octet* sig,
    size_t sig_len
){
    der_anchor_t Reg[1];
    size_t count = 0;

    derEncStep(derSEQEncStart(Reg, buf, count), buf, count);
    derEncStep(derOCTEnc(buf, acc, acc_len * baccGq_keep(l)), buf, count);
    if (prvAdd) {
        derEncStep(derOCTEnc(buf, prvAdd, baccDHPrvAdd_keep(l, acc_len - 1)), buf, count);
    }
    if (sig) {
        derEncStep(derOCTEnc(buf, sig, sig_len), buf, count);
    }
    derEncStep(derSEQEncStop(buf, count, Reg), buf, count);

    return count;
}

static size_t baccUnwrap(
    const octet* der,
    size_t count,
    size_t l,
    octet* acc,
    size_t acc_len,
    octet* prvAdd,
    octet* sig,
    size_t* sig_len
) {
    der_anchor_t Reg[1];
    const octet *ptr = der;

    derDecStep(derSEQDecStart(Reg, ptr, count), ptr, count);
    derDecStep(derOCTDec2(acc, ptr, count, acc_len * baccGq_keep(l)), ptr, count);
    if (acc_len > 1) {
        derDecStep(derOCTDec2(prvAdd, ptr, count, baccDHPrvAdd_keep(l, acc_len - 1)), ptr, count);
        derDecStep(derOCTDec(sig, sig_len, ptr, count), ptr, count);
    }
    derDecStep(derSEQDecStop(ptr, Reg), ptr, count);

    return ptr - der;
}

static err_t cmdBaccExtract(
    const char* acc_file,
    size_t* l,
    octet * acc,
    size_t* acc_len,
    size_t* endpoints
){
    FILE * fp;
    octet suffix[16];
    size_t count, tl_count;
    size_t file_size, total_seek;
    err_t code;
    u32 tag;
    size_t len;
    octet * buf;
    u16 _l;

    file_size = cmdFileSize(acc_file);

    if (file_size == SIZE_MAX)
        return ERR_FILE_READ;

    fp = fopen(acc_file, "r");

    if (!fp)
        return ERR_FILE_OPEN;

    code = fread(&_l, 2, 1, fp) == 1 ? ERR_OK : ERR_BAD_FILE;
    ERR_CALL_HANDLE(code, fclose(fp));

    total_seek = 2;

    *l = _l;
    if (*l != 128 && *l != 192 && *l != 256)
        ERR_CALL_HANDLE(ERR_BAD_FILE, fclose(fp));

    *acc_len = 0;
    while (total_seek < file_size)
    {
        (*acc_len)++;

        if (endpoints){
            endpoints[*acc_len-1] = ftell(fp);
        }
        count = MIN2(file_size - total_seek, sizeof(suffix));
        if (count != fread(suffix, 1, count, fp))
        {
            fclose(fp);
            return ERR_FILE_READ;
        };
        tl_count = derTLDec(&tag, &len, suffix, count);
        code = (tl_count == SIZE_MAX || tag != 0x30) ? ERR_BAD_FILE : ERR_OK;
        ERR_CALL_HANDLE(code, fclose(fp));

        code = fseek(fp, (long)(len - count + tl_count), SEEK_CUR) == 0 ? ERR_OK : ERR_FILE_READ;
        ERR_CALL_HANDLE(code, fclose(fp));

        total_seek += len + tl_count;
    }

    if (acc != 0) {
        fseek(fp, -(long) (len + tl_count), SEEK_CUR);

        code = cmdBlobCreate(buf, len+tl_count);
        ERR_CALL_HANDLE(code, fclose(fp));

        code = fread(buf, 1, len+tl_count, fp) == len + tl_count ? ERR_OK : ERR_FILE_READ;
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(buf)));

        code = baccUnwrap(buf, len + tl_count,*l, 0, *acc_len, 0, 0, 0) ==
               SIZE_MAX ? ERR_BAD_FILE : ERR_OK;
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(buf)));

        code = baccUnwrap(buf, len + tl_count,*l, acc, *acc_len, 0, 0, 0) ==
               SIZE_MAX ? ERR_BAD_FILE : ERR_OK;
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(buf)));

        cmdBlobClose(buf);
    }
    fclose(fp);
    return code;
}

static err_t baccAddAndSign(
    const char* acc_file,
    const octet* privkey,
    const octet* sign_privkey,
    size_t sign_privkey_len,
    const char* cert
){
    err_t code;
    FILE * fp;
    size_t l = 0;
    octet *old_acc, *new_acc, *proof, *buf;
    size_t olc_acc_len, sig_len, der_len;
    size_t new_acc_with_proof_len;
    octet sig[4096];

    // достать последний аккумулятор и уровень стойкости
    code = cmdBaccExtract(acc_file, &l, 0, &olc_acc_len,0);
    ERR_CALL_CHECK(code);
    code = cmdBlobCreate(old_acc, olc_acc_len * baccGq_keep(l));
    ERR_CALL_CHECK(code);

    code = cmdBaccExtract(acc_file, &l, old_acc, &olc_acc_len,0);
    ERR_CALL_HANDLE(code, cmdBlobClose(old_acc));

    // выделить память под новый аккумулятор и подтверждение
    new_acc_with_proof_len = (olc_acc_len + 1) * baccGq_keep(l) + baccDHPrvAdd_keep(l, olc_acc_len);
    code = cmdBlobCreate(new_acc, new_acc_with_proof_len);
    ERR_CALL_HANDLE(code, cmdBlobClose(old_acc));

    memCopy(new_acc, old_acc, olc_acc_len * baccGq_keep(l));

    //добавить личный ключ
    code = baccDHAdd(l, new_acc, olc_acc_len, privkey);
    ERR_CALL_HANDLE(code, (cmdBlobClose(old_acc), cmdBlobClose(new_acc)));

    proof = new_acc + (olc_acc_len + 1) * baccGq_keep(l);

    if (!rngIsValid()){
        cmdRngStart(0);
    }
    //создать подтверждение
    code = baccDHPrvAdd(proof, l, old_acc, new_acc, olc_acc_len, olc_acc_len + 1,
                        privkey, rngStepR, 0);
    ERR_CALL_HANDLE(code, (cmdBlobClose(old_acc), cmdBlobClose(new_acc)));

    cmdBlobClose(old_acc);

    //подписать изменения
    code = cmdSigSign2(sig, &sig_len, new_acc, new_acc_with_proof_len,
                       cert, sign_privkey, sign_privkey_len);

    ERR_CALL_HANDLE(code, cmdBlobClose(new_acc));

    //кодировать
    der_len = baccWrap(0, l, new_acc, olc_acc_len + 1, proof, sig, sig_len);
    code = der_len == SIZE_MAX ? ERR_MAX : ERR_OK;
    ERR_CALL_HANDLE(code, cmdBlobClose(new_acc));

    code = cmdBlobCreate(buf, der_len);
    ERR_CALL_HANDLE(code, cmdBlobClose(new_acc));

    der_len = baccWrap(buf, l, new_acc, olc_acc_len + 1, proof, sig, sig_len);
    code = der_len == SIZE_MAX ? ERR_MAX : ERR_OK;

    cmdBlobClose(new_acc);
    ERR_CALL_HANDLE(code, cmdBlobClose(buf));

    //открыть файл аккумулятора на дозапись
    fp = fopen(acc_file, "ab");
    code = fp ? ERR_OK : ERR_FILE_OPEN;
    ERR_CALL_HANDLE(code, cmdBlobClose(buf));

    // дописать изменения
    code = fwrite(buf, 1, der_len, fp) == der_len ? ERR_OK : ERR_OUTOFMEMORY;
    cmdBlobClose(buf);

    return code;
}

static err_t nameHash(const char* name, size_t l, octet hash[]) {
    octet hash_state[4096];

    if (l != 128 && l != 192 && l != 256) {
        return ERR_BAD_PARAMS;
    }

    if (l == 128) {
        beltHashStart(hash_state);
        beltHashStepH(name, strLen(name), hash_state);
        beltHashStepG(hash, hash_state);
    } else {
        bashHashStart(hash_state, l);
        bashHashStepH(name, strLen(name), hash_state);
        bashHashStepG(hash, l / 4, hash_state);
    }

    return ERR_OK;
}


static size_t cmdBaccValidate(
    const char* acc_file,
    const char* name,
    const octet anchor[],
    size_t anchor_len
) {
    FILE *fp;
    octet suffix[16];
    size_t count, tl_count;
    size_t file_size, total_read;
    err_t code;
    u32 tag;
    size_t len;
    octet *der=0, *prev_acc_buf=0;
    size_t current_acc_len = 0, sig_len;
    size_t l;
    u16 _l;
    octet * stack,*acc, *prvAdd, *sig;
    octet name_hash[64];
    octet acc_name_check[256];
    file_size = cmdFileSize(acc_file);

    if (file_size == SIZE_MAX)
        return ERR_FILE_READ;

    fp = fopen(acc_file, "r");

    if (!fp)
        return ERR_FILE_OPEN;

    code = fread(&_l, 2, 1, fp) == 1 ? ERR_OK : ERR_BAD_FILE;
    ERR_CALL_HANDLE(code, fclose(fp));

    l = _l;
    if (l != 128 && l != 192 && l != 256)
        ERR_CALL_HANDLE(ERR_BAD_FILE, fclose(fp));

    total_read = 2;

    while (total_read < file_size){

        ++current_acc_len;

        //прочитать длину закодированного эл-та аккумулятора
        count = MIN2(file_size - total_read, sizeof(suffix));
        if (count != fread(suffix, 1, count, fp))
        {
            fclose(fp);
            return ERR_FILE_READ;
        };
        tl_count = derTLDec(&tag, &len, suffix, count);
        code = (tl_count == SIZE_MAX || tag != 0x30) ? ERR_BAD_FILE : ERR_OK;
        ERR_CALL_HANDLE(code, fclose(fp));

        // выделить память под эл-т
        code = cmdBlobCreate(der, len + tl_count);
        ERR_CALL_HANDLE(code, fclose(fp));

        code = fseek(fp, -(long)count, SEEK_CUR) == 0 ? ERR_OK : ERR_FILE_READ;
        ERR_CALL_HANDLE(code, (fclose(fp),cmdBlobClose(der)));

        //прочитать эл-т
        code = fread(der, 1, len + tl_count, fp) == len + tl_count ? ERR_OK : ERR_FILE_READ;
        ERR_CALL_HANDLE(code, (fclose(fp),cmdBlobClose(der)));

        acc = der,
        prvAdd = der + current_acc_len * baccGq_keep(l);
        sig = prvAdd + baccDHPrvAdd_keep(l, current_acc_len - 1);

        //декодировать эл-т
        code = baccUnwrap(der, len + tl_count, l, acc, current_acc_len, prvAdd, sig, &sig_len) ==
                SIZE_MAX ? ERR_BAD_FILE : ERR_OK;
        ERR_CALL_HANDLE(code, (fclose(fp),cmdBlobClose(der)));

        //если не первая запись
        if (current_acc_len > 1) {
            ASSERT(prev_acc_buf != 0);
            // создать вспомогательную память
            code = cmdBlobCreate(stack, baccDHVfyAdd_deep(l, current_acc_len - 1));
            ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der), cmdBlobClose(prev_acc_buf)));

            //проверить добавление
            code = baccDHVfyAdd(l, prvAdd, prev_acc_buf, acc, current_acc_len - 1, current_acc_len, stack);

            //освободить предыдущий аккумулятор и вспомогательную память
            cmdBlobClose(stack);
            cmdBlobClose(prev_acc_buf);
            ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

            //проверить подпись
            code = cmdSigVerify3(acc, current_acc_len * baccGq_keep(l) + baccDHPrvAdd_keep(l, current_acc_len - 1), sig,
                                 anchor, anchor_len);
            ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));
        } else if (name) {
            code = nameHash(name, l,name_hash);
            ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));
            code = baccDHInit(acc_name_check, l, name_hash, rngStepR,0);
            ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

            if (!memEq(acc,acc_name_check, baccGq_keep(l))){
                ERR_CALL_HANDLE(ERR_BAD_NAME, (fclose(fp), cmdBlobClose(der)));
            }
        }

        //сохранить текущий аккумулятор
        code = cmdBlobCreate(prev_acc_buf, current_acc_len * baccGq_keep(l));
        ERR_CALL_HANDLE(code, (fclose(fp),cmdBlobClose(der)));
        memCopy(prev_acc_buf, acc, current_acc_len * baccGq_keep(l));

        cmdBlobClose(der);

        total_read += len + tl_count;
    }

    fclose(fp);
    cmdBlobClose(prev_acc_buf);

    return code;
}

#if defined OS_UNIX

struct bacc_validation_t {
    size_t acc_len;
    size_t acc_file_size;
    size_t l;
    size_t current_number;
    size_t* endpoints;
    const char *file_name;
    const char *acc_name;
    err_t code;
    pthread_mutex_t mutex;
    const octet* anchor;
    size_t anchor_len;
};


static err_t extractSingleElement(
   FILE* fp,
   size_t offset,
   octet* acc,
   size_t l,
   size_t number,
   size_t file_size
){
    octet suffix[16];
    size_t count, tl_count, total_read;
    err_t code;
    u32 tag;
    size_t len;
    octet *der = 0, *prev_acc_buf = 0;
    size_t sig_len;
    octet *prvAdd, *sig;

    total_read = 2;

    fseek(fp, (long)offset, SEEK_SET);

    //прочитать длину закодированного эл-та аккумулятора
    count = MIN2(file_size - total_read, sizeof(suffix));
    if (count != fread(suffix, 1, count, fp)) {
        fclose(fp);
        return ERR_FILE_READ;
    };
    tl_count = derTLDec(&tag, &len, suffix, count);
    code = (tl_count == SIZE_MAX || tag != 0x30) ? ERR_BAD_FILE : ERR_OK;
    ERR_CALL_HANDLE(code, fclose(fp));

    // выделить память под эл-т
    code = cmdBlobCreate(der, len + tl_count);
    ERR_CALL_HANDLE(code, fclose(fp));

    code = fseek(fp, -(long) count, SEEK_CUR) == 0 ? ERR_OK : ERR_FILE_READ;
    ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

    //прочитать эл-т
    code = fread(der, 1, len + tl_count, fp) == len + tl_count ? ERR_OK : ERR_FILE_READ;
    ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

    prvAdd = der + number * baccGq_keep(l);
    sig = prvAdd + baccDHPrvAdd_keep(l, number - 1);

    //декодировать эл-т
    code = baccUnwrap(der, len + tl_count, l, acc, number, prvAdd, sig, &sig_len) ==
           SIZE_MAX ? ERR_BAD_FILE : ERR_OK;
    ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

    return code;
}

static err_t validateProcValidation(
    FILE *fp,
    size_t number,
    const struct bacc_validation_t *validation
) {
    octet suffix[16];
    size_t count, tl_count, total_read;
    err_t code;
    u32 tag;
    size_t len;
    octet *der, *prev_acc_buf;
    size_t sig_len;
    octet *stack, *acc, *prvAdd, *sig;
    octet name_hash[64];
    octet acc_name_check[256];

    ASSERT(memIsValid(validation, sizeof (struct bacc_validation_t)));

    fseek(fp, (long)validation->endpoints[number-1], SEEK_SET);
    //прочитать длину закодированного эл-та аккумулятора
    count = fread(suffix, 1, sizeof (suffix), fp);
    tl_count = derTLDec(&tag, &len, suffix, count);
    code = tl_count == SIZE_MAX || tag != 0x30 ? ERR_BAD_FILE : ERR_OK;
    ERR_CALL_HANDLE(code, fclose(fp));

    // выделить память под эл-т
    code = cmdBlobCreate(der, len + tl_count);
    ERR_CALL_HANDLE(code, fclose(fp));

    code = fseek(fp, -(long) count, SEEK_CUR) == 0 ? ERR_OK : ERR_FILE_READ;
    ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

    //прочитать эл-т
    code = fread(der, 1, len + tl_count, fp) ==
            len + tl_count ? ERR_OK : ERR_FILE_READ;
    ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

    acc = der, prvAdd = der + number * baccGq_keep(validation->l);
    sig = prvAdd + baccDHPrvAdd_keep(validation->l, number - 1);

    //декодировать эл-т
    code = baccUnwrap(der, len + tl_count, validation->l, acc, number, prvAdd, sig, &sig_len) ==
           SIZE_MAX ? ERR_BAD_FILE : ERR_OK;
    ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

    //если не первая запись
    if (number > 1) {
        //прочитать предыдущий
        code = cmdBlobCreate(prev_acc_buf, (number-1) * baccGq_keep(validation->l));
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));
        code = extractSingleElement(fp, validation->endpoints[number-2], prev_acc_buf, validation->l, number-1, validation->acc_file_size);
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

        // создать вспомогательную память
        code = cmdBlobCreate(stack, baccDHVfyAdd_deep(validation->l, number - 1));
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der), cmdBlobClose(prev_acc_buf)));

        //проверить добавление
        code = baccDHVfyAdd(validation->l, prvAdd, prev_acc_buf, acc, number - 1, number, stack);

        //освободить предыдущий аккумулятор и вспомогательную память
        cmdBlobClose(stack);
        cmdBlobClose(prev_acc_buf);
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

        //проверить подпись
        code = cmdSigVerify3(acc, number * baccGq_keep(validation->l) +
                                  baccDHPrvAdd_keep(validation->l, number - 1), sig, validation->anchor,
                             validation->anchor_len);
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));
    } else if (validation->acc_name != 0) {
        code = nameHash(validation->acc_name, validation->l, name_hash);
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));
        code = baccDHInit(acc_name_check, validation->l, name_hash, rngStepR, 0);
        ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(der)));

        if (!memEq(acc, acc_name_check, baccGq_keep(validation->l))) {
            ERR_CALL_HANDLE(ERR_BAD_NAME, (fclose(fp), cmdBlobClose(der)));
        }
    }

    cmdBlobClose(der);

    return code;
}

void *validateProc(void *vargp)
{
    struct bacc_validation_t *validation = vargp;
    FILE * fp;
    bool_t finish = FALSE;
    size_t current;
    err_t code;

    fp = fopen(validation->file_name, "rb");
    if (!fp) {
        validation->code = ERR_FILE_OPEN;
        return NULL;
    }

    while (!finish) {

        pthread_mutex_lock(&validation->mutex);

        if (validation->code != ERR_OK || validation->current_number >= validation->acc_len) {
            finish = TRUE;
        }
        current = validation->current_number;
        validation->current_number++;

        pthread_mutex_unlock(&validation->mutex);
        if (finish == TRUE)
            continue;

        code = validateProcValidation(fp, current, validation);

        if (code != ERR_OK){
            pthread_mutex_lock(&validation->mutex);
            validation->code = code;
            pthread_mutex_unlock(&validation->mutex);
            finish = TRUE;
        }
    }
    fclose(fp);

    return NULL;
}


static size_t cmdBaccValidate_mt(
    const char* acc_file,
    const char* name,
    const octet anchor[],
    size_t anchor_len
) {
    long numCPU = sysconf( _SC_NPROCESSORS_ONLN );
    err_t code;
    pthread_t* threads;
    long i;

    struct bacc_validation_t validation[1];
    validation->file_name = acc_file;
    validation->anchor = anchor;
    validation->anchor_len = anchor_len;
    validation->acc_name = name;
    validation->code = ERR_OK;
    validation->acc_file_size = cmdFileSize(acc_file);
    validation->current_number = 1;

    if (validation->acc_file_size == SIZE_MAX)
        return ERR_FILE_READ;

    code = cmdBaccExtract(acc_file, &(validation->l),0, &(validation->acc_len),0);
    ERR_CALL_CHECK(code);

    code = cmdBlobCreate(validation->endpoints, sizeof (size_t ) *validation->acc_len);
    ERR_CALL_CHECK(code);

    code = cmdBaccExtract(acc_file, &(validation->l),0, &(validation->acc_len),validation->endpoints);
    ERR_CALL_HANDLE(code, blobClose(validation->endpoints));

    code = cmdBlobCreate(threads, sizeof (pthread_t) * numCPU);
    ERR_CALL_HANDLE(code, blobClose(validation->endpoints));

    code = pthread_mutex_init(&validation->mutex, 0) == 0 ? ERR_OK : ERR_SYS;
    ERR_CALL_HANDLE(code, (blobClose(validation->endpoints), blobClose(&threads)));

    for (i = 0; i < numCPU;i++) {
        code = pthread_create(&threads[i], NULL, validateProc, validation) == 0 ? ERR_OK : ERR_SYS;
        ERR_CALL_HANDLE(code, (blobClose(validation->endpoints), blobClose(&threads)));
    }

    for (i = 0; i < numCPU;i++) {
        code = pthread_join(threads[i], NULL) == 0 ? ERR_OK : ERR_SYS;
        ERR_CALL_HANDLE(code, (blobClose(validation->endpoints),blobClose(&threads)));
    }
    pthread_mutex_destroy(&validation->mutex);
    cmdBlobClose(validation->endpoints);
    cmdBlobClose(threads);

    return validation->code;
}

#endif

static err_t baccCreate(int argc, char* argv[])
{
    u16 l = 0;
    octet a[256];
    err_t code = ERR_OK;
    size_t der_len;
    octet b[258];
    octet name_hash[64];
    const char *name = 0;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (strStartsWith(*argv, "-l"))
        {
            char* str = *argv + strLen("-l");
            if (l)
            {
                code = ERR_CMD_DUPLICATE;
                break;
            }
            if (!decIsValid(str) || decCLZ(str) || strLen(str) != 3 ||
                (l = (size_t)decToU32(str)) % 64 || l < 128 || l > 256)
            {
                code = ERR_CMD_PARAMS;
                break;
            }
            ++argv, --argc;
        }
        else if (strStartsWith(*argv, "-name"))
        {
            ++argv, --argc;
            ASSERT(argc>0);
            name = *argv;

            ++argv, --argc;
        }
        else
        {
            code = ERR_CMD_PARAMS;
            break;
        }
    }
    if (l == 0)
        l = 128;

    if (code != ERR_OK || argc != 1)
        return ERR_CMD_PARAMS;

    memCopy(b, &l, sizeof (l));

    if (!rngIsValid())
    {
        code = cmdRngStart(0);
        ERR_CALL_CHECK(code);
    }

    if (name){
        code = nameHash(name, l, name_hash);
        ERR_CALL_CHECK(code);
    }

    code  = baccDHInit(a, l, name ? name_hash : 0,rngStepR, 0);
    ERR_CALL_CHECK(code);

    der_len = baccWrap(b+sizeof (l), l,a, 1,0,0,0);
    code = der_len == SIZE_MAX ? ERR_MAX : ERR_OK;
    ERR_CALL_CHECK(code);

    return cmdFileWrite(*argv, b, der_len + sizeof (l));
}


static err_t baccValidate(int argc, char* argv[]) {

    octet anchor[512];
    size_t anchor_len;
    err_t code;

    const char* name = 0;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (strStartsWith(*argv, "-name"))
        {
            ++argv, --argc;
            ASSERT(argc>0);
            name = *argv;
            ++argv, --argc;
        }
        else
        {
            code = ERR_CMD_PARAMS;
            break;
        }
    }
    if (argc != 2)
        return ERR_CMD_PARAMS;

    anchor_len = cmdFileSize(*(argv+1));
    code = cmdFileReadAll(anchor, &anchor_len, *(argv+1));

#if !defined OS_UNIX
    return cmdBaccValidate_mt(*argv, name, anchor, anchor_len);
#else
    return cmdBaccValidate(*argv, name, anchor, anchor_len);
#endif

}

static err_t baccAdd(int argc, char* argv[])
{
    size_t privkey_len;
    size_t sig_privkey_len;
    octet key[64];
    octet sig_key[64];
    err_t code = ERR_OK;
    cmd_pwd_t pwd = 0;

    const char* cert = 0;

    while (argc && strStartsWith(*argv, "-"))
    {
        if (argc < 2)
        {
            code = ERR_CMD_PARAMS;
            break;
        }
        else if (strStartsWith(*argv, "-cert"))
        {
            cert = *(argv+1);
            argv+=2; argc-=2;
        }
        else if (strStartsWith(*argv, "-pass"))
        {
            ++argv, --argc;
            ASSERT(argc > 0);
            code = cmdPwdRead(&pwd, *argv);
            if (code != ERR_OK)
                break;
            ASSERT(cmdPwdIsValid(pwd));
            ++argv, --argc;
            ASSERT(argc > 0);
            privkey_len = 0;
            code = cmdPrivkeyRead(key, &privkey_len, *argv, pwd);
            cmdPwdClose(pwd);
            ERR_CALL_CHECK(code);

            ++argv, --argc;
        }
        else if (strStartsWith(*argv, "-sigpass"))
        {
            ++argv, --argc;
            ASSERT(argc > 0);
            code = cmdPwdRead(&pwd, *argv);
            if (code != ERR_OK)
                break;
            ASSERT(cmdPwdIsValid(pwd));
            ++argv, --argc;
            ASSERT(argc > 0);
            sig_privkey_len = 0;
            code = cmdPrivkeyRead(sig_key, &sig_privkey_len, *argv, pwd);
            cmdPwdClose(pwd);
            ERR_CALL_CHECK(code);
            ++argv, --argc;
        }
        else
        {
            code = ERR_CMD_PARAMS;
            break;
        }
    }


    if (argc != 1 || !cert)
        return ERR_CMD_PARAMS;


    return baccAddAndSign(*argv, key, sig_key, sig_privkey_len, cert);
}

static err_t baccExtract(int argc, char* argv[]) {
    err_t code;
    size_t l;
    u16 _l;
    octet *acc;
    size_t acc_len;
    FILE *fp;

    if (argc != 2)
        return ERR_CMD_PARAMS;

    code = cmdBaccExtract(*argv, &l, 0, &acc_len,0);
    ERR_CALL_CHECK(code);

    code = cmdBlobCreate(acc, acc_len * baccGq_keep(l));
    ERR_CALL_CHECK(code);

    code = cmdBaccExtract(*argv, &l, acc, &acc_len,0);
    ERR_CALL_HANDLE(code, blobClose(acc));

    argv++;
    fp = fopen(*argv, "wb");
    code = fp ? ERR_OK : ERR_FILE_OPEN;
    ERR_CALL_HANDLE(code, blobClose(acc));

    _l = (u16)l;
    code = fwrite(&_l, sizeof(_l), 1, fp) ==
           1 ? ERR_OK : ERR_FILE_WRITE;
    ERR_CALL_HANDLE(code, blobClose(acc));

    code = fwrite(acc, 1,acc_len * baccGq_keep(l),fp) ==
            acc_len * baccGq_keep(l) ? ERR_OK : ERR_FILE_WRITE;

    blobClose(acc);
    fclose(fp);

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
    else if (strEq(argv[0], "validate"))
        code = baccValidate(argc - 1, argv + 1);
    else if (strEq(argv[0], "extract"))
        code = baccExtract(argc - 1, argv + 1);
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
