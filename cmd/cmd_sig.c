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
        const cmd_sig_t* sig,
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
        const cmd_sig_t* sig,
        octet certs[],
        const char* file,
        bool_t append
){

    size_t count;
    octet der[SIG_MAX_DER];
    FILE* fp;


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

    \remark Если anchor = NULL, то первый сертификат в
    цепочке считается дверенным. Пустая цепочка вызывает ошибку ERR_BAD_CERT

    \return ERR_OR, если цепочка корректна. Код ошибки в обратном случае
 */
static err_t cmdValCerts(
        btok_cvc_t *last_cert,              /*!< [out] последний сертификат */
        const octet * anchor,                     /*!< [in]  доверенный сертификат (optional) */
        size_t anchor_len,                  /*!< [in]  длина доверенного сертификата */
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
        code = btokCVCUnwrap(cvc_anchor, certs, certs_lens[0], 0, 0);
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
        const octet* pubkey,
        const octet* anchor_cert,
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
        code = cmdValCerts(last_cert, anchor_cert, anchor_cert_len, certs,sig->certs_len);
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
        code = cmdValCerts(0, 0, 0, certs, sig->certs_len);
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

#ifndef WAI_FUNCSPEC
#define WAI_FUNCSPEC
#endif
#ifndef WAI_PREFIX
#define WAI_PREFIX(function) wai_##function
#endif

/**
 * Returns the path to the current executable.
 *
 * Usage:
 *  - first call `int length = wai_getExecutablePath(NULL, 0, NULL);` to
 *    retrieve the length of the path
 *  - allocate the destination buffer with `path = (char*)malloc(length + 1);`
 *  - call `wai_getExecutablePath(path, length, NULL)` again to retrieve the
 *    path
 *  - add a terminal NUL character with `path[length] = '\0';`
 *
 * @param out destination buffer, optional
 * @param capacity destination buffer capacity
 * @param dirname_length optional recipient for the length of the dirname part
 *   of the path.
 *
 * @return the length of the executable path on success (without a terminal NUL
 * character), otherwise `-1`
 */
WAI_FUNCSPEC
static int WAI_PREFIX(getExecutablePath)(char* out, int capacity, int* dirname_length);

/**
 * Returns the path to the current module
 *
 * Usage:
 *  - first call `int length = wai_getModulePath(NULL, 0, NULL);` to retrieve
 *    the length  of the path
 *  - allocate the destination buffer with `path = (char*)malloc(length + 1);`
 *  - call `wai_getModulePath(path, length, NULL)` again to retrieve the path
 *  - add a terminal NUL character with `path[length] = '\0';`
 *
 * @param out destination buffer, optional
 * @param capacity destination buffer capacity
 * @param dirname_length optional recipient for the length of the dirname part
 *   of the path.
 *
 * @return the length of the module path on success (without a terminal NUL
 * character), otherwise `-1`
 */
WAI_FUNCSPEC
static int WAI_PREFIX(getModulePath)(char* out, int capacity, int* dirname_length);

err_t cmdVerifySelf(
        const octet* pubkey,
        const octet* anchor_cert,
        size_t anchor_cert_len
) {

    err_t code;
    int len;
    char* buf;

    len = wai_getExecutablePath(0,0, 0);
    if (len == -1)
        return ERR_SYS;
    buf = blobCreate(len+1);
    wai_getExecutablePath(buf, len,0);

    char* args[] = {"vfy",buf, buf};

    code = cmdSigVerify(0,0,0, buf, buf);

    blobClose(buf);
    return code;
}


#if defined(__linux__) || defined(__CYGWIN__)
#undef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#elif defined(__APPLE__)
#undef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#define _DARWIN_BETTER_REALPATH
#endif

#if !defined(WAI_MALLOC) || !defined(WAI_FREE) || !defined(WAI_REALLOC)
#include <stdlib.h>
#endif

#if !defined(WAI_MALLOC)
#define WAI_MALLOC(size) malloc(size)
#endif

#if !defined(WAI_FREE)
#define WAI_FREE(p) free(p)
#endif

#if !defined(WAI_REALLOC)
#define WAI_REALLOC(p, size) realloc(p, size)
#endif

#ifndef WAI_NOINLINE
#if defined(_MSC_VER)
#define WAI_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
#define WAI_NOINLINE __attribute__((noinline))
#else
#error unsupported compiler
#endif
#endif

#if defined(_MSC_VER)
#define WAI_RETURN_ADDRESS() _ReturnAddress()
#elif defined(__GNUC__)
#define WAI_RETURN_ADDRESS() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#error unsupported compiler
#endif

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#if defined(_MSC_VER)
#pragma warning(push, 3)
#endif
#include <windows.h>
#include <intrin.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#include <stdbool.h>

static int WAI_PREFIX(getModulePath_)(HMODULE module, char* out, int capacity, int* dirname_length)
{
  wchar_t buffer1[MAX_PATH];
  wchar_t buffer2[MAX_PATH];
  wchar_t* path = NULL;
  int length = -1;
  bool ok;

  for (ok = false; !ok; ok = true)
  {
    DWORD size;
    int length_, length__;

    size = GetModuleFileNameW(module, buffer1, sizeof(buffer1) / sizeof(buffer1[0]));

    if (size == 0)
      break;
    else if (size == (DWORD)(sizeof(buffer1) / sizeof(buffer1[0])))
    {
      DWORD size_ = size;
      do
      {
        wchar_t* path_;

        path_ = (wchar_t*)WAI_REALLOC(path, sizeof(wchar_t) * size_ * 2);
        if (!path_)
          break;
        size_ *= 2;
        path = path_;
        size = GetModuleFileNameW(module, path, size_);
      }
      while (size == size_);

      if (size == size_)
        break;
    }
    else
      path = buffer1;

    if (!_wfullpath(buffer2, path, MAX_PATH))
      break;
    length_ = (int)wcslen(buffer2);
    length__ = WideCharToMultiByte(CP_UTF8, 0, buffer2, length_ , out, capacity, NULL, NULL);

    if (length__ == 0)
      length__ = WideCharToMultiByte(CP_UTF8, 0, buffer2, length_, NULL, 0, NULL, NULL);
    if (length__ == 0)
      break;

    if (length__ <= capacity && dirname_length)
    {
      int i;

      for (i = length__ - 1; i >= 0; --i)
      {
        if (out[i] == '\\')
        {
          *dirname_length = i;
          break;
        }
      }
    }

    length = length__;
  }

  if (path != buffer1)
    WAI_FREE(path);

  return ok ? length : -1;
}

WAI_NOINLINE WAI_FUNCSPEC
int WAI_PREFIX(getExecutablePath)(char* out, int capacity, int* dirname_length)
{
  return WAI_PREFIX(getModulePath_)(NULL, out, capacity, dirname_length);
}

WAI_NOINLINE WAI_FUNCSPEC
int WAI_PREFIX(getModulePath)(char* out, int capacity, int* dirname_length)
{
  HMODULE module;
  int length = -1;

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4054)
#endif
  if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)WAI_RETURN_ADDRESS(), &module))
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
  {
    length = WAI_PREFIX(getModulePath_)(module, out, capacity, dirname_length);
  }

  return length;
}

#elif defined(__linux__) || defined(__CYGWIN__) || defined(__sun) || defined(WAI_USE_PROC_SELF_EXE)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <linux/limits.h>
#else
#include <limits.h>
#endif
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <stdbool.h>

#if !defined(WAI_PROC_SELF_EXE)
#if defined(__sun)
#define WAI_PROC_SELF_EXE "/proc/self/path/a.out"
#else
#define WAI_PROC_SELF_EXE "/proc/self/exe"
#endif
#endif

WAI_FUNCSPEC
int WAI_PREFIX(getExecutablePath)(char* out, int capacity, int* dirname_length)
{
  char buffer[PATH_MAX];
  char* resolved = NULL;
  int length = -1;
  bool ok;

  for (ok = false; !ok; ok = true)
  {
    resolved = realpath(WAI_PROC_SELF_EXE, buffer);
    if (!resolved)
      break;

    length = (int)strlen(resolved);
    if (length <= capacity)
    {
      memcpy(out, resolved, length);

      if (dirname_length)
      {
        int i;

        for (i = length - 1; i >= 0; --i)
        {
          if (out[i] == '/')
          {
            *dirname_length = i;
            break;
          }
        }
      }
    }
  }

  return ok ? length : -1;
}

#if !defined(WAI_PROC_SELF_MAPS_RETRY)
#define WAI_PROC_SELF_MAPS_RETRY 5
#endif

#if !defined(WAI_PROC_SELF_MAPS)
#if defined(__sun)
#define WAI_PROC_SELF_MAPS "/proc/self/map"
#else
#define WAI_PROC_SELF_MAPS "/proc/self/maps"
#endif
#endif

#if defined(__ANDROID__) || defined(ANDROID)
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <stdbool.h>

WAI_NOINLINE WAI_FUNCSPEC
int WAI_PREFIX(getModulePath)(char* out, int capacity, int* dirname_length)
{
  int length = -1;
  FILE* maps = NULL;

  for (int r = 0; r < WAI_PROC_SELF_MAPS_RETRY; ++r)
  {
    maps = fopen(WAI_PROC_SELF_MAPS, "r");
    if (!maps)
      break;

    for (;;)
    {
      char buffer[PATH_MAX < 1024 ? 1024 : PATH_MAX];
      uint64_t low, high;
      char perms[5];
      uint64_t offset;
      uint32_t major, minor;
      char path[PATH_MAX];
      uint32_t inode;

      if (!fgets(buffer, sizeof(buffer), maps))
        break;

      if (sscanf(buffer, "%" PRIx64 "-%" PRIx64 " %s %" PRIx64 " %x:%x %u %s\n", &low, &high, perms, &offset, &major, &minor, &inode, path) == 8)
      {
        uint64_t addr = (uintptr_t)WAI_RETURN_ADDRESS();
        if (low <= addr && addr <= high)
        {
          char* resolved;

          resolved = realpath(path, buffer);
          if (!resolved)
            break;

          length = (int)strlen(resolved);
#if defined(__ANDROID__) || defined(ANDROID)
          if (length > 4
              &&buffer[length - 1] == 'k'
              &&buffer[length - 2] == 'p'
              &&buffer[length - 3] == 'a'
              &&buffer[length - 4] == '.')
          {
            int fd = open(path, O_RDONLY);
            if (fd == -1)
            {
              length = -1; // retry
              break;
            }

            char* begin = (char*)mmap(0, offset, PROT_READ, MAP_SHARED, fd, 0);
            if (begin == MAP_FAILED)
            {
              close(fd);
              length = -1; // retry
              break;
            }

            char* p = begin + offset - 30; // minimum size of local file header
            while (p >= begin) // scan backwards
            {
              if (*((uint32_t*)p) == 0x04034b50UL) // local file header signature found
              {
                uint16_t length_ = *((uint16_t*)(p + 26));

                if (length + 2 + length_ < (int)sizeof(buffer))
                {
                  memcpy(&buffer[length], "!/", 2);
                  memcpy(&buffer[length + 2], p + 30, length_);
                  length += 2 + length_;
                }

                break;
              }

              --p;
            }

            munmap(begin, offset);
            close(fd);
          }
#endif
          if (length <= capacity)
          {
            memcpy(out, resolved, length);

            if (dirname_length)
            {
              int i;

              for (i = length - 1; i >= 0; --i)
              {
                if (out[i] == '/')
                {
                  *dirname_length = i;
                  break;
                }
              }
            }
          }

          break;
        }
      }
    }

    fclose(maps);
    maps = NULL;

    if (length != -1)
      break;
  }

  return length;
}

#elif defined(__APPLE__)

#include <mach-o/dyld.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdbool.h>

WAI_FUNCSPEC
int WAI_PREFIX(getExecutablePath)(char* out, int capacity, int* dirname_length)
{
    char buffer1[PATH_MAX];
    char buffer2[PATH_MAX];
    char* path = buffer1;
    char* resolved = NULL;
    int length = -1;
    bool ok;

    for (ok = false; !ok; ok = true)
    {
        uint32_t size = (uint32_t)sizeof(buffer1);
        if (_NSGetExecutablePath(path, &size) == -1)
        {
            path = (char*)WAI_MALLOC(size);
            if (!_NSGetExecutablePath(path, &size))
                break;
        }

        resolved = realpath(path, buffer2);
        if (!resolved)
            break;

        length = (int)strlen(resolved);
        if (length <= capacity)
        {
            memcpy(out, resolved, length);

            if (dirname_length)
            {
                int i;

                for (i = length - 1; i >= 0; --i)
                {
                    if (out[i] == '/')
                    {
                        *dirname_length = i;
                        break;
                    }
                }
            }
        }
    }

    if (path != buffer1)
        WAI_FREE(path);

    return ok ? length : -1;
}

WAI_NOINLINE WAI_FUNCSPEC
int WAI_PREFIX(getModulePath)(char* out, int capacity, int* dirname_length)
{
    char buffer[PATH_MAX];
    char* resolved = NULL;
    int length = -1;

    for(;;)
    {
        Dl_info info;

        if (dladdr(WAI_RETURN_ADDRESS(), &info))
        {
            resolved = realpath(info.dli_fname, buffer);
            if (!resolved)
                break;

            length = (int)strlen(resolved);
            if (length <= capacity)
            {
                memcpy(out, resolved, length);

                if (dirname_length)
                {
                    int i;

                    for (i = length - 1; i >= 0; --i)
                    {
                        if (out[i] == '/')
                        {
                            *dirname_length = i;
                            break;
                        }
                    }
                }
            }
        }

        break;
    }

    return length;
}

#elif defined(__QNXNTO__)

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdbool.h>

#if !defined(WAI_PROC_SELF_EXE)
#define WAI_PROC_SELF_EXE "/proc/self/exefile"
#endif

WAI_FUNCSPEC
int WAI_PREFIX(getExecutablePath)(char* out, int capacity, int* dirname_length)
{
  char buffer1[PATH_MAX];
  char buffer2[PATH_MAX];
  char* resolved = NULL;
  FILE* self_exe = NULL;
  int length = -1;
  bool ok;

  for (ok = false; !ok; ok = true)
  {
    self_exe = fopen(WAI_PROC_SELF_EXE, "r");
    if (!self_exe)
      break;

    if (!fgets(buffer1, sizeof(buffer1), self_exe))
      break;

    resolved = realpath(buffer1, buffer2);
    if (!resolved)
      break;

    length = (int)strlen(resolved);
    if (length <= capacity)
    {
      memcpy(out, resolved, length);

      if (dirname_length)
      {
        int i;

        for (i = length - 1; i >= 0; --i)
        {
          if (out[i] == '/')
          {
            *dirname_length = i;
            break;
          }
        }
      }
    }
  }

  fclose(self_exe);

  return ok ? length : -1;
}

WAI_FUNCSPEC
int WAI_PREFIX(getModulePath)(char* out, int capacity, int* dirname_length)
{
  char buffer[PATH_MAX];
  char* resolved = NULL;
  int length = -1;

  for(;;)
  {
    Dl_info info;

    if (dladdr(WAI_RETURN_ADDRESS(), &info))
    {
      resolved = realpath(info.dli_fname, buffer);
      if (!resolved)
        break;

      length = (int)strlen(resolved);
      if (length <= capacity)
      {
        memcpy(out, resolved, length);

        if (dirname_length)
        {
          int i;

          for (i = length - 1; i >= 0; --i)
          {
            if (out[i] == '/')
            {
              *dirname_length = i;
              break;
            }
          }
        }
      }
    }

    break;
  }

  return length;
}

#elif defined(__DragonFly__) || defined(__FreeBSD__) || \
      defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__)

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <stdbool.h>

#if defined(__OpenBSD__)

#include <unistd.h>

WAI_FUNCSPEC
int WAI_PREFIX(getExecutablePath)(char* out, int capacity, int* dirname_length)
{
  char buffer1[4096];
  char buffer2[PATH_MAX];
  char buffer3[PATH_MAX];
  char** argv = (char**)buffer1;
  char* resolved = NULL;
  int length = -1;
  bool ok;

  for (ok = false; !ok; ok = true)
  {
    int mib[4] = { CTL_KERN, KERN_PROC_ARGS, getpid(), KERN_PROC_ARGV };
    size_t size;

    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0)
        break;

    if (size > sizeof(buffer1))
    {
      argv = (char**)WAI_MALLOC(size);
      if (!argv)
        break;
    }

    if (sysctl(mib, 4, argv, &size, NULL, 0) != 0)
        break;

    if (strchr(argv[0], '/'))
    {
      resolved = realpath(argv[0], buffer2);
      if (!resolved)
        break;
    }
    else
    {
      const char* PATH = getenv("PATH");
      if (!PATH)
        break;

      size_t argv0_length = strlen(argv[0]);

      const char* begin = PATH;
      while (1)
      {
        const char* separator = strchr(begin, ':');
        const char* end = separator ? separator : begin + strlen(begin);

        if (end - begin > 0)
        {
          if (*(end -1) == '/')
            --end;

          if (((end - begin) + 1 + argv0_length + 1) <= sizeof(buffer2))
          {
            memcpy(buffer2, begin, end - begin);
            buffer2[end - begin] = '/';
            memcpy(buffer2 + (end - begin) + 1, argv[0], argv0_length + 1);

            resolved = realpath(buffer2, buffer3);
            if (resolved)
              break;
          }
        }

        if (!separator)
          break;

        begin = ++separator;
      }

      if (!resolved)
        break;
    }

    length = (int)strlen(resolved);
    if (length <= capacity)
    {
      memcpy(out, resolved, length);

      if (dirname_length)
      {
        int i;

        for (i = length - 1; i >= 0; --i)
        {
          if (out[i] == '/')
          {
            *dirname_length = i;
            break;
          }
        }
      }
    }
  }

  if (argv != (char**)buffer1)
    WAI_FREE(argv);

  return ok ? length : -1;
}

#else

WAI_FUNCSPEC
int WAI_PREFIX(getExecutablePath)(char* out, int capacity, int* dirname_length)
{
  char buffer1[PATH_MAX];
  char buffer2[PATH_MAX];
  char* path = buffer1;
  char* resolved = NULL;
  int length = -1;
  bool ok;

  for (ok = false; !ok; ok = true)
  {
#if defined(__NetBSD__)
    int mib[4] = { CTL_KERN, KERN_PROC_ARGS, -1, KERN_PROC_PATHNAME };
#else
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
#endif
    size_t size = sizeof(buffer1);

    if (sysctl(mib, 4, path, &size, NULL, 0) != 0)
        break;

    resolved = realpath(path, buffer2);
    if (!resolved)
      break;

    length = (int)strlen(resolved);
    if (length <= capacity)
    {
      memcpy(out, resolved, length);

      if (dirname_length)
      {
        int i;

        for (i = length - 1; i >= 0; --i)
        {
          if (out[i] == '/')
          {
            *dirname_length = i;
            break;
          }
        }
      }
    }
  }

  return ok ? length : -1;
}

#endif

WAI_NOINLINE WAI_FUNCSPEC
int WAI_PREFIX(getModulePath)(char* out, int capacity, int* dirname_length)
{
  char buffer[PATH_MAX];
  char* resolved = NULL;
  int length = -1;

  for(;;)
  {
    Dl_info info;

    if (dladdr(WAI_RETURN_ADDRESS(), &info))
    {
      resolved = realpath(info.dli_fname, buffer);
      if (!resolved)
        break;

      length = (int)strlen(resolved);
      if (length <= capacity)
      {
        memcpy(out, resolved, length);

        if (dirname_length)
        {
          int i;

          for (i = length - 1; i >= 0; --i)
          {
            if (out[i] == '/')
            {
              *dirname_length = i;
              break;
            }
          }
        }
      }
    }

    break;
  }

  return length;
}

#else

#error unsupported platform

#endif
