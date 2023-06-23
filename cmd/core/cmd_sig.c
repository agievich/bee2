/*
*******************************************************************************
\file cmd_sig.c
\brief Command-line interface to Bee2: signing files
\project bee2/cmd
\created 2022.08.20
\version 2023.06.23
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/err.h>
#include <bee2/core/blob.h>
#include <bee2/core/der.h>
#include <bee2/core/dec.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/bign96.h>
#include <bee2/crypto/btok.h>
#include <stdio.h>

/*
*******************************************************************************
Кодирование подписи

  SEQ Signature
    SEQ OF CVCertificate
    OCT(SIZE(48|72|96)) -- sig
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

static bool_t cmdSigSeemsValid(const cmd_sig_t* sig)
{
	size_t certs_len;
	const octet* cert;
	size_t cert_len;
	// проверить память и длины
	if (!memIsValid(sig, sizeof(cmd_sig_t)) ||
		!(sig->sig_len == 34 || sig->sig_len == 48 || sig->sig_len == 72 ||
			sig->sig_len == 96) ||
		sig->certs_len > sizeof(sig->certs))
		return FALSE;
	// проверить сертификаты
	for (certs_len = sig->certs_len, cert = sig->certs; certs_len; )
	{
		cert_len = btokCVCLen(cert, certs_len);
		if (cert_len == SIZE_MAX)
			return FALSE;
		cert += cert_len, certs_len -= cert_len;
	}
	// проверить дату
	return memIsZero(sig->date, 6) || tmDateIsValid2(sig->date);
}

static size_t cmdSigEnc(octet buf[], const cmd_sig_t* sig)
{
    der_anchor_t Signature[1];
	size_t count = 0;
	// pre
	ASSERT(cmdSigSeemsValid(sig));
	// начать кодирование...
	derEncStep(derSEQEncStart(Signature, buf, count), buf, count);
	// ...сертификаты...
	derEncStep(derEnc(buf, 0x30, sig->certs, sig->certs_len), buf, count);
	// ...дата...
	if (!memIsZero(sig->date, 6))
		derEncStep(derOCTEnc(buf, sig->date, 6), buf, count);
	// ...подпись...
	derEncStep(derOCTEnc(buf, sig->sig, sig->sig_len), buf, count);
	// ...завершить кодирование
	derEncStep(derSEQEncStop(buf, count, Signature), buf, count);
	// возвратить длину DER-кода
	return count;
}

static size_t cmdSigDec(cmd_sig_t* sig, const octet der[], size_t count)
{
	der_anchor_t Signature[1];
	const octet* ptr = der;
	const octet* val;
	size_t len;
	// pre
	ASSERT(memIsDisjoint2(sig, sizeof(cmd_sig_t), der, count));
	// начать декодирование...
	memSetZero(sig, sizeof(cmd_sig_t));
	derDecStep(derSEQDecStart(Signature, ptr, count), ptr, count);
	// ...сертификаты...
	derDecStep(derDec2(&val, &len, ptr, count, 0x30), ptr, count);
	if (len > sizeof(sig->certs))
		return SIZE_MAX;
	memCopy(sig->certs, val, sig->certs_len = len);
	// ...дата...
	memSetZero(sig->date, 6);
	if (derOCTDec2(0, ptr, count, 6) != SIZE_MAX)
		derDecStep(derOCTDec2(sig->date, ptr, count, 6), ptr, count);
	// ...подпись...
	if (derOCTDec2(0, ptr, count, sig->sig_len = 34) == SIZE_MAX &&
		derOCTDec2(0, ptr, count, sig->sig_len = 48) == SIZE_MAX &&
		derOCTDec2(0, ptr, count, sig->sig_len = 72) == SIZE_MAX &&
		derOCTDec2(0, ptr, count, sig->sig_len = 96) == SIZE_MAX)
		return SIZE_MAX;
	derDecStep(derOCTDec2(sig->sig, ptr, count, sig->sig_len), ptr, count);
	// ...завершить декодирование
	derDecStep(derSEQDecStop(ptr, Signature), ptr, count);
	// предварительная проверка результата
	if (!cmdSigSeemsValid(sig))
		return SIZE_MAX;
	// возвратить точную длину DER-кода
	return ptr - der;
}

/*
*******************************************************************************
Запись в файл / чтение из файла обратного DER-кода подписи
*******************************************************************************
*/

static err_t cmdSigWrite(const char* sig_file, const cmd_sig_t* sig)
{
	err_t code;
	octet* der;
	size_t len;
	// pre
	ASSERT(cmdSigSeemsValid(sig));
	ASSERT(strIsValid(sig_file));
	// определить длину DER-кода
	len = cmdSigEnc(0, sig);
	code = len != SIZE_MAX ? ERR_OK : ERR_BAD_SIG;
	ERR_CALL_CHECK(code);
	// подготовить память
	code = cmdBlobCreate(der, len);
	ERR_CALL_CHECK(code);
	// кодировать
	cmdSigEnc(der, sig);
	memRev(der, len);
	// записать код в файл
	code = cmdFileWrite(sig_file, der, len);
	// завершить
	cmdBlobClose(der);
	return code;
}

static err_t cmdSigAppend(const char* sig_file, const cmd_sig_t* sig)
{
	err_t code;
	octet* der;
	size_t len;
	// pre
	ASSERT(cmdSigSeemsValid(sig));
	ASSERT(strIsValid(sig_file));
	// определить длину DER-кода
	len = cmdSigEnc(0, sig);
	code = len != SIZE_MAX ? ERR_OK : ERR_BAD_SIG;
	ERR_CALL_CHECK(code);
	// подготовить память
	code = cmdBlobCreate(der, len);
	ERR_CALL_CHECK(code);
	// кодировать
	cmdSigEnc(der, sig);
	memRev(der, len);
	// дописать код к файлу
	code = cmdFileAppend(sig_file, der, len);
	// завершить
	cmdBlobClose(der);
	return code;
}

err_t cmdSigRead(cmd_sig_t* sig, size_t* sig_len, const char* sig_file)
{
	err_t code;
	size_t file_size;
	octet suffix[16];
	octet* der;
	size_t count;
	size_t len;
	FILE* fp;
	u32 tag;
	// pre
	ASSERT(memIsValid(sig, sizeof(cmd_sig_t)));
	ASSERT(memIsNullOrValid(sig_len, O_PER_S));
	ASSERT(strIsValid(sig_file));
	// определить длину суффикса файла
	file_size = cmdFileSize(sig_file);
	code = file_size == SIZE_MAX ? ERR_FILE_READ : ERR_OK;
	ERR_CALL_CHECK(code);
	count = MIN2(file_size, sizeof(suffix));
	// открыть файл для чтения
	fp = fopen(sig_file, "rb");
	code = fp ? ERR_OK : ERR_FILE_OPEN;
	ERR_CALL_CHECK(code);
	// читать суффикс
	code = fseek(fp, -(long)count, SEEK_END) == 0 ? ERR_OK : ERR_FILE_READ;
	ERR_CALL_HANDLE(code, fclose(fp));
	code = fread(suffix, 1, count, fp) == count ? ERR_OK : ERR_FILE_READ;
	ERR_CALL_HANDLE(code, fclose(fp));
	// развернуть октеты суффикса
	memRev(suffix, count);
	// определить длину TL-префикса DER-кода
	count = derTLDec(&tag, &len, suffix, count);
	code = (count != SIZE_MAX && tag == 0x30) ? ERR_OK : ERR_BAD_SIG;
	ERR_CALL_HANDLE(code, fclose(fp));
	// определить длину DER-кода
	count += len;
	code = count <= file_size ? ERR_OK : ERR_BAD_SIG;
	ERR_CALL_HANDLE(code, fclose(fp));
	// подготовить память
	code = cmdBlobCreate(der, count);
	ERR_CALL_HANDLE(code, fclose(fp));
	// читать DER-код и закрыть файл
	code = fseek(fp, (long)(file_size - count), SEEK_SET) == 0 ?
		ERR_OK : ERR_FILE_READ;
	ERR_CALL_HANDLE(code, (cmdBlobClose(der), fclose(fp)));
	code = fread(der, 1, count, fp) == count ? ERR_OK : ERR_FILE_READ;
	fclose(fp);
	ERR_CALL_HANDLE(code, cmdBlobClose(der));
	// декодировать
	memRev(der, count);
	code = cmdSigDec(sig, der, count) == count ? ERR_OK : ERR_BAD_SIG;
	// возвратить длину DER-кода
	if (sig_len)
		*sig_len = count;
	// завершить
	cmdBlobClose(der);
	return code;
}

/*
*******************************************************************************
Хэширование файла

Хэшируются содержимое file без заключительных drop октетов,
цепочка сертификатов [certs_len]certs и дата date, т.е. буфер
  file[:-drop] || [certs_len]certs || [6]date.
Алгоритм хэширования определяется по длине возвращаемого хэш-значения.
*******************************************************************************
*/

static err_t cmdSigHash(octet hash[], size_t hash_len, const char* file,
	size_t drop, const octet certs[], size_t certs_len, const octet date[6])
{
	const size_t buf_size = 4096;
	err_t code;
	octet* stack;
	octet* state;
	size_t file_size;
	FILE* fp;
	// pre
	ASSERT(hash_len == 24 || hash_len == 32 || hash_len == 48 ||
		hash_len == 64);
	ASSERT(memIsValid(hash, hash_len));
	ASSERT(strIsValid(file));
	// выделить память
	code = cmdBlobCreate(stack, buf_size +
		(hash_len <= 32 ? beltHash_keep() : bashHash_keep()));
	ERR_CALL_CHECK(code);
	// запустить хэширование
	state = stack + buf_size;
	if (hash_len <= 32)
		beltHashStart(state);
	else
		bashHashStart(state, hash_len * 4);
	// определить размер файла
	file_size = cmdFileSize(file);
	code = file_size != SIZE_MAX ? ERR_OK : ERR_FILE_READ;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить размер хэшируемой части файла
	code = drop <= file_size ? ERR_OK : ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	file_size -= drop;
	// открыть файл для чтения
	fp = fopen(file, "rb");
	code = fp ? ERR_OK : ERR_FILE_OPEN;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// хэшировать файл
	while (file_size)
	{
		// прочитать фрагмент
		size_t count = MIN2(file_size, buf_size);
		code = fread(stack, 1, count, fp) == count ? ERR_OK : ERR_FILE_READ;
		ERR_CALL_HANDLE(code, (fclose(fp), cmdBlobClose(stack)));
		file_size -= count;
		// хэшировать фрагмент
		if (hash_len <= 32)
			beltHashStepH(stack, count, state);
		else
			bashHashStepH(stack, count, state);
	}
	fclose(fp);
	// хэшировать сертификаты и дату
	if (hash_len <= 32)
	{
		beltHashStepH(certs, certs_len, state);
		beltHashStepH(date, 6, state);
		beltHashStepG2(hash, hash_len, state);
	}
	else
	{
		bashHashStepH(certs, certs_len, state);
		bashHashStepH(date, 6, state);
		bashHashStepG(hash, hash_len, state);
	}
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Долговременные параметры
*******************************************************************************
*/

static err_t cmdSigStdParams(bign_params* params, size_t privkey_len)
{
	switch (privkey_len)
	{
	case 24:
		return bign96StdParams(params, "1.2.112.0.2.0.34.101.45.3.0");
	case 32:
		return bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1");
	case 48:
		return bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.2");
	case 64:
		return bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3");
	}
	return ERR_BAD_INPUT;
}

/*
*******************************************************************************
Выработка подписи
*******************************************************************************
*/

err_t cmdSigSign(const char* sig_file, const char* file, const char* certs,
	const octet date[6], const octet privkey[], size_t privkey_len)
{
	err_t code;
	void* stack;
	cmd_sig_t* sig;
	bign_params* params;
	octet* oid_der;
	size_t oid_len = 16;
	octet* hash;
	octet* t;
	size_t t_len;
	// входной контроль
	if (!strIsValid(sig_file) || !strIsValid(file) ||
		!(privkey_len == 24 || privkey_len == 32 || privkey_len == 48 || 
			privkey_len == 64) ||
		!memIsValid(date, 6) ||
		!memIsValid(privkey, privkey_len))
		return ERR_BAD_INPUT;
	if (!memIsZero(date, 6) && !tmDateIsValid2(date))
		return ERR_BAD_DATE;
	// создать и разметить стек
	code = cmdBlobCreate(stack,
		sizeof(cmd_sig_t) + sizeof(bign_params) + oid_len + 2 * privkey_len);
	ERR_CALL_CHECK(code);
	sig = (cmd_sig_t*)stack;
	params = (bign_params*)(sig + 1);
	oid_der = (octet*)(params + 1);
	hash = oid_der + 16;
	t = hash + privkey_len;
	// зафиксировать дату
	memCopy(sig->date, date, 6);
	// указаны сертификаты?
	if (certs)
	{
		// собрать сертификаты
		sig->certs_len = sizeof(sig->certs);
		code = cmdCVCsCreate(sig->certs, &sig->certs_len, certs);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// проверить цепочку
		code = cmdCVCsVal(sig->certs, sig->certs_len, sig->date);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	}
	else
		sig->certs_len = 0;
	// проверить соответствие личному ключу
	if (sig->certs_len)
	{
		size_t offset;
		size_t cert_len;
		// найти последний сертификат
		code = cmdCVCsGetLast(&offset, &cert_len, sig->certs, sig->certs_len);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// проверить соответствие личному ключу
		code = btokCVCMatch(sig->certs + offset, cert_len, privkey,
			privkey_len);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	}
	// загрузить долговременные параметры
	code = cmdSigStdParams(params, privkey_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// хэшировать
	code = cmdSigHash(hash, privkey_len, file, 0, sig->certs, sig->certs_len, 
		sig->date);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	if (privkey_len <= 32)
	{
		code = bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		ASSERT(oid_len == 11);
	}
	else 
	{
		code = bignOidToDER(oid_der, &oid_len, privkey_len == 48 ? 
			"1.2.112.0.2.0.34.101.77.12" : "1.2.112.0.2.0.34.101.77.13");
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		ASSERT(oid_len == 11);
	}
	// получить случайные числа
	if (rngIsValid())
		rngStepR(t, t_len = privkey_len, 0);
	else
		t_len = 0;
	// подписать
	if (privkey_len == 24)
	{
		code = bign96Sign2(sig->sig, params, oid_der, oid_len, hash, privkey, 
			t, t_len);
		sig->sig_len = 34;
	}
	else
	{
    	code = bignSign2(sig->sig, params, oid_der, oid_len, hash, privkey, 
			t, t_len);
		sig->sig_len = privkey_len / 2 * 3;
	}
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// сохранить подпись
	if (cmdFileAreSame(file, sig_file))
		code = cmdSigAppend(sig_file, sig);
	else
		code = cmdSigWrite(sig_file, sig);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Проверка подписи
*******************************************************************************
*/

err_t cmdSigVerify(const char* file, const char* sig_file,
	const octet pubkey[], size_t pubkey_len)
{
	err_t code;
	void* stack;
	cmd_sig_t* sig;
	btok_cvc_t* cvc;
	bign_params* params;
	octet* oid_der;
	size_t oid_len = 16;
	octet* hash;
	size_t drop;
	// входной контроль
	if (!strIsValid(file) || !strIsValid(sig_file) ||
		!(pubkey_len == 48 || pubkey_len == 64 || pubkey_len == 96 || 
			pubkey_len == 128) ||
		!memIsValid(pubkey, pubkey_len))
		return ERR_BAD_INPUT;
	// создать и разметить стек
	code = cmdBlobCreate(stack, sizeof(cmd_sig_t) + sizeof(btok_cvc_t) +
		sizeof(bign_params) + oid_len + pubkey_len / 2);
	ERR_CALL_CHECK(code);
	sig = (cmd_sig_t*)stack;
	cvc = (btok_cvc_t*)(sig + 1);
	params = (bign_params*)(cvc + 1);
	oid_der = (octet*)(params + 1);
	hash = oid_der + oid_len;
	// читать подпись
	code = cmdSigRead(sig, &drop, sig_file);	
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// подпись в отдельном файле?
	if (!cmdFileAreSame(file, sig_file))
	{
		code = drop == cmdFileSize(sig_file) ? ERR_OK : ERR_BAD_FORMAT;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		drop = 0;
	}
	// проверить сертификаты
	code = cmdCVCsVal(sig->certs, sig->certs_len, sig->date);	
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// есть сертификаты?
	if (sig->certs_len)
	{
		size_t offset;
		size_t cert_len;
		// найти и разобрать последний сертификат
		code = cmdCVCsGetLast(&offset, &cert_len, sig->certs, sig->certs_len);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		code = btokCVCUnwrap(cvc, sig->certs + offset, cert_len, 0, 0);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// проверить открытый ключ последнего сертификата
		if (pubkey_len != cvc->pubkey_len ||
			!memEq(pubkey, cvc->pubkey, pubkey_len))
			code = ERR_BAD_PUBKEY;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	}
	// загрузить долговременные параметры
	code = cmdSigStdParams(params, pubkey_len / 2);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// хэшировать
	code = cmdSigHash(hash, pubkey_len / 2, file, drop, sig->certs, 
		sig->certs_len, sig->date);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	if (pubkey_len <= 64)
	{
		code = bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		ASSERT(oid_len == 11);
	}
	else 
	{
		code = bignOidToDER(oid_der, &oid_len, pubkey_len == 96 ? 
			"1.2.112.0.2.0.34.101.77.12" : "1.2.112.0.2.0.34.101.77.13");
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		ASSERT(oid_len == 11);
	}
	// проверить открытый ключ
	if (pubkey_len == 48)
		code = bign96ValPubkey(params, pubkey);
	else
		code = bignValPubkey(params, pubkey);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить подпись
	if (pubkey_len == 48)
		code = bign96Verify(params, oid_der, oid_len, hash, sig->sig, pubkey);
	else
		code = bignVerify(params, oid_der, oid_len, hash, sig->sig, pubkey);
	// завершить
	cmdBlobClose(stack);
	return code;
}

err_t cmdSigVerify2(const char* file, const char* sig_file,
	const octet anchor[], size_t anchor_len)
{
	err_t code;
	void* stack;
	cmd_sig_t* sig;
	btok_cvc_t* cvc;
	bign_params* params;
	octet* oid_der;
	size_t oid_len = 16;
	octet* hash;
	size_t drop;
	size_t offset;
	size_t cert_len;
	// входной контроль
	if (!strIsValid(file) || !strIsValid(sig_file) ||
		!memIsValid(anchor, anchor_len))
		return ERR_BAD_INPUT;
	// создать и разметить стек
	code = cmdBlobCreate(stack, sizeof(cmd_sig_t) + sizeof(btok_cvc_t) +
		sizeof(bign_params) + oid_len + 64);
	ERR_CALL_CHECK(code);
	sig = (cmd_sig_t*)stack;
	cvc = (btok_cvc_t*)(sig + 1);
	params = (bign_params*)(cvc + 1);
	oid_der = (octet*)(params + 1);
	hash = oid_der + oid_len;
	// читать подпись
	code = cmdSigRead(sig, &drop, sig_file);	
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// подпись в отдельном файле?
	if (!cmdFileAreSame(file, sig_file))
	{
		code = drop == cmdFileSize(sig_file) ? ERR_OK : ERR_BAD_FORMAT;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		drop = 0;
	}
	// цепочка сертификатов включает anchor?
	code = cmdCVCsFind(0, sig->certs, sig->certs_len, anchor, anchor_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить цепочку
	code = cmdCVCsVal(sig->certs, sig->certs_len, sig->date);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// найти последний сертификат
	code = cmdCVCsGetLast(&offset, &cert_len, sig->certs, sig->certs_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// разобрать последний сертификат
	code = btokCVCUnwrap(cvc, sig->certs + offset, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// загрузить долговременные параметры
	code = cmdSigStdParams(params, cvc->pubkey_len / 2);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// хэшировать
	code = cmdSigHash(hash, cvc->pubkey_len / 2, file, drop, sig->certs, 
		sig->certs_len, sig->date);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	if (cvc->pubkey_len <= 64)
	{
		code = bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		ASSERT(oid_len == 11);
	}
	else 
	{
		code = bignOidToDER(oid_der, &oid_len, cvc->pubkey_len == 96 ? 
			"1.2.112.0.2.0.34.101.77.12" : "1.2.112.0.2.0.34.101.77.13");
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		ASSERT(oid_len == 11);
	}
	// проверить открытый ключ
	if (cvc->pubkey_len == 48)
		code = bign96ValPubkey(params, cvc->pubkey);
	else
		code = bignValPubkey(params, cvc->pubkey);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить подпись
	if (cvc->pubkey_len == 48)
		code = bign96Verify(params, oid_der, oid_len, hash, sig->sig, 
			cvc->pubkey);
	else
		code = bignVerify(params, oid_der, oid_len, hash, sig->sig, 
			cvc->pubkey);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Самопроверка

\thanks Gregory Pakosz [https://github.com/gpakosz/whereami]
*******************************************************************************
*/

#include "whereami.h"

err_t cmdSigSelfVerify(const octet pubkey[], size_t pubkey_len)
{
    err_t code;
    int len;
    char* buf;
	// определить имя исполнимого файла
    len = wai_getExecutablePath(0, 0, 0);
    if (len < 0)
        return ERR_SYS;
    code = cmdBlobCreate(buf, (size_t)len + 1);
	ERR_CALL_CHECK(code);
    if (wai_getExecutablePath(buf, len, 0) != len)
		code = ERR_SYS;
	ERR_CALL_HANDLE(code, cmdBlobClose(buf));
	// проверить подпись
    code = cmdSigVerify(buf, buf, pubkey, pubkey_len);
	// завершить
    cmdBlobClose(buf);
    return code;
}

err_t cmdSigSelfVerify2(const octet anchor[], size_t anchor_len)
{
    err_t code;
    int len;
    char* buf;
	// определить имя исполнимого файла
    len = wai_getExecutablePath(0, 0, 0);
    if (len < 0)
        return ERR_SYS;
    code = cmdBlobCreate(buf, (size_t)len + 1);
	ERR_CALL_CHECK(code);
    if (wai_getExecutablePath(buf, len, 0) != len)
		code = ERR_SYS;
	ERR_CALL_HANDLE(code, cmdBlobClose(buf));
	// проверить подпись
    code = cmdSigVerify2(buf, buf, anchor, anchor_len);
	// завершить
    cmdBlobClose(buf);
    return code;
}

/*
*******************************************************************************
Извлечение объекта
*******************************************************************************
*/

err_t cmdSigExtr(const char* obj_file, const char* sig_file, const char* scope)
{
	err_t code;
	void* stack;
	cmd_sig_t* sig;
	size_t sig_len;
	// входной контроль
	if (!strIsValid(sig_file) || !strIsValid(obj_file) || !strIsValid(scope))
		return ERR_BAD_INPUT;
	if (!strEq(scope, "body") &&
		!strEq(scope, "sig") &&
		!strStartsWith(scope, "cert"))
		return ERR_CMD_PARAMS;
	// создать и разметить стек
	code = cmdBlobCreate(stack, sizeof(cmd_sig_t));
	ERR_CALL_CHECK(code);
	sig = (cmd_sig_t*)stack;
	// читать подпись
	code = cmdSigRead(sig, &sig_len, sig_file);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// извлечь сертификат?
	if (strStartsWith(scope, "cert"))
	{
		size_t num;
		size_t certs_len;
		const octet* cert;
		size_t cert_len;
		size_t pos;
		// определить номер сертификата
		scope += strLen("cert");
		if (!decIsValid(scope) || strLen(scope) != 1)
			code = ERR_CMD_PARAMS;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		num = decToU32(scope);
		// искать сертификат
		certs_len = sig->certs_len, cert = sig->certs, cert_len = pos = 0;
		while (certs_len)
		{
			cert_len = btokCVCLen(cert, certs_len);
			if (cert_len == SIZE_MAX || pos == num)
				break;
			certs_len -= cert_len, cert += cert_len, ++pos;
		}
		// найден? записать в файл
		if (pos == num && cert_len != 0 && cert_len != SIZE_MAX)
			code = cmdFileWrite(obj_file, cert, cert_len);
		else
			code = ERR_BAD_CERT;
	}
	else if (strEq(scope, "body"))
	{
		size_t size = cmdFileSize(sig_file);
		if (size == SIZE_MAX)
			code = ERR_FILE_READ;
		else if (size == sig_len)
			code = ERR_BAD_FORMAT;
		else
			code = cmdFileDup(obj_file, sig_file, 0, size - sig_len);
	}
	else
	{
		size_t size = cmdFileSize(sig_file);
		if (size == SIZE_MAX)
			code = ERR_FILE_READ;
		else
			code = cmdFileDup(obj_file, sig_file, size - sig_len, sig_len);
	}
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Печать подписи
*******************************************************************************
*/

static err_t cmdSigPrintCertc(const cmd_sig_t* sig)
{
	size_t certs_len;
	const octet* cert;
	size_t cert_len;
	size_t count;
	// определить число сертификатов
	certs_len = sig->certs_len, cert = sig->certs, count = 0;
	while (certs_len)
	{
		cert_len = btokCVCLen(cert, certs_len);
		if (cert_len == SIZE_MAX)
			return ERR_BAD_CERT;
		certs_len -= cert_len, cert += cert_len, ++count;
	}
	// печатать число сертификатов
	printf("%u", (unsigned)count);
	return ERR_OK;
}

err_t cmdSigPrint(const char* sig_file, const char* scope)
{
	err_t code;
	void* stack;
	cmd_sig_t* sig;
	// входной контроль
	if (!strIsValid(sig_file) || !strIsValid(scope))
		return ERR_BAD_INPUT;
	// создать и разметить стек
	code = cmdBlobCreate(stack, sizeof(cmd_sig_t));
	ERR_CALL_CHECK(code);
	sig = (cmd_sig_t*)stack;
	// читать подпись
	code = cmdSigRead(sig, 0, sig_file);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// печать всех полей
	if (scope == 0)
	{
		printf("certc: ");
		code = cmdSigPrintCertc(sig);
		ERR_CALL_CHECK(code);
		if (!memIsZero(sig->date, 6))
		{
			printf("\ndate:  ");
			code = cmdPrintDate(sig->date);
			ERR_CALL_CHECK(code);
		}
		printf("\nsig:   ");
		code = cmdPrintMem2(sig->sig, sig->sig_len);
	}
	// печать отдельных полей
	else if (strEq(scope, "certc"))
		code = cmdSigPrintCertc(sig);
	else if (strEq(scope, "date"))
		code = memIsZero(sig->date, 6) ?
			ERR_BAD_DATE : cmdPrintDate(sig->date);
	else if (strEq(scope, "sig"))
		code = cmdPrintMem(sig->sig, sig->sig_len);
	else
		code = ERR_CMD_PARAMS;
	// завершить
	ERR_CALL_CHECK(code);
	printf("\n");
	return code;
}
