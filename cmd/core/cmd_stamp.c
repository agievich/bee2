/*
*******************************************************************************
\file cmd_stamp.c
\brief Command-line interface to Bee2: file stamps
\project bee2/cmd 
\created 2025.04.21
\version 2025.05.27
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/der.h>
#include <bee2/core/file.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include "../cmd.h"

/*
*******************************************************************************
Управление штампом
*******************************************************************************
*/

/*!	\brief Штамп файла

	Вычисляется штамп stamp файла name. Штамп представляет собой обратный
	DER-код  хэш-значения файла, вычисленного с помощью алгоритма bash64.
	При установке флага suffix анализируется суффикс файла. Если файл содержит
	суффикс и в суффиксе записан штамп, то суффикс исключается из хэширования,
	а вычисленный штамп сравнивается со штампом суффикса.
	\return Если suffix == TRUE, то возврашается:
	- ERR_OK, если штамп успешно вычислен, подходящий суффикс обнаружен и
	  штамп суффикса совпадает с вычисленным штампом;
	- ERR_MAX, если штамп успешно вычислен, а подходящий суффикс не обнаружен;
	- ERR_FILE_STAMP, если штамп успешно вычислен, подходящий суффикс обнаружен
	  и штамп суффикса не совпадает с вычисленным штампом;
	- другие коды при ошибках вычисления штампа.
	Если suffix == FALSE, то возвращается ERR_OK при успешном вычислении штампа
	и код ошибки в противном случае.
	\remark При suffix == TRUE можно передать нулевой указатель stamp, и тогда
	код ERR_MAX будет возвращен сразу после обнаружения отсутствия подходящего
	суффикса, без вычисления штампа файла.
	\remark За один вызов cmdFileStamp(stamp, name, TRUE) можно проверить штамп
	суффикса и, если суффикса нет или в суффиксе нет штампа, вычислить штамп.
*/
static err_t cmdFileStamp(
	octet* stamp,			/*!< [out] штамп */
	const char* name,		/*!< [in] имя файла */
	bool_t suffix			/*!< [in] анализировать суффикс */
)
{
	const size_t buf_size = 4096;
	err_t code;
	octet* stack;
	octet* buf;			/* [buf_size] */
	octet* stamp1;		/* [10] */
	octet* stamp2;		/* [10] */
	octet* state;		/* [bashHash_keep()] */
	file_t file;
	size_t count;
	bool_t stamped;
	// pre
	ASSERT((suffix == TRUE && stamp == 0) || memIsValid(stamp, 10));
	ASSERT(strIsValid(name));
	// выделить и разметить память
	code = cmdBlobCreate(stack, buf_size + 20 + bashHash_keep());
	ERR_CALL_CHECK(code);
	buf = stack;
	stamp1 = buf + buf_size;
	stamp2 = stamp1 + 10;
	state = stamp2 + 10;
	// открыть файл
	code = cmdFileOpen(file, name, "rb");
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить размер файла
	if ((count = fileSize(file)) == SIZE_MAX)
		code = ERR_FILE_READ;
	ERR_CALL_HANDLE(code, (cmdFileClose(file), cmdBlobClose(stack)));
	// штамп в суффиксе?
	stamped = FALSE;
	if (suffix && count >= 10)
	{
		if (!fileSeek(file, count - 10, SEEK_SET) ||
			fileRead2(stamp2, 10, file) != 10 ||
			!fileSeek(file, 0, SEEK_SET))
			code = ERR_FILE_READ;
		ERR_CALL_HANDLE(code, (cmdFileClose(file), cmdBlobClose(stack)));
		memRev(stamp2, 10);
		stamped = (derOCTDec2(0, stamp2, 10, 8) == 10);
		memRev(stamp2, 10);
	}
	if (stamp == 0 && !stamped)
		code = ERR_MAX;
	ERR_CALL_HANDLE(code, (cmdFileClose(file), cmdBlobClose(stack)));
	// определить объем хэшируемой части файла
	count = stamped ? count - 10 : count;
	// хэшировать файл
	bashHashStart(state, 32);
	while (count)
	{
		size_t c = MIN2(count, buf_size);
		if (fileRead2(buf, c, file) != c)
			code = ERR_FILE_READ;
		ERR_CALL_HANDLE(code, (cmdFileClose(file), cmdBlobClose(stack)));
		bashHashStepH(buf, c, state);
		count -= c;
	}
	// закрыть файл
	code = cmdFileClose2(file);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// завершить хэширование и кодировать
	bashHashStepG(stamp1, 8, state);
	VERIFY(derOCTEnc(stamp1, stamp1, 8) == 10);
	memRev(stamp1, 10);
	// проверить суффикс
	if (suffix)
	{
		if (stamped)
			code = memEq(stamp1, stamp2, 10) ? ERR_OK : ERR_FILE_STAMP;
		else
			code = ERR_MAX;
	}
	// возвратить штамп
	if (stamp)
		memCopy(stamp, stamp1, 10);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Генерация штампа
*******************************************************************************
*/

err_t cmdStampGen(const char* stamp_name, const char* name)
{
	err_t code;
	octet* stamp;
	// входной контроль
	if (!strIsValid(name) || !strIsValid(stamp_name))
		return ERR_BAD_INPUT;
	// сгенерировать штамп
	code = cmdBlobCreate(stamp, 10);
	ERR_CALL_CHECK(code);
	cmdFileStamp(stamp, name, FALSE);
	// сохранить штамп
	if (cmdFileAreSame(name, stamp_name))
		code = cmdFileAppend(name, stamp, 10);
	else
		code = cmdFileWrite(stamp_name, stamp, 10);
	// завершить
	cmdBlobClose(stamp);
	return code;
}

/*
*******************************************************************************
Проверка штампа
*******************************************************************************
*/

err_t cmdStampVal(const char* name, const char* stamp_name)
{
	err_t code;
	// входной контроль
	if (!strIsValid(name) || !strIsValid(stamp_name))
		return ERR_BAD_INPUT;
	// проверить прикрепленный штамп
	if (cmdFileAreSame(name, stamp_name))
	{
		code = cmdFileStamp(0, name, TRUE);
		if (code == ERR_MAX)
			code = ERR_FILE_STAMP;
	}
	// проверить открепленный штамп
	else
	{
		void* stack;
		octet* stamp;
		octet* stamp1;
		size_t count;
		// выделить и разметить память
		code = cmdBlobCreate(stack, 20);
		ERR_CALL_CHECK(code);
		stamp = (octet*)stack;
		stamp1 = stamp + 10;
		// вычислить штамп
		code = cmdFileStamp(stamp, name, FALSE);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// прочитать штамп
		count = 10;
		code = cmdFileReadAll(stamp1, &count, stamp_name);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// сравнить
		if (!memEq(stamp, stamp1, 10))
			code = ERR_FILE_STAMP;
		cmdBlobClose(stack);
	}
	return code;
}

err_t cmdStampSelfVal()
{
	const char* ext = ".stamp";
	err_t code;
	size_t count;
	void* stack;
	octet* stamp;
	octet* stamp1;
	char* name;
	// определить длину имени исполняемого модуля
	code = cmdSysModulePath(0, &count);
	ERR_CALL_CHECK(code);
	// выделить и разметить память
	code = cmdBlobCreate(stack, 10 + 10 + count + strLen(ext));
	ERR_CALL_CHECK(code);
	stamp = (octet*)stack;
	stamp1 = stamp + 10;
	name = (char*)(stamp1 + 10);
	// определить имя исполняемого модуля
	code = cmdSysModulePath(name, &count);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить присоединенный штамп
	code = cmdFileStamp(stamp, name, TRUE);
	// в файле нет штампа?
	if (code == ERR_MAX)
	{
		count = 10;
		// прочитать отсоединенный штамп
		strCopy(name + strLen(name), ext);
		code = cmdFileReadAll(stamp1, &count, name);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// проверить отсоединенный штамп
		if (!memEq(stamp, stamp1, 10))
			code = ERR_FILE_STAMP;
	}
	// завершить
	cmdBlobClose(stack);
	return code;
}
