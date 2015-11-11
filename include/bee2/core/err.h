/*
*******************************************************************************
\file err.h
\brief Errors
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.07.09
\version 2014.04.28
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file err.h
\brief Ошибки
*******************************************************************************
*/

#ifndef __BEE2_ERR_H
#define __BEE2_ERR_H

#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file err.h

Коды системных ошибок выбираются из диапазона 1 -- 3199. Коды системных
ошибок соответствуют кодам Windows. Код 32000 соответствует
неклассифицированной системной ошибке.

Обработка ошибок может быть ускорена с помощью макросов ERR_CALL_XXX.
*******************************************************************************
*/

#define _ERR_REG(err) ((err_t)(err))

/*
*******************************************************************************
Основные системные ошибки
*******************************************************************************
*/

/* ошибочное завершение */
#define ERR_INVALID_FUNCTION		_ERR_REG(1)
/* запрашиваемый файл или другой объект не найден */
#define ERR_FILE_NOT_FOUND			_ERR_REG(2)
/* слишком много открытых файлов */
#define ERR_TOO_MANY_OPEN_FILES		_ERR_REG(4)
/* доступ запрещен */
#define ERR_ACCESS_DENIED			_ERR_REG(5)
/* неверный дескриптор */
#define ERR_INVALID_HANDLE			_ERR_REG(6)
/* не хватает памяти для начала операции */
#define ERR_NOT_ENOUGH_MEMORY		_ERR_REG(8)
/* неверные данные */
#define ERR_INVALID_DATA			_ERR_REG(13)
/* не хватает памяти для завершения операции */
#define ERR_OUTOFMEMORY				_ERR_REG(14)
/* устройство не найдено */
#define ERR_BAD_UNIT				_ERR_REG(20)
/* устройство не готово */
#define ERR_NOT_READY				_ERR_REG(21)
/* устройство не поддерживает команду */
#define ERR_BAD_COMMAND				_ERR_REG(22)
/* неверная длина команды */
#define ERR_BAD_LENGTH				_ERR_REG(24)
/* ошибка записи на устройство */
#define ERR_WRITE_FAULT				_ERR_REG(29)
/* ошибка чтения с устройства */
#define ERR_READ_FAULT				_ERR_REG(30)
/* достигнут конец файла */
#define ERR_HANDLE_EOF				_ERR_REG(38)
/* запрос не поддерживается */
#define ERR_NOT_SUPPORTED			_ERR_REG(50)
/* устройство уже не существует */
#define ERR_DEV_NOT_EXIST			_ERR_REG(55)
/* файл уже существует */
#define ERR_FILE_EXISTS				_ERR_REG(80)
/* объект не может быть создан */
#define ERR_CANNOT_MAKE				_ERR_REG(82)
/* неверный параметр */
#define ERR_INVALID_PARAMETER		_ERR_REG(87)
/* невозможно открыть устройство или файл */
#define ERR_OPEN_FAILED				_ERR_REG(110)
/* очень длинное имя файла */
#define ERR_BUFFER_OVERFLOW			_ERR_REG(111)
/* операция не реализована */
#define ERR_NOT_IMPLEMENTED			_ERR_REG(120)
/* недостаточная длина буфера */
#define ERR_INSUFFICIENT_BUFFER		_ERR_REG(122)
/* некорректное имя */
#define ERR_INVALID_NAME			_ERR_REG(123)
/* запрашиваемый ресурс занят */
#define ERR_BUSY					_ERR_REG(170)
/* невозможно создать файл, который уже существует */
#define ERR_ALREADY_EXISTS			_ERR_REG(183)
/* pipe-соединение не установлено */
#define ERR_PIPE_NOT_CONNECTED		_ERR_REG(233)
/* таймаут при выполнении операции */
#define ERR_WAIT_TIMEOUT			_ERR_REG(258)
/* таймаут при ожидании открытия канала клиентом */
#define ERR_PIPE_CONNECTED			_ERR_REG(535)
/* операция ввода-вывода все еще выполняется */
#define ERR_IO_PENDING				_ERR_REG(997)
/* неизвестное свойство */
#define ERR_UNKNOWN_PROPERTY		_ERR_REG(1608)

/*
*******************************************************************************
Дополнительные системные ошибки
*******************************************************************************
*/

/* устройство не найдено */
#define ERR_DEV_NOT_FOUND			_ERR_REG(31997)
/* файл уже открыт */
#define ERR_ALREADY_OPEN			_ERR_REG(31999)
/* неклассифицированная системная ошибка */
#define ERR_SYS_FUNCTION			_ERR_REG(32000)

/*
*******************************************************************************
Прикладные ошибки
*******************************************************************************
*/

/* внутренняя ошибка */
#define ERR_INTERNAL				_ERR_REG(32001)
/* пустая ошибка (никогда не будет возвращена) */
#define ERR_VOID					_ERR_REG(32002)
/* некорректные входные данные */
#define ERR_BAD_INPUT				_ERR_REG(32003)
/* некорректные долговременные параметры */
#define ERR_BAD_PARAMS				_ERR_REG(32004)
/* некорректный секретный ключ */
#define ERR_BAD_SECKEY				_ERR_REG(32005)
/* некорректный личный ключ */
#define ERR_BAD_PRIVKEY				_ERR_REG(32006)
/* некорректный открытый ключ */
#define ERR_BAD_PUBKEY				_ERR_REG(32007)
/* некорректный сертификат (открытого ключа) */
#define ERR_BAD_CERT				_ERR_REG(32008)
/* некорректный общий ключ */
#define ERR_BAD_SHAREKEY			_ERR_REG(32009)
/* некорректное хэш-значение */
#define ERR_BAD_HASH				_ERR_REG(32010)
/* некорректная ЭЦП */
#define ERR_BAD_SIG					_ERR_REG(32011)
/* некорректная имитовставка */
#define ERR_BAD_MAC					_ERR_REG(32012)
/* некорректный токен ключа */
#define ERR_BAD_KEYTOKEN			_ERR_REG(32013)
/* ошибка аутентификации */
#define ERR_BAD_AUTH				_ERR_REG(32014)
/* недостаточно энтропии */
#define ERR_INSUFFICIENT_ENTROPY	_ERR_REG(32015)
/* ошибка при обращении к генератору случайных чисел */
#define ERR_BAD_RNG					_ERR_REG(32016)
/* ошибка при обращении к генератору произвольных чисел */
#define ERR_BAD_ANG					_ERR_REG(32017)
/* некорректный идентификатор объекта */
#define ERR_BAD_OID					_ERR_REG(32018)
/* некорректная точка эллиптической кривой */
#define ERR_BAD_POINT				_ERR_REG(32019)
/* нарушена простота */
#define ERR_NOT_PRIME				_ERR_REG(32020)
/* нарушена взаимная простота */
#define ERR_NOT_COPRIME				_ERR_REG(32021)
/* многочлен не является неприводимым */
#define ERR_NOT_IRRED				_ERR_REG(32022)
/* неверный формат */
#define ERR_BAD_FORMAT				_ERR_REG(32023)
/* неверная логика (протокола) */
#define ERR_BAD_LOGIC				_ERR_REG(32024)
/* неверный пароль */
#define ERR_BAD_PWD					_ERR_REG(32025)

/*
*******************************************************************************
Обработка ошибок
*******************************************************************************
*/

/*!	Если код ошибки, заданный в переменной code, совпадает с ERR_OK,
	то выполнить f и обновить код ошибки.
*/
#define ERR_CALL(code, f)\
	if ((code) == ERR_OK)\
		(code) = (f);\

/*!	Выйти, если код ошибки, заданный в переменной code, отличается
	от ERR_OK.
*/
#define ERR_CALL_CHECK(code)\
	if ((code) != ERR_OK)\
		return (code);\

/*!	Если код ошибки, заданный в переменной code, совпадает с ERR_OK
	и выполняется условие cond, то установить новый код ошибки new_code.
*/
#define ERR_CALL_SET(code, new_code, cond)\
	if ((code) == ERR_OK && (cond))\
		(code) = (new_code);\

/*!	Если код ошибки, заданный в переменной code, отличается от ERR_OK,
	то выполнить действие op и закончить работу.
*/
#define ERR_CALL_HANDLE(code, op)\
	if ((code) != ERR_OK) {\
		(op);\
		return (code);\
	}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_ERR_H */
