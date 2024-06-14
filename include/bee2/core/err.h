/*
*******************************************************************************
\file err.h
\brief Errors
\project bee2 [cryptographic library]
\created 2012.07.09
\version 2024.06.14
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
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

Обработка ошибок может быть упрощена с помощью макросов ERR_CALL_XXX.
*******************************************************************************
*/

/*!	brief Сообщение об ошибке

Формируется строка, которая содержит сообщение об ошибке с кодом code.
\return Строка с сообщением об ошибке, или 0, если ошибка нераспознана.
*/
const char* errMsg(
	err_t code			/*!< [in] код ошибки */
);


/*
*******************************************************************************
Sys
*******************************************************************************
*/

#define _ERR_REG(err) ((err_t)(err))

/* нераспознанная системная ошибка */
#define ERR_SYS						_ERR_REG(101)
/* некорректное устройство */
#define ERR_BAD_UNIT				_ERR_REG(102)
/* некорректный файл */
#define ERR_BAD_FILE				_ERR_REG(103)
/* некорректный таймер */
#define ERR_BAD_TIMER				_ERR_REG(104)
/* некорректная переменная окружения */
#define ERR_BAD_ENV					_ERR_REG(105)
/* некорректная функция */
#define ERR_BAD_FUNCTION			_ERR_REG(106)
/* некорректная команда */
#define ERR_BAD_COMMAND				_ERR_REG(107)
/* некорректная длина */
#define ERR_BAD_LENGTH				_ERR_REG(108)
/* некорректные входные данные */
#define ERR_BAD_INPUT				_ERR_REG(109)
/* не хватает памяти */
#define ERR_OUTOFMEMORY				_ERR_REG(110)
/* переполнение */
#define ERR_OVERFLOW				_ERR_REG(111)
/* объект не найден */
#define ERR_NOT_FOUND				_ERR_REG(112)
/* объект уже существует */
#define ERR_ALREADY_EXISTS			_ERR_REG(113)
/* доступ запрещен */
#define ERR_ACCESS_DENIED			_ERR_REG(114)
/* устройство не готово */
#define ERR_NOT_READY				_ERR_REG(115)
/* запрашиваемый ресурс занят */
#define ERR_BUSY					_ERR_REG(116)
/* таймаут */
#define ERR_TIMEOUT					_ERR_REG(117)
/* без результата */
#define ERR_NO_RESULT				_ERR_REG(118)
/* не реализовано */
#define ERR_NOT_IMPLEMENTED			_ERR_REG(119)
/* последствия предыдущих ошибок */
#define ERR_AFTER					_ERR_REG(120)

/*
*******************************************************************************
File
*******************************************************************************
*/

/* ошибка при создании файла */
#define ERR_FILE_CREATE				_ERR_REG(201)
/* файл не найден */
#define ERR_FILE_NOT_FOUND			_ERR_REG(202)
/* ошибка при открытии файла */
#define ERR_FILE_OPEN				_ERR_REG(203)
/* файл уже существует */
#define ERR_FILE_EXISTS				_ERR_REG(204)
/* слишком много открытых файлов */
#define ERR_FILE_TOO_MANY_OPEN		_ERR_REG(205)
/* ошибка записи в файл */
#define ERR_FILE_WRITE				_ERR_REG(206)
/* ошибка чтения из файла */
#define ERR_FILE_READ				_ERR_REG(207)
/* достигнут конец файла */
#define ERR_FILE_EOF				_ERR_REG(208)

/*
*******************************************************************************
Core
*******************************************************************************
*/

/* некорректный идентификатор объекта */
#define ERR_BAD_OID					_ERR_REG(301)
/* ошибка при сборе энтропии */
#define ERR_BAD_ENTROPY				_ERR_REG(302)
/* недостает энтропии */
#define ERR_NOT_ENOUGH_ENTROPY		_ERR_REG(303)
/* ошибка при обращении к генератору случайных чисел */
#define ERR_BAD_RNG					_ERR_REG(304)
/* ошибка при обращении к генератору произвольных чисел */
#define ERR_BAD_ANG					_ERR_REG(305)
/* неверный формат */
#define ERR_BAD_FORMAT				_ERR_REG(306)
/* некорректная отметка времени */
#define ERR_BAD_TIME				_ERR_REG(307)
/* некорректная дата */
#define ERR_BAD_DATE				_ERR_REG(308)
/* некорректное имя */
#define ERR_BAD_NAME				_ERR_REG(309)
/* вне диапазона */
#define ERR_OUTOFRANGE				_ERR_REG(310)
/* некорректный перечень прав доступа */
#define ERR_BAD_ACL					_ERR_REG(311)
/* некорректная APDU-команда/ответ */
#define ERR_BAD_APDU				_ERR_REG(312)

/*
*******************************************************************************
Math
*******************************************************************************
*/

/* некорректная точка эллиптической кривой */
#define ERR_BAD_POINT				_ERR_REG(401)
/* нарушена простота */
#define ERR_NOT_PRIME				_ERR_REG(402)
/* нарушена взаимная простота */
#define ERR_NOT_COPRIME				_ERR_REG(403)
/* многочлен не является неприводимым */
#define ERR_NOT_IRRED				_ERR_REG(404)

/*
*******************************************************************************
Crypto
*******************************************************************************
*/

/* некорректные долговременные параметры */
#define ERR_BAD_PARAMS				_ERR_REG(501)
/* некорректный секретный ключ */
#define ERR_BAD_SECKEY				_ERR_REG(502)
/* некорректный личный ключ */
#define ERR_BAD_PRIVKEY				_ERR_REG(503)
/* некорректный открытый ключ */
#define ERR_BAD_PUBKEY				_ERR_REG(504)
/* некорректная пара открытый / личный ключ */
#define ERR_BAD_KEYPAIR				_ERR_REG(505)
/* некорректный общий ключ */
#define ERR_BAD_SHAREDKEY			_ERR_REG(506)
/* некорректный частичный секрет */
#define ERR_BAD_SHAREKEY			_ERR_REG(507)
/* некорректное хэш-значение */
#define ERR_BAD_HASH				_ERR_REG(508)
/* некорректная ЭЦП */
#define ERR_BAD_SIG					_ERR_REG(509)
/* некорректная имитовставка */
#define ERR_BAD_MAC					_ERR_REG(510)
/* некорректная контрольная сумма */
#define ERR_BAD_CRC					_ERR_REG(511)
/* некорректный токен ключа */
#define ERR_BAD_KEYTOKEN			_ERR_REG(512)
/* некорректный сертификат (открытого ключа) */
#define ERR_BAD_CERT				_ERR_REG(513)
/* некорректный якорь сертификатов */
#define ERR_BAD_ANCHOR				_ERR_REG(514)
/* некорректное кольцо сертификатов */
#define ERR_BAD_CERTRING			_ERR_REG(515)
/* неверная логика (протокола) */
#define ERR_BAD_LOGIC				_ERR_REG(516)
/* неверный пароль */
#define ERR_BAD_PWD					_ERR_REG(517)
/* ключ не найден */
#define ERR_KEY_NOT_FOUND			_ERR_REG(518)
/* отсутствует доверие */
#define ERR_NO_TRUST				_ERR_REG(519)
/* ошибка аутентификации */
#define ERR_AUTH					_ERR_REG(520)
/* ошибка самотестирования */
#define ERR_SELFTEST				_ERR_REG(521)
/* ошибка статистического тестирования */
#define ERR_STATTEST				_ERR_REG(522)
/* некорректные затравочные параметры */
#define ERR_BAD_SEED				_ERR_REG(523)

/*
*******************************************************************************
Cmd
*******************************************************************************
*/

/* команда не найдена */
#define ERR_CMD_NOT_FOUND			_ERR_REG(601)
/* команда уже зарегистрирована */
#define ERR_CMD_EXISTS				_ERR_REG(602)
/* неверные параметры команды */
#define ERR_CMD_PARAMS				_ERR_REG(603)
/* повтор параметров команды */
#define ERR_CMD_DUPLICATE			_ERR_REG(604)

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
