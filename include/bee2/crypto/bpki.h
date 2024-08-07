/*
*******************************************************************************
\file bpki.h
\brief STB 34.101.78 (bpki): PKI helpers
\project bee2/apps/bpki
\created 2021.04.03
\version 2023.12.19
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#ifndef __BEE2_BPKI_H
#define __BEE2_BPKI_H

#include "bee2/defs.h"

/*!
*******************************************************************************
\file bpki.h
\brief Механизмы СТБ 34.101.78 (bpki)
*******************************************************************************
*/


#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file bpki.h

Реализованы отдельные механизмы СТБ 34.101.78 (bpki):
- управление контейнерами с личными ключами СТБ 34.101.45 (bign);
- управление контейнерами с частичными секретами СТБ 34.101.60 (bels).

Дополнительно поддерживается размещение в контейнере личных ключей системы 
ЭЦП bign96 (см. bign.h) с долговременными параметрами bign-curve192v1.

Дополнительно реализован перевыпуск запросов на получение сертификата
(Cerificate Signing Request, CSR).

Формат контейнера с личным ключом описывается типом EncryptedPrivateKeyInfo,
определенным в PKCS#8 (RFC 5208). Для защиты контейнера используется механизм
PBKDF2, определенный в PKCS#5 (RFC 8018). Формат и механизм уточняются
в СТБ 34.101.78.

Секретным параметром PBKDF2 является пароль. Для повышения гарантий защиты
в качестве пароля может выступать полноценный ключ. Этот ключ разделяется
на частичные секреты, которые также сохраняются в контейнерах
EncryptedPrivateKeyInfo будучи защищенными на обычных паролях.

При разделении на частичные секреты используются стандартные параметры bels,
в частности, стандартные открытые ключи. Номер открытого ключа (число от 1
до 16) кодируется октетом и добавляется в начало частичного секрета.
Поэтому длина частичного секрета в октетах на единицу больше стандартной
длины (17 вместо 16, 25 вместо 24 и 33 вместо 32).

Формат запроса на получение сертификата определен в СТБ 34.101.17 (PKCS#10).
Запрос содержит идентификационные данные будущего владельца сертификата,
его открытый ключ, технические расширения, а также подпись всех этих полей
на личном ключе. Идентификационные данные, открытый ключ, а также некоторые
расширения переносятся в сертификат. Подпись доказывает владение открытым
ключом сертификата, т.е. знание соответствующего личного ключа. Перевыпуск
запроса позволяет доказать владение на новой паре ключей при сохранении 
(громоздких) идентификационных данных и расширений.

\expect{ERR_BAD_INPUT} Все входные указатели действительны. Исключение
составляют случаи, когда нулевой указатель передается как запрос на определение
объема памяти, которую требуется зарезервировать при повторном вызове
(конструкция [len?]ptr).  
*******************************************************************************
*/

/*!	\brief Создание контейнера с личным ключом

	Создается  контейнер [epki_len?]epki с защищенным личным ключом
	[privkey_len]privkey. Ключ защищается на пароле [pwd_len]pwd.
	Используется механизм защиты PBKDF2 с синхропосылкой ("солью") salt
	и числом итераций iter.
	\expect{ERR_BAD_PRIVKEY} privkey_len \in {32, 48, 64}.
	\expect{ERR_BAD_INPUT} iter >= 10000.
	\return ERR_OK, если контейнер успешно создан, и код ошибки в противном
	случае.
	\remark При нулевом epki указатели privkey, pwd и salt могут быть нулевыми.
*/

err_t bpkiPrivkeyWrap(
	octet epki[],			/*!< [out] контейнер с личным ключом */
	size_t* epki_len,		/*!< [out] длина epki */
	const octet privkey[],	/*!< [in] личный ключ */
	size_t privkey_len,		/*!< [in] длина privkey */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len,			/*!< [in] длина pwd */
	const octet salt[8],	/*!< [in] синхропосылка ("соль") PBKDF2 */
	size_t iter				/*!< [in] количество итераций в PBKDF2 */
);

/*!	\brief Разбор контейнера с личным ключом

	Из контейнера [epki_len]epki извлекается личный ключ [privkey_len?]privkey,
	защищенный с помощью механизма PBKDF2. Защита снимается на пароле
	[pwd_len]pwd.
	\return ERR_OK, если личный ключ успешно извлечен, и код ошибки в противном
	случае.
	\remark Формально для определения длины privkey_len личного ключа нужно
	снять защиту, а для этого предъявить пароль. Поэтому указатель pwd должен
	быть корректен даже при нулевом указателе privkey, т.е. во время запроса
	длины privkey_len. Здесь не учитывается, что длину личного ключа можно
	определить косвенно по длине контейнера.
*/

err_t bpkiPrivkeyUnwrap(
	octet privkey[],		/*!< [out] личный ключ */
	size_t* privkey_len,	/*!< [in] длина privkey */
	const octet epki[],		/*!< [in] контейнер с личным ключом */
	size_t epki_len,		/*!< [in] длина epki */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len			/*!< [in] длина pwd */
);

/*!	\brief Создание контейнера с частичным секретом

	Создается  контейнер [epki_len?]epki с защищенным частичным секретом
	[share_len]share. Ключ защищается на пароле [pwd_len]pwd.
	Используется механизм защиты PBKDF2 с синхропосылкой ("солью") salt
	и числом итераций iter.
	\expect{ERR_BAD_SHAREKEY} share_len \in {17, 25, 33}.
	\expect{ERR_BAD_SHAREKEY} Если share != 0, то 1 <= share[0] <= 16.
	\expect{ERR_BAD_INPUT} iter >= 10000.
	\return ERR_OK, если контейнер успешно создан, и код ошибки в противном
	случае.
	\remark В префиксе частичного секрета указывается номер соответствующего 
	открытого ключа (из стандартного списка открытых ключей). Открытый ключ
	используется при сборке ключа по частичным секретам. 
	\remark При нулевом epki указатели share, pwd и salt могут быть нулевыми.
*/

err_t bpkiShareWrap(
	octet epki[],			/*!< [out] контейнер с частичным секретом */
	size_t* epki_len,		/*!< [out] длина epki */
	const octet share[],	/*!< [in] частичный секрет */
	size_t share_len,		/*!< [in] длина share */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len,			/*!< [in] длина pwd */
	const octet salt[8],	/*!< [in] синхропосылка ("соль") PBKDF2 */
	size_t iter				/*!< [in] количество итераций в PBKDF2 */
);

/*!	\brief Разбор контейнера с частичным секретом

	Из контейнера [epki_len]epki извлекается частичный секрет
	[share_len?]share, защищенный с помощью механизма PBKDF2. Защита
	снимается на пароле [pwd_len]pwd.
	\expect{ERR_BAD_SECKEY} Если share != 0, то 1 <= share[0] <= 16.
	\return ERR_OK, если частичный секрет успешно извлечен, и код ошибки
	в противном случае.
	\remark Формально для определения длины share_len частичного секрета нужно
	снять защиту, а для этого предъявить пароль. Поэтому указатель pwd должен
	быть корректен даже при нулевом указателе share, т.е. во время запроса длины
	share_len. Здесь не учитывается, что длину частичного секрета можно определить
	косвенно по длине контейнера.
*/
err_t bpkiShareUnwrap(
	octet share[],			/*!< [out] частичный секрет */
	size_t* share_len,		/*!< [out] длина share */
	const octet epki[],		/*!< [in] контейнер с частичным секретом */
	size_t epki_len,		/*!< [in] длина epki */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len			/*!< [in] длина pwd */
);

/*!	\brief Перевыпуск запроса на выпуск сертификата

	В запрос на выпуск сертификата [csr_len]csr вкладывается новый
	открытый ключ, построенный по личному ключу [privkey_len]privkey,
	а затем запрос подписывается на privkey.
	\expect{ERR_NOT_IMPLEMENTED} privkey_len == 32.
	\expect{ERR_BAD_FORMAT} Формат запроса соответствует СТБ 34.101.17.
	\expect{ERR_BAD_FORMAT} В запросе используются стандартные долговременные
	параметры bign-curve256v1 и алгоритм bign-with-hbelt. 
	\return ERR_OK, если запрос успешно перевыпущен, и код ошибки в противном
	случае.
*/
err_t bpkiCSRRewrap(
	octet csr[],			/*!< [in/out] запрос на выпуск сертификата */
	size_t csr_len,			/*!< [in] длина csr */
	const octet privkey[],	/*!< [in] личный ключ */
	size_t privkey_len		/*!< [in] длина privkey */
);

/*!	\brief Разбор запроса на выпуск сертификата

	Подпись запроса на выпуск сертификата [csr_len]csr проверяется на открытом
	ключе, вложенном в запрос. В случае успеха из запроса извлекается открытый
	ключ [pubkey_len?]pubkey.
	\expect{ERR_BAD_FORMAT} Формат запроса соответствует СТБ 34.101.17.
	\expect{ERR_BAD_FORMAT} В запросе используются стандартные долговременные
	параметры bign-curve256v1 и алгоритм bign-with-hbelt.
	\return ERR_OK, если разбор прошел успешно, и код ошибки в противном
	случае.
*/
err_t bpkiCSRUnwrap(
	octet pubkey[],			/*!< [out] открытый ключ */
	size_t* pubkey_len,		/*!< [out] длина pubkey */
	const octet csr[],		/*!< [in] запрос на выпуск сертификата */
	size_t csr_len			/*!< [in] длина csr */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /*__BEE2_BPKI_H */
