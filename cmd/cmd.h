/*
*******************************************************************************
\file cmd.h
\brief Command-line interface to Bee2
\project bee2/cmd
\created 2022.06.09
\version 2023.06.02
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#ifndef __BEE2_CMD_H
#define __BEE2_CMD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <bee2/defs.h>
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/tm.h>
#include <bee2/crypto/btok.h>

/*
*******************************************************************************
Блобы
*******************************************************************************
*/

/*! \brief Создание блоба */
#define cmdBlobCreate(blob, size) \
	(((blob) = blobCreate(size)) ? ERR_OK : ERR_OUTOFMEMORY)

/*! \brief Закрытие блоба */
#define cmdBlobClose blobClose

/*
*******************************************************************************
Регистрация команд
*******************************************************************************
*/

/*!	\brief Главная функция команды */
typedef int (*cmd_main_i)(
	int argc,				/*!< [in] число параметров командной строки */
	char* argv[]			/*!< [in] параметры командной строки */
);

/*!	\brief Регистрация команды

	Регистрируется команда с именем name, описанием descr и главной
	функцией fn.
	\expect Строки name и descr -- статические, указатели на них остаются
	корректными на протяжении всего времени выполнения. 
	\expect{ERR_BAD_FORMAT} 1 <= strLen(name) <= 8 && strLen(descr) <= 60.
	\return ERR_OK, если команда зарегистрирована, и код ошибки в противном
	случае.
*/
err_t cmdReg(
	const char* name, 		/*!< [in] имя команды */
	const char* descr,		/*!< [in] описание команды */
	cmd_main_i fn			/*!< [in] главная функция команды */
);

/*
*******************************************************************************
Терминал
*******************************************************************************
*/

/*!	\brief Нажата клавиша?

	Опрашивается теримнал и проверяется, что очередь нажатых клавиш не пуста.
	\return Признак нажатия.
	\remark Очередь очищается в том числе через вызовы cmdTermGetch().
*/
bool_t cmdTermKbhit();

/*!	\brief Чтение символа

	Прочитывается символ, введенный в терминале.
	\return Прочитанный символ.
	\remark Прочитанный символ не экранируется.
*/
int cmdTermGetch();

/*
*******************************************************************************
ГСЧ

В функции cmdKbRead() реализован клавиатурный источник энтропии. Реализация
соответствует СТБ 34.101.27-2011 (Б.7):
- при нажатии клавиш фиксируются значения высокоточного таймера (регистр TSC);
- разность между значениями регистра сохраняется, если друг за другом нажаты
  две различные клавиши и интервал между нажатиями более 50 мс;
- всего сохраняется 128 разностей;
- собранные разности объединяются и хэшируются;
- хэш-значение (32 октета) возвращается в качестве энтропийных данных.

Дополнительно в cmdKbRead() проверяется, что интервал между нажатиями клавиш
не превышает 5 секунд. При отсутствии активности со стороны пользователя
сбор данных от источника будет прекращен.

В функции cmdRngStart() проверяются требования СТБ 34.101.27-2020 уровня 1:
наличие работоспособного физического источника энтропии или двух различных
работоспособных источников. Если недостает одного источника, то задействуется
клавиатурный.
*******************************************************************************
*/

/*!	\brief Данные от клавиатурного источника энтропии

	Прочитываются даные data с клавиатурного источника энтропии.
	\return ERR_OK в случае успеха и код ошибки в противном случае.
*/
err_t cmdRngKbRead(
	tm_ticks_t data[128]	/*!< [out] данные */
);

/*!	\brief Запуск ГСЧ

	Запускается штатный ГСЧ. При установке флага verbose запуск сопровождается
	экранным выводом.
	\return ERR_OK в случае успеха и код ошибки в противном случае.
*/
err_t cmdRngStart(
	bool_t verbose			/*!< [in] печатать подробности */
);

/*
*******************************************************************************
Дата
*******************************************************************************
*/

/*!	\brief Разбор даты

	По строке str формата YYMMDD формируется дата date. При str == "000000" в
	date устанавливается текущая дата.
	\return ERR_OK, если строка имеет нужный формат и дата сформирована, и код
	ошибки в противном случае.
*/
err_t cmdDateParse(
	octet date[6],					/*!< [out] дата */
	const char* str					/*!< [in] строка */
);

/*
*******************************************************************************
Файлы

\remark Пара параметров (count, files) функций cmdFilesValXXX() соответствует
паре (argc, argv) функции main(). Если заменить тип files на const char**,
то возможны предупредеждения компилятора при переходе от argv к files
(см. http://c-faq.com/ansi/constmismatch.html).
*******************************************************************************
*/

/*!	\brief Размер файла

	Определяется размер файла с именем file.
	\return Размер файла или SIZE_MAX в случае ошибки.
*/
size_t cmdFileSize(
	const char* file		/*!< [in] имя файла */
);

/*!	\brief Запись в файл

	Создается файл file и в него записывается буфер [count]buf.
	\return ERR_OK в случае успеха и код ошибки в противном случае.
*/
err_t cmdFileWrite(
	const char* file,	/*!< [in] файл */
	const octet buf[],	/*!< [in] буфер */
	size_t count		/*!< [in] длина буфера */
);

/*!	\brief Чтение всего файла

	Буфер [?count]buf прочитывается из файла file. При ненулевом buf
	дополнительно проверяется, что переданная длина в точности совпадает
	с размером файла.
	\return ERR_OK в случае успеха и код ошибки в противном случае.
*/
err_t cmdFileReadAll(
	octet buf[],		/*!< [in] буфер */
	size_t* count,		/*!< [in] длина буфера */
	const char* file	/*!< [in] файл */
);

/*!	\brief Проверка отсутствия файлов

	Проверяется, что файлы списка [count]files отсутствуют и, таким образом,
	их можно создавать и записывать в них данные. Если некоторый файл все-таки
	присутствует, то предлагается его перезаписать. Разрешение на перезапись
	приравнивается к отсутствию файла.
	\return ERR_OK в случае успеха и код ошибки в противном случае. 
*/
err_t cmdFileValNotExist(
	int count,				/*!< [in] число файлов */
	char* files[]			/*!< [in] список имен файлов */
);

/*!	\brief Проверка наличия файлов

	Проверяется существование файлов списка [count]files.
	\return ERR_OK в случае успеха и код ошибки в противном случае.
*/
err_t cmdFileValExist(
	int count,				/*!< [in] число файлов */
	char* files[]			/*!< [in] список имен файлов */
);

/*!	\brief Проверка совпадения файлов

	Проверяется, что имена file1 и file2 соответствуют одному и тому же файлу.
	\return Признак успеха.
	\remark Корректность имен не проверяется.
*/
bool_t cmdFileAreSame(
	const char* file1,		/*!< [in] первый файл */
	const char* file2		/*!< [in] второй файл */
);

/*
*******************************************************************************
Командная строка
*******************************************************************************
*/

/*!	\brief Создание списка аргументов

	По командной строке args строится список аргументов [argc]argv.
	\pre Указатели argc, argv и строка args корректны.
	\return ERR_OK в случае успеха и код ошибки в противном случае. 
	\remark Аргументами считаются фрагменты args, разделенные пробелами.
	Фрагмент, окаймленный кавычками, считаются единым аргументом, даже если
	внутри него содержатся пробелы.
	\remark Детали:
	https://docs.microsoft.com/cpp/c-language/parsing-c-command-line-arguments
*/
err_t cmdArgCreate(
	int* argc,			/*!< [out] число аргументов */
	char*** argv,		/*!< [out] список аргументов */
	const char* args	/*!< [in] командная строка */
);

/*!	\brief Закрытие списка аргументов

	Закрывается список аргументов argv, созданный в функции cmdArgCreate().
	\pre cmdArgCreate() < cmdArgClose().
*/
void cmdArgClose(
	char** argv			/*!< [in] список аргументов */
);

/*
*******************************************************************************
Управление паролями

Пароль представляется собой стандартную C-строку (с завершающим нулем).

Пароль размещается в блобе, который создается внутри функций cmdPwdGen(),
cmdPwdRead(). Схема возврата [pwd_len?]pwd не используется, потому что
в некоторых случаях (например, при вводе пароля с консоли) важно, чтобы пароль
можно было возвратить за один вызов функции. За закрытие блоба отвечает
вызывающая программа.

Пароль задается в командной строке в стиле OpenSSL:
- обычно после аргумента "-pass" / "-passin" / "-passout" / ...;
- имеется несколько схем задания пароля;
- схема pass предлназначена для задания пароля прямо в командной строке:
  "-pass pass:password";
- схема share предлназначена для задания пароля с помощью методов
  разделения секрета в соответствии с правилами СТБ 34.101.78:
  "-pass share:\"share_descr\"";

В последнем случае параметры share_args, которые описывают настройку разделения
секрета, имеют следующий синтаксис:
\code
  [-t<nn>] [-l<mmm>] -pass <scheme> <share1> <share2> ....
\endcode
Здесь:
- <nn> -- порог числа частичных секретов (2 <= n <= 16, 2 по умолчанию);
- <mmm> -- уровень стойкости (128, 192 или 256, 256 по умолчанию);
- <scheme> --- описание пароля защиты файлов с частичными секретами;
- <share1>, <share2>,... -- файлы с частичными секретами (их число должно быть
  не меньше порога и не больше 16).

\todo Поддержать опции "env:var", "file:pathname", "fd:number" и "stdin",
реализованные в OpenSSL
(https://www.openssl.org/docs/manmaster/man1/openssl-passphrase-options.html).

\todo Поддержать правила кодирования паролей, реализованные в OpenSSL
(https://www.openssl.org/docs/manmaster/man7/passphrase-encoding.html).
*******************************************************************************
*/

/*!	\brief Пароль */
typedef char* cmd_pwd_t;

/*!	\brief Создание пароля

	Создается блоб для хранения пароля максимальной длины size.
	\return Дескриптор блоба. Нулевой дескриптор возвращается
	при нехватке памяти.
	\remark При создании блоба все его октеты обнуляются.
*/
cmd_pwd_t cmdPwdCreate(
	size_t size			/*!< [in] максимальная длина */
);

/*!	\brief Корректный пароль?

	Проверяется корректность пароля pwd.
	\return Признак корректности.
	\remark Пароль корректен, если он хранится в корректном непустом блобе,
	который завершается нулевым октетом.
*/
bool_t cmdPwdIsValid(
	const cmd_pwd_t pwd		/*!< [in] корректный блоб */
);

/*!	\brief Закрытие пароля

	Выполняется очистка и освобождение блоба пароля pwd.
*/
void cmdPwdClose(
	cmd_pwd_t pwd		/*!< [in] пароль */
);

/*!	\brief Длина пароля */
#define cmdPwdLen strLen

/*!	\brief Построение пароля

	По инструкциям во фрагменте cmdline командной строки строится пароль pwd.
	\pre При использовании некоторых опций, в частности "share", должен быть
	проинициализирован штатный ГСЧ: rngIsValid() == TRUE.
	\return ERR_OK, если пароль успешно построен, и код ошибки 
	в противном случае.
	\remark За закрытие пароля отвечает вызывающая программа.
*/
err_t cmdPwdGen(
	cmd_pwd_t* pwd,			/*!< [out] пароль */
	const char* cmdline		/*!< [in] фрагмент командной строки */
);

/*!	\brief Определение пароля

	По инструкциям во фрагменте cmdline командной строки определяется 
	ранее построенный пароль pwd.
	\return ERR_OK, если пароль успешно определен, и код ошибки в противном
	случае.
	\remark За закрытие пароля отвечает вызывающая программа.
*/
err_t cmdPwdRead(
	cmd_pwd_t* pwd,			/*!< [out] пароль */
	const char* cmdline		/*!< [in] фрагмент командной строки */
);

/*
*******************************************************************************
Управление личными ключами СТБ 34.101.45 (bign)

Личные ключи хранятся в контейнерах, защищенных на паролях по схеме
СТБ 34.101.78 (bpki).

\expect Личный ключ связан со стандартными параметрами СТБ 34.101.45 того или
иного уровня стойкости: bign-curve256v1, bign-curve384v1 или bign-curve512v1.
*******************************************************************************
*/

/*!	\brief Запись личного ключа в контейнер

	Личный ключ [privkey_len]privkey записывается в защищенный файл-контейнер
	file. Защита устанавливается на пароле pwd.
	\return ERR_OK, если ключ успешно записан, и код ошибки	в противном случае.
*/
err_t cmdPrivkeyWrite(
	const octet privkey[],			/*!< [in] личный ключ */
	size_t privkey_len,				/*!< [in] длина личного ключа */
	const char* file,				/*!< [in] имя контейнера */
	const cmd_pwd_t pwd				/*!< [in] пароль защиты */
);

/*!	\brief Чтение личного ключа из контейнера

	Личный ключ [privkey_len?]privkey читается из защищенного файла-контейнера
	file. Защита снимается на пароле pwd.
	\pre Если адрес privkey_len ненулевой, то по этому адресу передается
	одно из следующих значений: 0, 32, 48, 64. Нулевое значение соответствует
	стандартной логике [privkey_len?]. Ненулевые значения соответствуют логике
	[?privkey_len], то есть задают требуемую длину ключа.
	\expect{ERR_BAD_FORMAT} Если privkey_len != 0 и *privkey_len != 0,
	то контейнер file содержит ключ из *privkey_len октетов.
	\return ERR_OK, если ключ успешно прочитан, и код ошибки в противном случае.
*/
err_t cmdPrivkeyRead(
	octet privkey[],				/*!< [out] личный ключ */
	size_t* privkey_len,			/*!< [out] длина личного ключа */
	const char* file,				/*!< [in] имя контейнера */
	const cmd_pwd_t pwd				/*!< [in] пароль защиты */
);

/*
*******************************************************************************
CV-сертификаты
*******************************************************************************
*/

/*!	\brief Печать CV-сертификата

	Печатается область CV-сертификата cvc, заданная строкой scope:
	- если scope != 0, то печатается поле с именем scope ("authority",
	  "holder", "from", "until", "eid", "esign" или "pubkey");
	- если scope == 0, то печатаются все поля сертификата.
	\return ERR_OK, если печать успешно выполнена, и код ошибки
	в противном случае. 
*/
err_t cmdCVCPrint(
	const btok_cvc_t* cvc,			/*!< [in] сертификат */
	const char* scope				/*!< [in] область печати */
);

/*
*******************************************************************************
ЭЦП

ЭЦП может сопровождаться (обратной) цепочкой CV-сертификатов. Первым в цепочке
идет сертификат подписанта. Каждый следующий сертификат -- это сертификат
удостоверяющего центра, выпустившего предыдущий сертификат.

ЭЦП может сопровождаться датой выработки подписи. Дата задается 6 октетами
по схеме YYMMDD, которая используется в CV-сертификатах (см. btok.h).
Если все октеты нулевые, то значит дата не указана.

Цепочка сертификатов и дата подписываются вместе с содержимым целевого файла.
При этом смена сертификата подписанта в цепочке сделает подпись
недействительной, даже если открытый ключ будет повторен в двух сертификатах
(см. RFC5035: описание угроз, описание атрибута SigningCertificateV2).

Формат ЭЦП:
\code
Signature ::= SEQUENCE
{
   certs SEQUENCE OF CVCertificate,
   sig OCTET STRING(SIZE(48|72|96)),
   date CVDate OPTIONAL
}
CVDate ::= OCTET STRING(SIZE(6))
\endcode

Для управления форматом предусмотрена структура cmd_sig_t. В поле certs этой
структуры cmd_sig_t размещается цепочка сертификатов. Сертификаты цепочки
записываются последовательно друг за другом без разделителей. Сертификаты
закодированы по правилам АСН.1, их длины однозначно определяются в ходе
декодирования. Дата (date) и подпись (sig) также кодируются по правилам
АСН.1.

DER-код структуры Signature (строка октетов) переворачивается. За счет
переворота DER-код однозначно декодируется даже будучи записанным в конец
файла произвольного размера. В частности, подпись может быть присоединена
к подписывемому файлу. В этом случае при проверке подписи она исключается
из контролируемого содержимого файла.
*******************************************************************************
*/

/*!	\brief Подпись и сопровождающие сертификаты */
typedef struct {
	octet sig[96];			/*!< подпись */
	size_t sig_len;	        /*!< длина подписи в октетах */
	octet certs[1460];		/*!< цепочка сертификатов */
	size_t certs_len;		/*!< cуммарная длина сертификатов */
	octet date[6];			/*!< дата выработки подписи */
} cmd_sig_t;

/*!	\brief Подпись файла

	Содержимое файла file подписывается на личном ключе [privkey_len]privkey
	с указанием date в качестве даты подписания. При передаче нулевого буфера
	date дата подписания не указывается.Подпись сохраняется в файле sig_file
	вместе с сертификатами цепочки certs. Цепочка certs может быть пустой.
	В качестве файла подписи можно указать подписываемый файл, и тогда подпись
	записывается в его конец. 
	\expect{ERR_BAD_KEYPAIR} Если цепочка certs непуста, то ее первый
	сертификат соответствует privkey.
	\expect{ERR_BAD_CERT} Если цепочка certs непуста, то каждый ее сертификат,
	начиная со второго, -- это сертификат удостоверяющего центра, выпустившего
	предыдущий сертификат.
	\expect{ERR_BAD_DATE} Если дата подписания date указана, то она корректна.
	\expect{ERR_OUTOFRANGE} Если дата подписания date указана, то все
	сертификаты цепочки certs действительны на эту дату.
	\return ERR_OK, если файл успешно подписан, и код ошибки в противном
	случае.
	\remark В списке certs указываются имена файлов сертификатов. Имена
	разделяются пробелами. Имена могут окаймляться кавычками.
	\remark Файлы file и sig_file могут совпадать, и тогда подпись
	присоединяется к подписываемому файлу.
*/
err_t cmdSigSign(
	const char* sig_file,		/*!< [in] файл подписи */
	const char* file,			/*!< [in] подписываемый файл */
	const char* certs,			/*!< [in] цепочка сертификатов */
	const octet date[6],		/*!< [in] дата подписания */
	const octet privkey[],		/*!< [in] личный ключ */
	size_t privkey_len			/*!< [in] длина личного ключа */
);

/*!	\brief Проверка подписи файла на открытом ключе

	Подпись содержимого файла file, размещенная в sig_file, проверяется
	на открытом ключе [pubkey_len]pubkey. В качестве файла подписи может
	указывать подписываемый файл, и тогда подпись прочитывается из его конца
	и исключается из содержимого файла при проверке.
	\expect{ERR_BAD_KEYPAIR} Если подпись сопровождается цепочкой сертификатов,
	то ее первый сертификат соответствует pubkey.
	\expect{ERR_BAD_CERT} Если подпись сопровождается цепочкой сертификатов,
	то каждый ее сертификат, начиная со второго, -- это сертификат
	удостоверяющего центра, выпустившего предыдущий сертификат.
	\expect{ERR_BAD_DATE} Если подпись сопровождается датой подписания,
	то эта дата корректна.
	\expect{ERR_OUTOFRANGE} Если подпись сопровождается датой подписания, то все
	сертификаты вложеннной цепочки действительны на эту дату.
	\expect{ERR_BAD_FORMAT} Если подпись размещается в отдельном файле, то этот
	файл содержит исключительно подпись.
	\return ERR_OK, если подпись корректна, и код ошибки в противном случае.
*/
err_t cmdSigVerify(
	const char* file,			/*!< [in] подписанный файл */
	const char* sig_file,		/*!< [in] файл подписи */
	const octet pubkey[],		/*!< [in] открытый ключ */
	size_t pubkey_len			/*!< [in] длина открытого ключа */
);

/*!	\brief Проверка подписи файла на доверенном сертификате

	Подпись содержимого файла file, размещенная в sig_file, проверяется
	на доверенном сертификате [anchor_len]anchor. Проверка будет завершена
	успешно, если подпись сопровождается цепочкой сертификатов и признается
	корректной на первом сертификате цепочки. В качестве файла подписи может
	указывать подписываемый файл, и тогда подпись прочитывается из его конца
	и исключается из содержимого файла при проверке.
	\expect{ERR_NO_TRUST} Один из сертификатов цепочки совпадает с anchor.
	\expect{ERR_BAD_CERT} Каждый сертификат цепочки, начиная со второго, --
	это сертификат удостоверяющего центра, выпустившего предыдущий сертификат.
	\expect{ERR_BAD_DATE} Если подпись сопровождается датой подписания,
	то эта дата корректна.
	\expect{ERR_OUTOFRANGE} Если подпись сопровождается датой подписания, то все
	сертификаты вложеннной цепочки действительны на эту дату.
	\expect{ERR_BAD_FORMAT} Если подпись размещается в отдельном файле, то этот
	файл содержит исключительно подпись.
	\return ERR_OK, если подпись корректна, и код ошибки в противном случае.
*/
err_t cmdSigVerify2(
	const char* file,			/*!< [in] подписанный файл */
	const char* sig_file,		/*!< [in] файл подписи */
	const octet anchor[],		/*!< [in] доверенный сертификат */
	size_t anchor_len			/*!< [in] длина anchor */
);

/*!	\brief Самопроверка подписи на открытом ключе

	Подпись исполнимого файла, в котором вызывается данная функция,
	прочитывается из конца этого же файла и проверяется на открытом ключе
	[pubkey_len]pubkey через обращение к cmdSigVerify(pubkey, pubkey_len).
	\return ERR_OK, если подпись корректна, и код ошибки в противном случае.
*/
err_t cmdSigSelfVerify(
	const octet pubkey[],		/*!< [in] открытый ключ */
	size_t pubkey_len			/*!< [in] длина открытого ключа */
);

/*!	\brief Самопроверка подписи на доверенном сертификате

	Подпись исполнимого файла, в котором вызывается данная функция,
	прочитывается из конца этого же файла и проверяется на доверенном
	сертификате [anchor_len]anchor через обращение к
	cmdSigVerify2(anchor, anchor_len).
	\return ERR_OK, если подпись корректна, и код ошибки в противном случае.
*/
err_t cmdSigSelfVerify2(
	const octet anchor[],		/*!< [in] доверенный сертификат */
	size_t anchor_len			/*!< [in] длина anchor */
);

/*!	\brief Печать подписи

	Печатается подпись, размещенная в конце файла sig_file. Вместе с подписью
	печатаются сопровождающие ее CV-сертификаты.
	\return ERR_OK, если печать успешно выполнена, и код ошибки в противном
	случае.
*/
err_t cmdSigPrint(
	const char* sig_file		/*!< [in] файл подписи */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_CMD_H */
