/*
*******************************************************************************
\file bake.h
\brief STB 34.101.66 (bake): key establishment protocols
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.04.14
\version 2015.09.01
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file bake.h
\brief Протоколы СТБ 34.101.66 (bake)
*******************************************************************************
*/

#ifndef __BEE2_BAKE_H
#define __BEE2_BAKE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"
#include "bee2/crypto/bign.h"

/*!
*******************************************************************************
\file bake.h

\section bake-common СТБ 34.101.66 (bake): Общие положения

Реализованы протоколы и алгоритмы СТБ 34.101.66 (bake). При ссылках на 
протоколы, таблицы, другие объекты подразумеваются разделы СТБ 34.101.66-2014, 
в которых эти объекты определены.

Долговременные параметры bake повторяют долговременные параметры bign 
и задаются структурой типа bign_params, описанной в заголовочном файле bign.h. 
Стандартные долговременные параметры можно получить с помощью функции 
bignStdParams(), проверить --- с помощью функции bignValParams().

На личные и открытые ключи распространяются соглашения bign. Генерацию 
пары ключей можно выполнить с помощью функции bignGenKeypair(),
проверку открытого ключа --- с помощью функции bignValPubkey(),
построение открытого ключа по личному --- с помощью bignCalcPubkey().

Найстройки протоколов описываются структурой типа bake_settings. В этих 
настройках задаются:
-	признак kca подтверждения ключа стороной A;
-	признак kcb подтверждения ключа стороной B;
-	приветственное сообщение [helloa_len]helloa стороны A;
-	приветственное сообщение [hellob_len]hellob стороны B;
-	генератор случайных чисел rng и его состояние rng_state.

В зависимости от флагов kca, kcb в протоколах BMQV, BPACE могут меняться 
число пересылок и длины фрагментов.

Каждый из протоколов реализован набором низкоуровневых функций, которые 
используют общее состояние и работают по схеме Start, Step2, Step3,.... 
Номера шагов указываются в соответствии со стандартом bake. В функцию Start 
передаются приветственные сообщения и поэтому шаг 1 стандарта, на котором 
происходит их пересылка, опускается. 

Память для состояния готовится вызывающей программой. Длина состояния 
задается функцией с суффиксом keep. Состояние включает указатели на внутренние
фрагменты памяти, и поэтому его нельзя копировать как обычный блок памяти.

В описаниях низкоуровневых функций StepX фигурируют данные, которые задаются в
инициализирующей функции Start: 
-	уровень стойкости l из перечня долговременных параметров;
-	флаги kca, kcb из перечня настроек;
-	указатель cert на собственный сертификат стороны протокола.
.

Для каждого протокола имеются две высокоуровневые функции с суффиксами RunA 
и RunB. В этих функциях реализовано полное выполнение протокола от лица 
стороны A или B. В функции передается реализация канала передачи сообщений
между сторонами.

\expect{ERR_BAD_INPUT} Все входные указатели, за исключением оговоренных 
случаев, корректны.

\expect При пошаговом выполнении протокола данные, переданные при инициализации
через указатели, остаются корректными и постоянными на протяжении всего
выполнения протокола.

\safe todo
*******************************************************************************
*/

/*!	\brief Настройки bake */
typedef struct
{
	bool_t kca;				/*!< сторона A подтверждает ключ */
	bool_t kcb;				/*!< сторона B подтверждает ключ */
	const void* helloa;		/*!< приветственное сообщение стороны A */
	size_t helloa_len;		/*!< длина helloa в октетах */
	const void* hellob;		/*!< приветственное сообщение стороны B */
	size_t hellob_len;		/*!< длина hellob в октетах */
	gen_i rng;				/*!< генератор случайных чисел */
	void* rng_state;		/*!< состояние rng */
} bake_settings;

/*!
*******************************************************************************
\file bake.h

\section bake-cert Сертификаты

В протоколах BMQV, BSTS используются сертификаты. Сертификат распространяется
в виде структуры типа bake_cert. В этой структуре кроме собственно сертификата
указывается функция его проверки. 

\remark Функции проверки своего и чужого сертификатов у сторон протоколов могут
быть разными. 
*******************************************************************************
*/

/*!	\brief Проверка сертификата

	Проверяется, что сертификат cert корректен и соответствует долговременным 
	параметрам params. Если pubkey != 0, то из сертификата извлекается 
	открытый ключ [l / 2]pubkey.
	\expect Параметры params корректны.
	\return ERR_OK, если сертификат корректен, и код ошибки в противном случае.
	\remark В функции интерфейса bake_certval_i можно не проверять, что 
	pubkey лежит на кривой, заданной params. Данная проверка обязательно 
	проводится при выполнении каждого из протоколов.
*/
typedef err_t (*bake_certval_i)(
	octet pubkey[],					/*!< [out] открытый ключ */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const octet* data,				/*!< [in] данные сертификата */
	size_t len						/*!< [in] длина data в октетах */
);

/*!	\brief Сертификат bake */
typedef struct
{
	octet* data;			/*!< данные сертификата */
	size_t len;				/*!< длина data */
	bake_certval_i val;		/*!< функция проверки сертификата */
} bake_cert;

/*
*******************************************************************************
Вспомогательные функции
*******************************************************************************
*/

/*!	\brief Построение ключа

	По секретному слову [secret_len]secret, дополнительному слову [iv_len]iv
	и номеру num строится ключ key.
	\return ERR_OK, если ключ успешно построен, и код ошибки в противном 
	случае.
	\remark Реализован алгоритм 6.1.3.
*/
err_t bakeKDF(
	octet key[32],			/*!< [out] ключ */
	const octet secret[],	/*!< [in] секретное слово */
	size_t secret_len,		/*!< [in] длина secret */
	const octet iv[],		/*!< [in] дополнительное слово */
	size_t iv_len,			/*!< [in] длина iv */
	size_t num				/*!< [in] номер ключа */
);

/*!	\brief Построение точки эллиптической кривой

	При долговременных параметрах params по сообщению [l / 4]msg строится 
	точка [l / 2]pt эллиптической кривой, описываемой params.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\return ERR_OK, если точка успешно построена, и код ошибки в противном 
	случае.
	\remark Реализован алгоритм 6.2.3.
*/
err_t bakeSWU(
	octet pt[],					/*!< [out] точка */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet msg[]			/*!< [in] сообщение */
);

/*!	\brief Построение общего ключа протокола Диффи -- Хеллмана 
	
	Задается ссылка на функцию bignDH(), которая реализует базовый протокол
	Диффи -- Хеллмана.
	\remark Базовый протокол Диффи -- Хеллмана описан в приложении А.
*/
#define bakeDH bignDH

/*!
*******************************************************************************
\file bake.h

\section bake-bmqv Протокол BMQV
*******************************************************************************
*/

/*!	\brief Длина состояния функций BMQV

	Возвращается длина состояния (в октетах) функций протокола BMQV.
	\return Длина состояния.
*/
size_t bakeBMQV_keep(
	size_t l						/*!< [in] уровень стойкости */
);

/*!	\brief Инициализация протокола BMQV

	По параметрам params, настройкам settings, личному ключу [l / 4]privkey 
	и сертификату cert соответствующего открытого ключа в state формируются 
	структуры данных, необходимые для выполнения протокола BMQV.
	\pre По адресу state зарезервировано bakeBMQV_keep() октетов.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_INPUT} Указатель settings->helloa нулевой, либо буфер 
	[settings->helloa_len]settings->helloa корректен. Аналогичное требование
	касается полей settings->hellob, settings->hellob_len.
	\expect{ERR_BAD_RNG} Генератор settings->rng (с состоянием 
	settings->rng_state) корректен.
	\expect Генератор settings->rng является криптографически стойким.
	\expect{ERR_BAD_CERT} Сертификат cert корректен.
	\expect Ключ privkey и сертификат cert согласованы. Если согласование
	нарушено, то протокол будет завершен с ошибкой.
	\return ERR_OK, если инициализация успешно выполнена, и код ошибки 
	в противном случае.
*/
err_t bakeBMQVStart(
	void* state,					/*!< [out] состояние */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet privkey[],			/*!< [in] личный ключ */
	const bake_cert* cert			/*!< [in] сертификат */
);

/*!	\brief Шаг 2 протокола BMQV

	Выполняется шаг 2 протокола BMQV с состоянием state. Сторона B формирует
	сообщение M1 = [l / 2]out.
	\expect bakeBMQVStart() < bakeBMQVStep2().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
	\remark Приветственное сообщение и сертификат стороны B в M1 не передаются. 
*/
err_t bakeBMQVStep2(
	octet out[],			/*!< [out] выходное сообщение M1 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 3 протокола BMQV

	Выполняется шаг 3 протокола BMQV с состоянием state. Сторона A 
	обрабатывает сообщение M1 = [l / 2]in и формирует сообщение 
	M2 = [l / 2 + (kca ? 8 : 0)]out. Используется сертификат certb стороны B.
	\expect bakeBMQVStart() < bakeBMQVStep3().
	\expect bakeBMQVStep2() << bakeBMQVStep3().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
	\remark Cертификат стороны A в M2 не передается. 
*/
err_t bakeBMQVStep3(
	octet out[],			/*!< [out] выходное сообщение M2 */
	const octet in[],		/*!< [in] входное сообщение M1 */
	const bake_cert* certb,	/*!< [in] сертификат стороны B */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 4 протокола BMQV

	Выполняется шаг 4 протокола BMQV с состоянием state. Сторона B 
	обрабатывает сообщение M2 = [l / 2 + (kca ? 8 : 0)]in и формирует 
	сообщение M3 = [kcb ? 8 : 0]out. Используется сертификат certa стороны A.
	\expect bakeBMQVStep2() < bakeBMQVStep4().
	\expect bakeBMQVStep3() << bakeBMQVStep4().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBMQVStep4(
	octet out[],			/*!< [out] выходное сообщение M3 */
	const octet in[],		/*!< [in] входное сообщение M2 */
	const bake_cert* certa,	/*!< [in] сертификат стороны A */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 5 протокола BMQV

	Выполняется шаг 5 протокола BMQV с состоянием state. Сторона A 
	обрабатывает сообщение M3 = [8]in. Шаг выполняется только тогда,
	когда B подтверждает ключ (kcb == 0).
	\expect bakeBMQVStep5() < bakeBMQVStep3().
	\expect bakeBMQVStep4() << bakeBMQVStep5().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBMQVStep5(
	const octet in[8],		/*!< [in] входное сообщение M3 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Извлечение ключа протокола BMQV

	Определяется общий секретный ключ key, полученный с помощью протокола BMQV
	с состоянием state.
	\expect bakeBMQVStep4() < bakeBMQVStepG().
	\expect Если сторона B не подтверждает ключ, то 
	bakeBMQVStep3() < bakeBMQVStepG(). Если подтверждает, то 
	bakeBMQVStep5() < bakeBMQVStepG().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBMQVStepG(
	octet key[32],			/*!< [out] общий ключ */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Выполнение BMQV стороной B

	Протокол BMQV с параметрами params и настройками settings выполняется 
	от лица стороны B по каналу file с функциями чтения read и записи write.
	Сторона B использует личный ключ [l / 4]privkeyb, соответствующий 
	сертификат certb и сертификат certa стороны A. В результате выполнения 
	протокола определяется общий ключ key.
	\expect Повторяются условия функции bakeBMQVStart() (при замене privkeyb
	на privkey и certb на сеrt).
	\return ERR_OK, если протокол успешно выполнен, и код ошибки в противном 
	случае.
*/
err_t bakeBMQVRunB(
	octet key[32],					/*!< [out] общий ключ */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet privkeyb[],			/*!< [in] личный ключ стороны B */
	const bake_cert* certb,			/*!< [in] сертификат стороны B */
	const bake_cert* certa,			/*!< [in] сертификат стороны A */
	read_i read,					/*!< [in] функция чтения */
	write_i write,					/*!< [in] функция записи */
	void* file						/*!< [in/out] канал связи */
);

/*!	\brief Выполнение BMQV стороной A

	Протокол BMQV с параметрами params и настройками settings выполняется 
	от лица стороны A по каналу file с функциями чтения read и записи write. 
	Сторона A использует личный ключ [l / 4]privkeya, соответствующий 
	сертификат certa и сертификат certb стороны B. В результате выполнения 
	протокола определяется общий ключ key.
	\expect Повторяются условия функции bakeBMQVStart() (при замене privkeya
	на privkey и certa на сеrt).
	\return ERR_OK, если протокол успешно выполнен, и код ошибки в противном 
	случае.
*/
err_t bakeBMQVRunA(
	octet key[32],					/*!< [out] общий ключ */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet privkeya[],			/*!< [in] личный ключ */
	const bake_cert* certa,			/*!< [in] сертификат стороны A */
	const bake_cert* certb,			/*!< [in] сертификат стороны B */
	read_i read,					/*!< [in] функция чтения */
	write_i write,					/*!< [in] функция записи */
	void* file						/*!< [in/out] канал связи */
);

/*!
*******************************************************************************
\file bake.h

\section bake-bsts Протокол BSTS
*******************************************************************************
*/

/*!	\brief Длина состояния функций BSTS

	Возвращается длина состояния (в октетах) функций протокола BSTS.
	\return Длина состояния.
*/
size_t bakeBSTS_keep(
	size_t l						/*!< [in] уровень стойкости */
);

/*!	\brief Инициализация протокола BSTS

	По параметрам params, настройкам settings, личному ключу [l / 4]privkey 
	и сертификату cert соответствующего открытого ключа в state формируются 
	структуры данных, необходимые для выполнения протокола BSTS.
	\pre По адресу state зарезервировано bakeBSTS_keep() октетов.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_INPUT} settings->kca == TRUE && settings->kcb == TRUE.
	\expect{ERR_BAD_INPUT} Указатель settings->helloa нулевой, либо буфер 
	[settings->helloa_len]settings->helloa корректен. Аналогичное требование
	касается полей settings->hellob, settings->hellob_len.
	\expect{ERR_BAD_RNG} Генератор settings->rng (с состоянием 
	settings->rng_state) корректен.
	\expect Генератор settings->rng является криптографически стойким.
	\expect{ERR_BAD_CERT} Сертификат cert корректен.
	\expect Ключ privkey и сертификат cert согласованы. Если согласование
	нарушено, то протокол будет завершен с ошибкой.
	\return ERR_OK, если инициализация успешно выполнена, и код ошибки 
	в противном случае.
*/
err_t bakeBSTSStart(
	void* state,					/*!< [out] состояние */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet privkey[],			/*!< [in] личный ключ */
	const bake_cert* cert			/*!< [in] сертификат */
);

/*!	\brief Шаг 2 протокола BSTS

	Выполняется шаг 2 протокола BSTS с состоянием state. Сторона B формирует
	сообщение M1 = [l / 2]out.
	\expect bakeBSTSStart() < bakeBSTSStep2().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
	\remark Приветственное сообщение стороны B в M1 не передаются. 
*/
err_t bakeBSTSStep2(
	octet out[],			/*!< [out] выходное сообщение M1 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 3 протокола BSTS

	Выполняется шаг 3 протокола BSTS с состоянием state. Сторона A 
	обрабатывает сообщение M1 = [l / 2]in и формирует сообщение 
	M2 = [3 * l / 4 + cert->len + 8]out. 
	\expect bakeBSTSStart() < bakeBSTSStep3().
	\expect bakeBSTSStep2() << bakeBSTSStep3().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
	\remark Синтаксис [?out_len]out объяснен в defs.h. 
*/
err_t bakeBSTSStep3(
	octet out[],			/*!< [out] выходное сообщение M2 */
	const octet in[],		/*!< [in] входное сообщение M1 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 4 протокола BSTS

	Выполняется шаг 4 протокола BSTS с состоянием state. Сторона B 
	обрабатывает сообщение M2 = [in_len]in и формирует сообщение 
	M3 = [l / 4 + cert->len + 8]out. Сторона B проверяет присланный 
	в M2 сертификат стороны A с помощью функции vala.
	\expect bakeBSTSStep2() < bakeBSTSStep4().
	\expect bakeBSTSStep3() << bakeBSTSStep4().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBSTSStep4(
	octet out[],			/*!< [out] выходное сообщение M3 */
	const octet in[],		/*!< [in] входное сообщение M2 */
	size_t in_len,			/*!< [in] длина in */
	bake_certval_i vala,	/*!< [in] функция проверки сертификата стороны A */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 5 протокола BSTS

	Выполняется шаг 5 протокола BSTS с состоянием state. Сторона A 
	обрабатывает сообщение M3 = [in_len]in. Сторона A проверяет присланный 
	в M3 сертификат стороны B с помощью функции valb.
	\expect bakeBSTSStep5() < bakeBSTSStep3().
	\expect bakeBSTSStep4() << bakeBSTSStep5().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBSTSStep5(
	const octet in[],		/*!< [in] входное сообщение M3 */
	size_t in_len,			/*!< [in] длина in */
	bake_certval_i valb,	/*!< [in] функция проверки сертификата стороны B */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Извлечение ключа протокола BSTS

	Определяется общий секретный ключ key, полученный с помощью протокола BSTS
	с состоянием state.
	\expect bakeBSTSStep4() < bakeBSTSStepG().
	\expect Если сторона B не подтверждает ключ, то 
	bakeBSTSStep3() < bakeBSTSStepG(). Если подтверждает, то 
	bakeBSTSStep5() < bakeBSTSStepG().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBSTSStepG(
	octet key[32],			/*!< [out] общий ключ */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Выполнение BSTS стороной B

	Протокол BSTS с параметрами params и настройками settings выполняется 
	от лица стороны B по каналу file с функциями чтения read и записи write.
	Сторона B использует личный ключ [l / 4]privkeyb, соответствующий 
	сертификат certb и функцию vala проверки сертификата стороны A. 
	В результате выполнения протокола определяется общий ключ key.
	\expect Повторяются условия функции bakeBSTSStart() (при замене privkeyb
	на privkey и certb на сеrt).
	\return ERR_OK, если протокол успешно выполнен, и код ошибки в противном 
	случае.
*/
err_t bakeBSTSRunB(
	octet key[32],					/*!< [out] общий ключ */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet privkeyb[],			/*!< [in] личный ключ стороны B */
	const bake_cert* certb,			/*!< [in] сертификат стороны B */
	bake_certval_i vala,			/*!< [in] функция проверки сертификата A */
	read_i read,					/*!< [in] функция чтения */
	write_i write,					/*!< [in] функция записи */
	void* file						/*!< [in/out] канал связи */
);

/*!	\brief Выполнение BSTS стороной A

	Протокол BSTS с параметрами params и настройками settings выполняется 
	от лица стороны A по каналу file с функциями чтения read и записи write. 
	Сторона A использует личный ключ [l / 4]privkeya, соответствующий 
	сертификат certa и функцию valb проверки сертификата стороны B. 
	В результате выполнения протокола определяется общий ключ key.
	\expect Повторяются условия функции bakeBSTSStart() (при замене privkeya
	на privkey и certa на сеrt).
	\return ERR_OK, если протокол успешно выполнен, и код ошибки в противном 
	случае.
*/
err_t bakeBSTSRunA(
	octet key[32],					/*!< [out] общий ключ */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet privkeya[],			/*!< [in] личный ключ стороны A */
	const bake_cert* certa,			/*!< [in] сертификат стороны A */
	bake_certval_i valb,			/*!< [in] функция проверки сертификата B */
	read_i read,					/*!< [in] функция чтения */
	write_i write,					/*!< [in] функция записи */
	void* file						/*!< [in/out] канал связи */
);

/*!
*******************************************************************************
\file bake.h

\section bake-bpace Протокол BPACE
*******************************************************************************
*/

/*!	\brief Длина состояния функций BPACE

	Возвращается длина состояния (в октетах) функций протокола BPACE.
	\return Длина состояния.
*/
size_t bakeBPACE_keep(
	size_t l						/*!< [in] уровень стойкости */
);

/*!	\brief Инициализация протокола BPACE

	По параметрам params, настройкам settings и паролю [pwd_len]pwd в state
	формируются структуры данных, необходимые для выполнения протокола BPACE. 
	\pre По адресу state зарезервировано bakeBPACE_keep() октетов.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_INPUT} Указатель settings->helloa нулевой, либо буфер 
	[settings->helloa_len]settings->helloa корректен. Аналогичное требование
	касается полей settings->hellob, settings->hellob_len.
	\expect{ERR_BAD_RNG} Генератор settings->rng (с состоянием 
	settings->rng_state) корректен.
	\expect Генератор settings->rng является криптографически стойким.
	\return ERR_OK, если инициализация успешно выполнена, и код ошибки 
	в противном случае.
*/
err_t bakeBPACEStart(
	void* state,					/*!< [out] состояние */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet pwd[],				/*!< [in] пароль */
	size_t pwd_len					/*!< [in] длина пароля */
);

/*!	\brief Шаг 2 протокола BPACE

	Выполняется шаг 2 протокола BPACE с состоянием state. Сторона B формирует
	сообщение M1 = [l / 8]out.
	\expect bakeBPACEStart() < bakeBPACEStep2().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
	\remark Приветственное сообщение стороны B в M1 не передается. 
*/
err_t bakeBPACEStep2(
	octet out[],			/*!< [out] выходное сообщение M1 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 3 протокола BPACE

	Выполняется шаг 3 протокола BPACE с состоянием state. Сторона A 
	обрабатывает сообщение M1 = [l / 8]in и формирует сообщение 
	M2 = [5 * l / 8]out.
	\expect bakeBPACEStart() < bakeBPACEStep3().
	\expect bakeBPACEStep2() << bakeBPACEStep3().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBPACEStep3(
	octet out[],			/*!< [out] выходное сообщение M2 */
	const octet in[],		/*!< [in] входное сообщение M1 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 4 протокола BPACE

	Выполняется шаг 4 протокола BPACE с состоянием state. Сторона B 
	обрабатывает сообщение M2 = [5 * l / 8]in и формирует сообщение 
	M3 = [4 * l / 8 + (kcb ? 8 : 0)]out.
	\expect bakeBPACEStep2() < bakeBPACEStep4().
	\expect bakeBPACEStep3() << bakeBPACEStep4().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBPACEStep4(
	octet out[],			/*!< [out] выходное сообщение M3 */
	const octet in[],		/*!< [in] входное сообщение M2 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 5 протокола BPACE

	Выполняется шаг 5 протокола BPACE с состоянием state. Сторона A 
	обрабатывает сообщение M3 = [4 * l / 8 + (kcb ? 8 : 0)]in и формирует 
	сообщение M4 = [kca ? 8 : 0]out.
	\expect bakeBPACEStep3() < bakeBPACEStep5().
	\expect bakeBPACEStep4() << bakeBPACEStep5().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBPACEStep5(
	octet out[],			/*!< [out] выходное сообщение M4 */
	const octet in[],		/*!< [in] входное сообщение M3 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Шаг 6 протокола BPACE

	Выполняется шаг 6 протокола BPACE с состоянием state. Сторона B 
	обрабатывает сообщение M4 = [8]in. Шаг выполняется только тогда,
	когда A подтверждает ключ (kca == 0).
	\expect bakeBPACEStep4() < bakeBPACEStep6().
	\expect bakeBPACEStep5() << bakeBPACEStep6().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBPACEStep6(
	const octet in[8],		/*!< [in] входное сообщение M4 */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Извлечение ключа протокола BPACE

	Определяется общий секретный ключ key, полученный с помощью протокола BPACE
	с состоянием state.
	\expect bakeBPACEStep5() < bakeBPACEStepG().
	\expect Если сторона A не подтверждает ключ, то 
	bakeBPACEStep4() < bakeBPACEStepG(). Если подтверждает, то 
	bakeBPACEStep6() < bakeBPACEStepG().
	\return ERR_OK, если шаг успешно выполнен, и код ошибки в противном случае.
*/
err_t bakeBPACEStepG(
	octet key[32],			/*!< [out] общий ключ */
	void* state				/*!< [in/out] состояние */
);

/*!	\brief Выполнение BPACE стороной B

	Протокол BPACE с параметрами params и настройками settings выполняется от 
	лица стороны B по каналу file с функциями чтения read и записи write. 
	Сторона B использует пароль [pwd_len]pwd. В результате выполнения протокола 
	определяется общий ключ key.
	\expect Повторяются условия функции bakeBPACEStart().
	\return ERR_OK, если протокол успешно выполнен, и код ошибки в противном 
	случае.
*/
err_t bakeBPACERunB(
	octet key[32],					/*!< [out] общий ключ */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet pwd[],				/*!< [in] пароль */
	size_t pwd_len,					/*!< [in] длина пароля */
	read_i read,					/*!< [in] функция чтения */
	write_i write,					/*!< [in] функция записи */
	void* file						/*!< [in/out] канал связи */
);

/*!	\brief Выполнение BPACE стороной A

	Протокол BPACE с параметрами params и настройками settings выполняется от 
	лица стороны A по каналу file с функциями чтения read и записи write. 
	Сторона A использует пароль [pwd_len]pwd. В результате выполнения протокола 
	определяется общий ключ key.
	\expect Повторяются условия функции bakeBPACEStart().
	\return ERR_OK, если протокол успешно выполнен, и код ошибки в противном 
	случае.
*/
err_t bakeBPACERunA(
	octet key[32],					/*!< [out] общий ключ */
	const bign_params* params,		/*!< [in] долговременные параметры */
	const bake_settings* settings,	/*!< [in] настройки */
	const octet pwd[],				/*!< [in] пароль */
	size_t pwd_len,					/*!< [in] длина пароля */
	read_i read,					/*!< [in] функция чтения */
	write_i write,					/*!< [in] функция записи */
	void* file						/*!< [in/out] канал связи */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BAKE_H */