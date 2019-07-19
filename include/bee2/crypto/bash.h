/*
*******************************************************************************
\file bash.h
\brief STB 34.101.77 (bash): sponge-based algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.15
\version 2019.07.19
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#ifndef __BEE2_BASH_H
#define __BEE2_BASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"

/*!
*******************************************************************************
\file bash.h

Алгоритмы СТБ 34.101.77

СТБ 34.101.77 определяет семейство алгоритмов хэширования на основе 
sponge-функции bash-f, реализованной в bashF(). Sponge-функция имеет 
самостоятельное значение и может использоваться не только для хэширования.

Конкретный алгоритм хэширования bashHashNNN возвращает NNN-битовые хэш-значения,
где NNN кратно 32 и не превосходит 512. Параметр NNN регулируется уровнем 
стойкости l = NNN / 2. 

Хэширование выполняется по схеме:
-	определить длину хэш-состояния с помощью функции bash_keep();
-	подготовить буфер памяти для состояния;
-	инициализировать состояние с помощью bashHashStart(). Передать в эту 
	функцию требуемый уровень стойкости;
-	обработать фрагменты хэшируемых данных с помощью bashHashStepH();
-	определить хэш-значение с помощью bashHashStepG() или проверить его 
	с помощью bashHashStepV().

Функции bashHashStart(), bashHashStepH(), bashHashStepG(), bashHashStepV() 
используют общее хэш-состояние и образуют связку. Функции связки являются 
низкоуровневыми --- в них не проверяются входные данные. 
Связка покрывается высокоуровневой функцией bashHash().

Стандартные уровни l = 128, 192, 256 поддержаны макросами bashNNNXXX.

Расширение СТБ 34.101.77 (в стадии разработки) определяет алгоритмы 
аутентифицированного шифрования.

Алгоритмы аутентифицированного шифрования реализуются 5 операциями:
-	Start (инициализировать);
-	Absorb (загрузить / абсорбировать данные);
-	Squeeze (выгрузить данные);
-	Encr (зашифровать);
-	Decr (расшифровать).

Первая операция поддерживается функцией bashAEStart(). Каждая следующая 
операция обрабатывает данные потенциально произвольного объема. 
Поэтому предусмотрена стандартная цепочечная обработка по схеме 
Start/Step/Stop. Схема поддерживается функциями bashAENNNStart(), 
bashAENNNStep(), bashAENNNStop(), где NNN -- имя операции.

Константы BASH_AE_XXX описывают типы обратываемых данных. Константы 
определены в СТБ 34.101.77.

\expect Общее состояние связки функций не изменяется вне этих функций.

\pre Все входные указатели низкоуровневых функций действительны.

\pre Если не оговорено противное, то входные буферы функций связки 
не пересекаются.

\remark При сборке библиотеки через опцию BASH_PLATFORM можно запросить
использование реализации bashF(), оптимизированной для одной из 5 аппаратных 
платформ: 
- 64-разрядной (BASH_64), 
- 32-разрядной (BASH_32), 
- Intel SSE2 (BASH_SSE2),
- Intel AVX2 (BASH_AVX2),
- Intel AVX512 (BASH_AVX512).
По умолчанию используется реализация для платформы BASH_64 либо, если 
64-разрядные регистры не поддерживаются, BASH_32.

\safe Реализация для платформ BASH_SSE2, BASH_AVX2, BASH_AVX512 могут 
оставлять в стеке данные, которые не помещаются в расширенные регистры 
соответствующих архитектур.

\remark При описании Absorb / Squeeze мы используем вполне уместный жаргон:
"загрузить в состояние", "выгрузить из состояния", "зашифровать на состоянии".
*******************************************************************************
*/

/*!	\brief Глубина стека sponge-функции

	Возвращается глубина стека (в октетах) sponge-функции.
	\return Глубина стека.
*/
size_t bashF_deep();

/*!	\brief Sponge-функция

	Буфер block преобразуется с помощью sponge-функции bash-f.
	\pre Буфер block корректен.
*/
void bashF(
	octet block[192],	/*!< [in/out] прообраз/образ */
	void* stack			/*!< [in/out] стек */
);

/*
*******************************************************************************
bashHash
*******************************************************************************
*/

/*!	\brief Длина состояния функций хэширования

	Возвращается длина состояния (в октетах) алгоритмов хэширования bash.
	\return Длина состояния.
*/
size_t bashHash_keep();

/*!	\brief Инициализация хэширования

	В state формируются структуры данных, необходимые для хэширования 
	с помощью алгоритмов bash уровня l.
	\pre l > 0 && l % 16 == 0 && l <= 256.
	\pre По адресу state зарезервировано bashHash_keep() октетов.
*/
void bashHashStart(
	void* state,		/*!< [out] состояние */
	size_t l			/*!< [in] уровень стойкости */
);	

/*!	\brief Хэширование фрагмента данных

	Текущее хэш-значение, размещенное в state, пересчитывается по алгоритму 
	bash с учетом нового фрагмента данных [count]buf.
	\expect bashHashStart() < bashHashStepH()*.
*/
void bashHashStepH(
	const void* buf,	/*!< [in] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Определение хэш-значения

	Определяются первые октеты [hash_len]hash окончательного хэш-значения 
	всех данных, обработанных до этого функцией bashHashStepH().
	\pre hash_len <= l / 4, где l -- уровень стойкости, ранее переданный 
	в bashHashStart().
	\expect (bashHashStepH()* < bashHashStepG())*. 
	\remark Если продолжение хэширования не предполагается, то буферы 
	hash и state могут пересекаться.
*/
void bashHashStepG(
	octet hash[],		/*!< [out] хэш-значение */
	size_t hash_len,	/*!< [in] длина hash */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Проверка хэш-значения

	Прооверяется, что первые октеты окончательного хэш-значения 
	всех данных, обработанных до этого функцией bashHashStepH(),
	совпадают с [hash_len]hash.
	\pre hash_len <= l / 4, где l -- уровень стойкости, ранее переданный 
	в bashHashStart().
	\expect (bashHashStepH()* < bashHashStepV())*.
	\return Признак успеха.
*/
bool_t bashHashStepV(
	const octet hash[],	/*!< [in] контрольное хэш-значение */
	size_t hash_len,	/*!< [in] длина hash */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Хэширование

	С помощью алгоритма bash уровня стойкости l определяется хэш-значение 
	[l / 4]hash буфера [count]src.
	\expect{ERR_BAD_PARAM} l > 0 && l % 16 == 0 && l <= 256.
	\expect{ERR_BAD_INPUT} Буферы hash, src корректны.
	\return ERR_OK, если хэширование завершено успешно, и код ошибки
	в противном случае.
	\remark Буферы могут пересекаться.
*/
err_t bashHash(
	octet hash[],		/*!< [out] хэш-значение */
	size_t l,			/*!< [out] уровень стойкости */
	const void* src,	/*!< [in] данные */
	size_t count		/*!< [in] число октетов данных */
);

/*
*******************************************************************************
bash256
*******************************************************************************
*/

#define bash256_keep bashHash_keep
#define bash256Start(state) bashHashStart(state, 128)
#define bash256StepH(buf, count, state) bashHashStepH(buf, count, state)
#define bash256StepG(hash, state) bashHashStepG(hash, 32, state)
#define bash256StepG2(hash, hash_len, state)\
	bashHashStepG(hash, hash_len, state)
#define bash256StepV(hash, state) bashHashStepV(hash, 32, state)
#define bash256StepV2(hash, hash_len, state)\
	bashHashStepV2(hash, hash_len, state)
#define bash256Hash(hash, src, count) bashHash(hash, 128, src, count)

/*
*******************************************************************************
bash384
*******************************************************************************
*/

#define bash384_keep bashHash_keep
#define bash384Start(state) bashHashStart(state, 192)
#define bash384StepH(buf, count, state) bashHashStepH(buf, count, state)
#define bash384StepG(hash, state) bashHashStepG(hash, 48, state)
#define bash384StepG2(hash, hash_len, state)\
	bashHashStepG(hash, hash_len, state)
#define bashHash384StepV(hash, state) bashHashStepV(hash, 48, state)
#define bash384StepV2(hash, hash_len, state)\
	bashHashStepV2(hash, hash_len, state)
#define bash384Hash(hash, src, count) bashHash(hash, 192, src, count)

/*
*******************************************************************************
bashHash512
*******************************************************************************
*/

#define bash512_keep bashHash_keep
#define bash512Start(state) bashHashStart(state, 256)
#define bash512StepH(buf, count, state) bashHashStepH(buf, count, state)
#define bash512StepG(hash, state) bashHashStepG(hash, 64, state)
#define bash512StepG2(hash, hash_len, state)\
	bashHashStepG(hash, hash_len, state)
#define bash512StepV(hash, state) bashHashStepV(hash, 64, state)
#define bash512StepV2(hash, hash_len, state)\
	bashHashStepV2(hash, hash_len, state)
#define bash512Hash(hash, src, count) bashHash(hash, 256, src, count)

/*
*******************************************************************************
bashAE
*******************************************************************************
*/

#define BASH_AE_KEY		0
#define BASH_AE_DATA	1
#define BASH_AE_TEXT	2
#define BASH_AE_PRN		5
#define BASH_AE_MAC		6

/*!	\brief Длина состояния функций AE

	Возвращается длина состояния (в октетах) AE-алгоритмов bash.
	\return Длина состояния.
*/
size_t bashAE_keep();

/*!	\brief Инициализация AE

	В state формируются структуры данных, необходимые для аутентифицированного
	шифрования на ключе [key_len]key и синхропосылке [iv_len]iv. 
	\pre key_len == 16 || key_len == 24 || key_len == 32.
	\pre iv_len <= key_len * 2.
	\pre По адресу state зарезервировано bashAE_keep() октетов.
	\remark Длина key_len определяет уровень стойкости l = key_len * 8.
*/
void bashAEStart(
	void* state,		/*!< [out] состояние */
	const octet key[],	/*!< [in] ключ */
	size_t key_len,		/*!< [in] длина ключа в октетах */
	const octet iv[],	/*!< [in] синхропосылка */
	size_t iv_len		/*!< [in] длина синхропосылки в октетах */
);

/*!	\brief Начало загрузка

	Инициализируется загрузка в state данных типа code.
	\pre code == BASH_AE_KEY || code == BASH_AE_DATA.
	\expect bashAEStart() < bashAEAbsorbStart().
*/
void bashAEAbsorbStart(
	octet code,			/*!< [in] код данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Шаг загрузки

	Выполняется абсорбирование в state фрагмента [count]buf.
	\expect bashAEAbsorbStart() < bashAEAbsorbStep()*.
*/
void bashAEAbsorbStep(
	const void* buf,	/*!< [in] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Окончание загрузки

	Завершается загрузка в state.
	\expect bashAEAbsorbStart() < bashAEAbsorbStep()* < bashAEAbsorbStop().
	\remark Если вызовы bashAEAbsorbStep() пропущены или во всех вызовах
	задаются пустые фрагменты, будет загружено пустое слово. Загрузка
	даже пустого слова требует вызова bashF().
*/
void bashAEAbsorbStop(
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Загрузка данных

	В состояние state загружаются данные [count]buf типа code. 
	\pre code == BASH_AE_KEY || code == BASH_AE_DATA.
	\expect bashAEStart() < bashAEAbsorb()*.
*/
void bashAEAbsorb(
	octet code,			/*!< [in] код данных */
	const void* buf,	/*!< [in] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Начало выгрузки

	Инициализируется выгрузка из state данных типа code.
	\pre code == BASH_AE_PRN || code == BASH_AE_MAC.
	\expect bashAEStart() < bashAESqueezeStart().
*/
void bashAESqueezeStart(
	octet code,			/*!< [in] код данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Шаг выгрузки

	Выполняется выгрузка из state фрагмента [count]buf.
	\expect bashAESqueezeStart() < bashAESqueezeStep()*.
*/
void bashAESqueezeStep(
	void* buf,			/*!< [out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Окончание выгрузки

	Завершается выгрузка из state.
	\expect bashAESqueezeStart() < bashAESqueezeStep()* < bashAESqueezeStop().
	\remark Если вызовы bashAESqueezeStep() пропущены или во всех вызовах
	задаются пустые фрагменты, будет выгружено пустое слово. Выгрузка даже 
	пустого слова требует вызова bashF().
*/
void bashAESqueezeStop(
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Выгрузка данных

	Из состояния state выгружаются данные [count]buf типа code. 
	\pre code == BASH_AE_RPN || code == BASH_AE_MAC.
	\expect bashAEStart() < bashAESqueeze()*.
*/
void bashAESqueeze(
	octet code,			/*!< [in] код данных */
	void* buf,			/*!< [out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Начало зашифрования

	Инициализируется зашифрование на state.
	\expect bashAEStart() < bashAEEncrStart().
*/
void bashAEEncrStart(
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Шаг зашифрования

	Выполняется зашифрование из state фрагмента [count]buf.
	\expect bashAEEncrStart() < bashAEEncrStep()*.
*/
void bashAEEncrStep(
	void* buf,			/*!< [in/out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Окончание зашифрования

	Завершается зашифрование state.
	\expect bashAEEncrStart() < bashAEEncrStep()* < bashAEEncrStop().
	\remark Если вызовы bashAEEncrStep() пропущены или во всех вызовах
	задаются пустые фрагменты, будет зашифровано пустое слово. 
	Зашифрование даже пустого слова требует вызова bashF().
*/
void bashAEEncrStop(
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Зашифрование данных

	На состоянии state зашифровываются данные [count]buf. 
	\expect bashAEStart() < bashAEEncr()*.
*/
void bashAEEncr(
	void* buf,			/*!< [in/out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Начало расшифрования

	Инициализируется расшифрование на state.
	\expect bashAEStart() < bashAEDecrStart().
*/
void bashAEDecrStart(
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Шаг расшифрования

	Выполняется расшифрование на state фрагмента [count]buf.
	\expect bashAEDecrStart() < bashAEDecrStep()*.
*/
void bashAEDecrStep(
	void* buf,			/*!< [in/out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Окончание расшифрования

	Завершается расшифрование state.
	\expect bashAEDecrStart() < bashAEDecrStep()* < bashAEDecrStop().
	\remark Если вызовы bashAEDecrStep() пропущены или во всех вызовах
	задаются пустые фрагменты, будет расшифровано пустое слово. 
	Расшифрование даже пустого слова требует вызова bashF().
*/
void bashAEDecrStop(
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Расшифрование данных

	На состоянии state расшифровываются данные [count]buf. 
	\expect bashAEStart() < bashAEDecr()*.
*/
void bashAEDecr(
	void* buf,			/*!< [in/out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BASH_H */
