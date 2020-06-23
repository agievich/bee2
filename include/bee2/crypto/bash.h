/*
*******************************************************************************
\file bash.h
\brief STB 34.101.77 (bash): sponge-based algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.15
\version 2020.06.23
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

Кроме алгоритмов хэширования, СТБ 34.101.77 определяет криптографический
автомат на основе sponge-функции и программируемые алгоритмы --
последовательности команд автомата.

Перечень команд:
-	start (инициализировать);
-	restart (повторно инициализировать);
-	absorb (загрузить данные);
-	squeeze (выгрузить данные);
-	encrypt (зашифровать, сокращается до encr);
-	decrypt (расшифровать, сокращается до decr);
-	ratchet (необратимо изменить автомат).

Еще одна команда, commit, является внутренней, она вызывается из других команд.

Команды start, restart, ratchet реализованы в функциях bashPrgStart(),
bashPrgRestart(), bashPrgRatchet().

Команды absorb, squeeze, encrypt, decrypt обрабатывают данные потенциально
произвольного объема. Поэтому предусмотрена стандартная цепочечная обработка
по схеме Start/Step. Схема поддерживается функциями bashPrgCmdStart(), 
bashPrgCmdStep(), где Cmd -- имя команды. Обратим внимание, что шаг Stop
отсутствует. Он не нужен, потому что команды автомата выполняются в отложенной
манере --- команда завершается при запуске следующей.

В функциях, реализующих команды, автомат программируемых алгоритмов
отождествляется со своим состоянием. Используется приемлемый (и отражающий
суть дела) жаргон: "загрузить в автомат", "выгрузить из автомата".

Конкретные программируемые алгоритмы, в том числе определенные в СТБ 34.101.77,
не реализованы. Их легко сконструировать, вызывая функции-команды
в определенной последовательности.

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
Алгоритмы хэширования (bashHash)
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
Программируемые алгоритмы (bashPrg)
*******************************************************************************
*/

/*!	\brief Длина состояния автомата 

	Возвращается длина состояния (в октетах) автомата программируемых
	алгоритмов.
	\return Длина состояния.
*/
size_t bashPrg_keep();

/*!	\brief Инициализация автомата

	По уровню стойкости l, емкости d, анонсу [ann_len]ann и ключу
	[key_len]ley инициализуется автомат state. 
	\pre l == 128 || l == 192 || l == 256.
	\pre d == 1 || d == 2.
	\pre ann_len % 4 == 0 && ann_len <= 60.
	\pre key_len % 4 == 0 && key_len <= 60.
	\pre key_len == 0 || key_len >= l / 8, где l --- уровень, заданный
	в bashPrgStart().
	\pre По адресу state зарезервировано bashPrg_keep() октетов.
	\remark Если key_len != 0, то автомат переводится в ключевой режим.
*/
void bashPrgStart(
	void* state,		/*!< [out] автомат */
	size_t l,			/*!< [in] уровень стойкости */
	size_t d,			/*!< [in] емкость */
	const octet ann[],	/*!< [in] анонс */
	size_t ann_len,		/*!< [in] длина анонса в октетах */
	const octet key[],	/*!< [in] ключ */
	size_t key_len		/*!< [in] длина ключа в октетах */
);

/*!	\brief Повторная инициализация автомата

	По анонсу [ann_len]ann и ключу [key_len]key выполняется повторная
	инициализация автомата state.
	\pre ann_len % 4 == 0 && ann_len <= 60.
	\pre key_len % 4 == 0 && key_len <= 60.
	\pre key_len == 0 || key_len >= l / 8, 
	\expect bashPrgStart() < bashPrgRestart()*.
	\remark Если key_len != 0, то автомат переводится в ключевой режим.
*/
void bashPrgRestart(
	const octet ann[],	/*!< [in] анонс */
	size_t ann_len,		/*!< [in] длина анонса в октетах */
	const octet key[],	/*!< [in] ключ */
	size_t key_len,		/*!< [in] длина ключа в октетах */
	void* state			/*!< [out] автомат */
);

/*!	\brief Начало загрузки данных

	Инициализируется загрузка данных в автомат state.
	\expect bashPrgStart() < bashPrgAbsorbStart().
	\remark В начале загрузки завершается предыдущая команда.
*/
void bashPrgAbsorbStart(
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Шаг загрузки данных

	Выполняется загрузка в автомат state фрагмента [count]buf.
	\expect bashPrgAbsorbStart() < bashPrgAbsorbStep()*.
*/
void bashPrgAbsorbStep(
	const void* buf,	/*!< [in] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Загрузка данных

	В автомат state загружаются данные [count]buf. 
	\expect bashPrgStart() < bashPrgAbsorb()*.
*/
void bashPrgAbsorb(
	const void* buf,	/*!< [in] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Начало выгрузки данных

	Инициализируется выгрузка данных из автомата state.
	\expect bashPrgStart() < bashPrgSqueezeStart().
	\remark В начале выгрузки завершается предыдущая команда.
*/
void bashPrgSqueezeStart(
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Шаг выгрузки данных

	Выполняется выгрузка из автомата state фрагмента [count]buf.
	\expect bashPrgSqueezeStart() < bashPrgSqueezeStep()*.
*/
void bashPrgSqueezeStep(
	void* buf,			/*!< [out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Выгрузка данных

	Из автомата state выгружаются данные [count]buf. 
	\expect bashPrgStart() < bashPrgSqueeze()*.
*/
void bashPrgSqueeze(
	void* buf,			/*!< [out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Начало зашифрования

	Инициализируется зашифрование с помощью автомата state.
	\expect bashPrgStart() < bashPrgEncrStart().
	\pre Автомат находится в ключевом режиме.
	\remark В начале зашифрования завершается предыдущая команда.
*/
void bashPrgEncrStart(
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Шаг зашифрования

	Выполняется зашифрование с помощью автомата state
	фрагмента [count]buf.
	\expect bashPrgEncrStart() < bashPrgEncrStep()*.
*/
void bashPrgEncrStep(
	void* buf,			/*!< [in/out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Зашифрование

	С помощью автомата state зашифровываются данные [count]buf.
	\pre Автомат находится в ключевом режиме.
	\expect bashPrgStart() < bashPrgEncr()*.
*/
void bashPrgEncr(
	void* buf,			/*!< [in/out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Начало расшифрования

	Инициализируется расшифрование данных с помощью автомата state.
	\pre Автомат находится в ключевом режиме.
	\expect bashPrgStart() < bashPrgDecrStart().
	\remark В начале расшифрования завершается предыдущая команда.
*/
void bashPrgDecrStart(
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Шаг расшифрования

	Выполняется расшифрование с помощью автомата state фрагмента [count]buf.
	\expect bashPrgDecrStart() < bashPrgDecrStep()*.
*/
void bashPrgDecrStep(
	void* buf,			/*!< [in/out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Расшифрование

	С помощью автомата state расшифровываются данные [count]buf. 
	\pre Автомат находится в ключевом режиме.
	\expect bashPrgStart() < bashPrgDecr()*.
*/
void bashPrgDecr(
	void* buf,			/*!< [in/out] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] автомат */
);

/*!	\brief Необратимое изменение автомата

	Автомат state меняется так, что по новому состоянию трудно определить
	предыдущее.
	\expect bashPrgStart() < bashPrgRatchet().
*/
void bashPrgRatchet(
	void* state			/*!< [in/out] автомат */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BASH_H */
