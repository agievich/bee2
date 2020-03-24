/*
*******************************************************************************
\file mem.h
\brief Memory management
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.07.16
\version 2019.07.09
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file mem.h
\brief Управление памятью
*******************************************************************************
*/

#ifndef __BEE2_MEM_H
#define __BEE2_MEM_H

#include <memory.h>
#include <string.h>
#include "bee2/defs.h"
#include "bee2/core/safe.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file mem.h

Реализованы или переопределены манипуляции над буферами памяти, которые
интерпретируются как строки октетов.

Функции xxTo и xxFrom выполняют преобразования между буферами
памяти и другими структурами данных. Могут быть функции двух типов:
простые и сложные. В простых функциях объем памяти для размещения
преобразованных данных сразу известен. В простые функции передается
корректный указатель на буфер-назначение, простые функции не возвращают
никаких значений. В сложных функциях объем выходных данных рассчитывается
по входным и возвращается как выходное значение. В сложную функцию можно
передать нулевой указатель на буфер-назначение, получить требуемый объем
буфера, зарезервировать буфер и обратиться к функции еще один раз.

Буфер памяти может представлять массив слов u16, u32, u64, word.
Стандартными считаются соглашения LITTLE_ENDIAN (см. defs.h). Поэтому
на платформах с соглашениями BIG_ENDIAN при загрузке слова из памяти
и, наоборот, при сохранении слова в памяти выполняется реверс октетов
слова.

\pre В функции передаются корректные буферы памяти.
*******************************************************************************
*/

/*
*******************************************************************************
Стандартные функции
*******************************************************************************
*/

/*!	\brief Копировать буфер памяти

	Октеты буфера [count]src переписываются в буфер [count]dest.
	\pre Буферы src и dest не пересекаются.
*/
void memCopy( 
	void* dest,			/*< [out] буфер-назначение */
	const void* src,	/*< [in] буфер-источник */
	size_t count		/*< [in] число октетов */
);

/*!	\brief Переместить буфер памяти

	Октеты буфера [count]src перемещаются в буфер [count]dest.
	\pre Буферы src и dest могут пересекаться.
*/
void memMove( 
	void* dest,			/*< [out] буфер-назначение */
	const void* src,	/*< [in] буфер-источник */
	size_t count		/*< [in] число октетов */
);

/*!	\brief Заполнить буфер памяти

	Буфер [count]buf заполняется октетом c.
*/
void memSet( 
	void* buf,			/*< [out] буфер */
	octet c,			/*< [in] октет-значение */
	size_t count		/*< [in] число октетов */
);

/*!	Буфер [count]buf обнуляется. */
#define memSetZero(buf, count) memSet(buf, 0, count)

/*!	\brief Инвертировать буфер памяти

	Все биты буфера [count]buf инвертируются.
*/
void memNeg( 
	void* buf,			/*< [in/out] буфер */
	size_t count		/*< [in] число октетов */
);

/*!	\brief Выделение блока памяти
	Выделяется блок динамической памяти из count октетов.
	\return Указатель на блок памяти или 0, если памяти не хватает.
	\remark Блок выделяется, даже если count == 0.
*/
void* memAlloc(
	size_t count		/*!< [in] размер блока */
);

/*!	\brief Изменение размера блока памяти
	Размер блока динамической памяти buf устанавливается равным count. 
	При необходимости блок перемещается в памяти. Содержимое блока 
	максимально сохраняется. 
	\return Указатель на блок памяти с новым размером 
	или 0, если count == 0 или памяти не хватает.
	\remark memRealloc(buf, 0) равносильно memFree(buf).
*/
void* memRealloc(
	void* buf,		/*!< [in] блок памяти */
	size_t count	/*!< [in] размер блока */
);

/*!	\brief Освобождение блока памяти

	Освобождается блок динамической памяти buf.
	\pre buf выделен с помощью memAlloc() или memRealloc().
*/
void memFree(
	void* buf		/*!< [in] буфер */
);

/*
*******************************************************************************
Дополнительные функции
*******************************************************************************
*/

/*!	\brief Корректный буфер памяти?

	Проверяется, что [count]buf является корректным буфером.
	\return Проверяемый признак.
	\remark Нулевой указатель buf является корректным, если count == 0.
*/
bool_t memIsValid(
	const void* buf,	/*!< [in] буфер */
	size_t count		/*!< [in] размер буфера */
);

/*!	\def memIsNullOrValid
	\brief Нулевой указатель или корректный буфер памяти? 
*/
#define memIsNullOrValid(buf, count)\
	((buf) == 0 || memIsValid(buf, count))

/*!	\brief Буфер выровнен на границу?

	Проверяется, что buf выровнен на границу size-байтового блока.
	\return Проверяемый признак.
*/
bool_t memIsAligned(
	const void* buf,	/*!< [in] буфер */
	size_t size			/*!< [in] длина блока */
);


/*!	\brief Проверка совпадения

	Проверяется, что содержимое буферов [count]buf1 и [count]buf2 совпадает. 
	\return Признак совпадения.
	\safe Имеется ускоренная нерегулярная редакция.
*/
bool_t memEq(
	const void* buf1,	/*!< [in] первый буфер */
	const void* buf2,	/*!< [in] второй буфер */
	size_t count		/*!< [in] размер буферов */
);

bool_t SAFE(memEq)(const void* buf1, const void* buf2, size_t count);
bool_t FAST(memEq)(const void* buf1, const void* buf2, size_t count);

/*!	\brief Сравнение

	Буферы [count]buf1 и [count]buf2 сравниваются обратно-лексикографически.
	\return < 0, если [count]buf1 < [count]buf2, 
	0, если [count]buf1 == [count]buf2, 
	> 0, если [count]buf1 > [count]buf2.
	\remark Октеты буферов сравниваются последовательно, от последнего 
	к первому. Первое несовпадение задает соотношение между буферами.
	\warning Стандартная функция memcmp() сравнивает октеты от первого 
	к последнему.
	\safe Имеется ускоренная нерегулярная редакция.
*/
int memCmp(
	const void* buf1,	/*!< [in] первый буфер */
	const void* buf2,	/*!< [in] второй буфер */
	size_t count		/*!< [in] размер буферов */
);

int SAFE(memCmp)(const void* buf1, const void* buf2, size_t count);
int FAST(memCmp)(const void* buf1, const void* buf2, size_t count);

/*!	\brief Очистить буфер памяти

	Буфер [count]buf очищается -- в него записываются произвольные октеты.
	\remark Запись выполняется всегда, даже если buf в дальнейшем не
	используется и включена оптимизация компиляции.
*/
void memWipe(
	void* buf,			/*!< [out] буфер */
	size_t count		/*!< [in] размер буфера */
);

/*!	\brief Нулевой буфер памяти?

	Проверяется, что буфер [count]buf является нулевым.
	\return Проверяемый признак.
	\safe Имеется ускоренная нерегулярная редакция.
*/
bool_t memIsZero(
	const void* buf,	/*!< [out] буфер */
	size_t count		/*!< [in] размер буфера */
);

bool_t SAFE(memIsZero)(const void* buf, size_t count);
bool_t FAST(memIsZero)(const void* buf, size_t count);

/*!	\brief Размер значащей части буфера

	Определяется размер значащей части буфера [count]buf.
	Незначащими считаются последние нулевые октеты буфера вплоть до первого
	ненулевого.
	\return Размер значащей части в октетах.
	\safe Функция нерегулярна: время выполнения зависит от заполнения buf.
*/
size_t memNonZeroSize(
	const void* buf,	/*!< [out] буфер */
	size_t count		/*!< [in] размер буфера */
);

/*!	\brief Повтор октета?

	Проверяется, что [count]buf заполнен октетом o.
	\remark Считается, что в пустом буфере (count == 0) повторяется значение 0.
	\return Признак успеха.
	\safe Имеется ускоренная нерегулярная редакция.
*/
bool_t memIsRep(
	const void* buf,	/*!< [in] буфер */
	size_t count,		/*!< [in] размер буфера */
	octet o				/*!< [in] значение */
);

bool_t SAFE(memIsRep)(const void* buf, size_t count, octet o);
bool_t FAST(memIsRep)(const void* buf, size_t count, octet o);

/*!	\brief Объединение двух буферов

	В dest записывается блок [count1]src1 || [count2]src2.
	\pre По адресам src1, src2, dest зарезервировано count1, count2 и
	count1 +  count2 октетов памяти соответственно.
	\remark Буферы src1, src2 и dest могут пересекаться.
*/
void memJoin(
	void* dest,			/*!< [out] назначение */
	const void* src1,	/*!< [in] первый источник */
	size_t count1,		/*!< [in] число октетов src1 */
	const void* src2,	/*!< [in] второй источник */
	size_t count2		/*!< [in] число октетов src2 */
);

/*!	\brief Буферы одинакового размера не пересекаются?

	Проверяется, что буфер [count]buf1 не пересекается с буфером [count]buf2.
	\return Проверяемый признак.
	\pre Буферы buf1 и buf2 корректны.
*/
bool_t memIsDisjoint(
	const void* buf1,	/*!< [out] первый буфер */
	const void* buf2,	/*!< [out] второй буфер */
	size_t count		/*!< [in] размер буферов */
);

/*!	\brief Буферы совпадают или не пересекаются?

	Проверяется, что буфер [count]buf1 совпадает или не пересекается с буфером 
	[count]buf2.
	\return Проверяемый признак.
	\pre Буферы buf1 и buf2 корректны.
*/
bool_t memIsSameOrDisjoint(
	const void* buf1,	/*!< [out] первый буфер */
	const void* buf2,	/*!< [out] второй буфер */
	size_t count		/*!< [in] размер буферов */
);

/*!	\brief Два буфера не пересекаются?

	Проверяется, что буфер [count1]buf1 не пересекается с буфером [count2]buf2.
	\return Проверяемый признак.
	\pre Буферы buf1 и buf2 корректны.
*/
bool_t memIsDisjoint2(
	const void* buf1,	/*!< [out] первый буфер */
	size_t count1,		/*!< [in] размер buf1 */
	const void* buf2,	/*!< [out] второй буфер */
	size_t count2		/*!< [in] размер buf2 */
);

/*!	\brief Три буфера не пересекаются?

	Проверяется, что буферы [count1]buf1, [count2]buf2 и [count3]buf3 
	попарно не пересекаются.
	\return Проверяемый признак.
	\pre Буферы buf1, buf2 и buf3 корректны.
*/
bool_t memIsDisjoint3(
	const void* buf1,	/*!< [out] первый буфер */
	size_t count1,		/*!< [in] размер buf1 */
	const void* buf2,	/*!< [out] второй буфер */
	size_t count2,		/*!< [in] размер buf2 */
	const void* buf3,	/*!< [out] третий буфер */
	size_t count3		/*!< [in] размер buf3 */
);

/*!	\brief Четыре буфера не пересекаются?

	Проверяется, что буферы [count1]buf1, [count2]buf2, [count3]buf3 
	и [count4]buf4 попарно не пересекаются.
	\return Проверяемый признак.
	\pre Буферы buf1, buf2, buf3 и buf4 корректны.
*/
bool_t memIsDisjoint4(
	const void* buf1,	/*!< [out] первый буфер */
	size_t count1,		/*!< [in] размер buf1 */
	const void* buf2,	/*!< [out] второй буфер */
	size_t count2,		/*!< [in] размер buf2 */
	const void* buf3,	/*!< [out] третий буфер */
	size_t count3,		/*!< [in] размер buf3 */
	const void* buf4,	/*!< [out] четвертый буфер */
	size_t count4		/*!< [in] размер buf4 */
);

/*!	\brief Cложение октетов памяти по модулю 2

	В буфер [count]dest записывается поразрядная по модулю 2 сумма октетов
	октетов буферов [count]src1 и [count]src2.
	\pre Буфер dest либо не пересекается, либо совпадает с каждым из
	буферов src1, src2.
*/
void memXor(
	void* dest,			/*!< [out] сумма */
	const void* src1,	/*!< [in] первое слагаемое */
	const void* src2,	/*!< [in] второе слагаемое */
	size_t count		/*!< [in] число октетов */
);

/*!	\brief Добавление октетов памяти по модулю 2

	К октетам буфера [count]dest добавляются октеты буфера [count]src. 
	Сложение выполняется поразрядно по модулю 2.
	\pre Буфер dest либо не пересекается, либо совпадает с буфером src.
*/
void memXor2(
	void* dest,			/*!< [in/out] второе слагаемое / сумма */
	const void* src,	/*!< [in] первое слагаемое */
	size_t count		/*!< [in] число октетов */
);

/*!	\brief Перестановка октетов памяти

	Октеты буферов [count]buf1 и [count]buf2 меняются местами. 
	\pre Буферы buf1 и buf2 не пересекаются.
*/
void memSwap(
	void* buf1,		/*!< [in/out] первый буфер */
	void* buf2,		/*!< [in/out] второй буфер */
	size_t count	/*!< [in] число октетов */
);

/*
*******************************************************************************
Реверс октетов
*******************************************************************************
*/

/*!	\brief Реверс октетов

	Октеты буфера [count]buf записываются в обратном порядке.
*/
void memRev(
	void* buf,		/*!< [out] буфер */
	size_t count	/*!< [in] размер буфера */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_MEM_H */
