/*
*******************************************************************************
\file mt.h
\brief Multithreading
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.10
\version 2014.10.13
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file mt.h
\brief Поддержка многозадачности
*******************************************************************************
*/

#ifndef __BEE2_MT_H
#define __BEE2_MT_H

#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file mt.h

\section mt-mtx Мьютексы

Мьютексы — это объект, который может находиться в одном из двух состояний —
"заблокирован" или "разблокирован". Поток блокирует мьютекс с помощью функции
mtxLock() и снимает блокировку с помощью функции mtxUnlock(). Заблокировать
можно только разблокированный мьютекс. Поэтому вызов mtxLock() повлечет
приостановку выполнения потока вплоть до разблокировки мьютекса.

С помощью мьютексов можно синхронизировать доступ к общим объектам потоков.
Перед досупом к объекту каждый из потоков должен заблокировать мьютекс,
а после операции над объектом разблокировать его.

Управление мьютексами реализуется по схемам, заданным в новом стандарте
языка Си ISO/IEC 9899:2011 (см. заголовочный файл threads.h).

Интерфейс мьютексов упрощен по сравнению со стандартом:
ошибки при блокировке и разблокировке мьютекса не предполагаются.

Если операционная система не распознана, то мьютексы будут
"положительно пустыми": они всегда будут успешно создаваться, блокироваться
и разблокироваться, хотя за этими действиями не будет стоять никакого
функционала.

\typedef mt_mtx_t
\brief Мьютекс
*******************************************************************************
*/

#ifdef OS_WINDOWS
	#include <windows.h>
	typedef HANDLE mt_mtx_t;
#elif defined OS_UNIX
	#include <pthread.h>
	typedef pthread_mutex_t mt_mtx_t;
#else
	typedef void mt_mtx_t;
#endif

/*!	\brief Создание мьютекса

	Создается мьютекс mtx.
	\return Признак успеха.
	\post В случае успеха мьютекс корректен.
*/
bool_t mtMtxCreate(
	mt_mtx_t* mtx		/*!< [in] мьютекс */
);

/*!	\brief Корректный мьютекс?

	Проверяется корректность мьютекса mtx.
	\return Признак корректности.
*/
bool_t mtMtxIsValid(
	const mt_mtx_t* mtx	/*!< [in] мьютекс */
);

/*!	\brief Блокировка мьютекса

	Мьютекс mtx блокируется.
	\pre Мьютекс корректен.
*/
void mtMtxLock(
	mt_mtx_t* mtx		/*!< [in] мьютекс */
);

/*!	\brief Снятие блокировки мьютекса

	Мьютекс mtx разблокируется.
	\pre Мьютекс корректен.
*/
void mtMtxUnlock(
	mt_mtx_t* mtx		/*!< [in] мьютекс */
);

/*!	\brief Закрытие мьютекса

	Мьютекс mtx закрывается.
	\pre Мьютекс корректен.
*/
void mtMtxClose(
	mt_mtx_t* mtx		/*!< [in] мьютекс */
);

/*!
*******************************************************************************
\file mt.h

\section mt-thrd Управление потоками

Управление потоками реализуется по схемам, заданным в новом стандарте
языка Си ISO/IEC 9899:2011 (см. заголовочный файл threads.h).
*******************************************************************************
*/

/*!	\brief Приостановка потока

	Текущий поток приостанавливается на ms миллисекунд.
	\remark 1 секунда = 10^3 миллисекунд = 10^6 микросекунд = 10^9 наносекунд.
	\remark Если операционная система не распознана или операционная система
	не поддерживает многозадачность, то приостановки не будет.
*/
void mtSleep(
	uint32 ms		/*!< [in] число миллисекунд */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_MT_H */
