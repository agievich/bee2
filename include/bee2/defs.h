/*
*******************************************************************************
\file defs.h
\brief Basic definitions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.01
\version 2019.06.18
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file defs.h
\brief Базовые определения
*******************************************************************************
*/

#ifndef __BEE2_DEFS_H
#define __BEE2_DEFS_H

#include <limits.h>
#include <stddef.h>

#ifndef SIZE_MAX
	#include <stdint.h>
#endif

/*!
*******************************************************************************
\file defs.h

\section defs-types Типы данных

\pre Длина машинного слова в битах (B_PER_W) равняется 16, 32 или 64.

\pre Длина слова типа size_t в битах не менее 16.

\pre Обязательно поддерживаются типы u16, u32.

Могут поддерживаться типы u64, u128.

\remark Поддержка B_PER_W == 16 полезна для организации тестирования
арифметики больших чисел и арифметики многочленов: как правило, ошибки в
функциях арифметики возникают с вероятностями, близкими к 1 / 2^B_PER_W.

\remark При разборе платформ для определения порядка октетов использован код
Брайана Гладмана (Brian Gladman, http://www.gladman.me.uk/). Дополнительная 
платформа EMSCRIPTEN (https://emscripten.org) является виртуальной, на ней 
выполняется компиляция в asm.js. 

\section defs-arrays Массивы

Массив элементов типа T, как правило, передается в функцию в виде пары
(указатель in на элементы массива, длина массива in_len). Здесь in имеет тип
const T*, а in_len -- тип size_t. При документировании массива используется
запись [in_len]in. При T == void запись имеет такой же смысл, как при
T == octet.

Если длина in_len заранее известна, то она может не передаваться в функцию.

Массив элементов типа T заранее известного размера возвращается из функций
через буфер, на который ссылается указатель out типа T*.

Если длина массива заранее неизвестна, то для его возврата используется пара
(указатель out, размер out_len), где out_len имеет тип size_t*.
Если обратиться к функции с нулевым out, то по адресу out_len будет
размещена длина возвращаемого массива. При обращении с ненулевым out по
адресу out_len должно быть указано число элементов типа T, зарезервированных
в буфере out. В результате выполнения функции число по адресу out_len 
корректируется -- устанавливается равным актуальному числу элементов,
записанных в массив out. Размера буфера может контролироваться предусловиями.
О недостаточности размера функции может сообщать через коды возврата.

При документировании описанной логики возврата массива используется
запись [?out_len]out. При T == void запись имеет такой же смысл,
как при T == octet.

\section defs-seqs Последовательности вызовов

Ограничения на последовательность вызовов определенных функций документируются
с помощью знаков "<", "*" и "<<".

Запись "f1() < f2()" означает, что функция f2() должна вызываться после f1().

Запись "f1() < [f2()] < f3()" означает, что функция f2() должна вызываться 
после f1(), f3() после f2(), и вызов f2() может быть пропущен.

Запись "f()*" означает, что функция f() может вызываться последовательно
произвольное число раз.

Запись "f1()* < f2()" означает, что несколько вызовов f1() завершаются
вызовом f2().

Запись "(f1()* < f2())*" означает, что каскад "несколько раз f1(), затем f2()"
может повторяться произвольное число раз. Например, возможность
инкрементального хэширования, при котором можно рассчитывать хэш-значение
все более длинного фрагмента, обозначается следующим образом:
\code
(hash_step()* < hash_get())*.
\endcode

Знак "<<" используется при документировании протоколов. Запись "f1() << f2()"
означает, что перед вызовом функции f2() стороной A сторона B должна вызвать
функцию f1() и переслать результаты ее работы стороне B.
*******************************************************************************
*/

/*!
*******************************************************************************
\def OCTET_ORDER
\brief Порядок октетов в машинном слове

\def LITTLE_ENDIAN
\brief Порядок "от младших к старшим"

\def BIG_ENDIAN
\brief Порядок "от старших к младшим"
*******************************************************************************
*/

#ifndef LITTLE_ENDIAN
	#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
	#define BIG_ENDIAN 4321
#endif

#if defined(__M_IX86) || defined(_X86_) || defined(i386) ||\
	defined(__i386__) || defined(_M_I86)  || defined(_M_IX86) ||\
	defined(_M_IA64) || defined(__ia64__) || defined(_M_X64) ||\
	defined(_M_AMD64) || defined(__amd64__) || defined(__amd64) ||\
	defined(__x86_64__) || defined(_M_ALPHA) || defined(__alpha__) ||\
	defined(__alpha) || defined(__arm__) || defined(__MIPS__) ||\
	defined(__mips__) || defined(__mips) || defined(__OS2__) ||\
	defined(sun386) || defined(__TURBOC__) || defined(vax) || defined(vms) ||\
	defined(VMS) || defined(__VMS) || defined(__EMSCRIPTEN__) ||\
	defined(__aarch64__)
	#define OCTET_ORDER LITTLE_ENDIAN
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__) ||\
	defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) ||\
	defined(AMIGA) || defined(applec) || defined(__AS400__) ||\
	defined(_CRAY) || defined(__hppa) || defined(__hp9000) ||\
	defined(ibm370) || defined(mc68000) || defined(m68k) ||\
	defined(__MRC__) || defined(__MVS__) || defined(__MWERKS__) ||\
	defined(sparc) || defined(__sparc) || defined(SYMANTEC_C) ||\
	defined(__VOS__) || defined(__TIGCC__) || defined(__TANDEM) ||\
	defined(THINK_C) || defined(__VMCMS__) || defined(_AIX)
	#define OCTET_ORDER BIG_ENDIAN
#else
	#error "Platform undefined"
#endif

/*!
*******************************************************************************
\def OS_WIN
\brief Операционная система линейки Windows

\def OS_UNIX
\brief Операционная система линейки Unix
\remark Включает линейки Linux и MAC OS X

\def OS_LINUX
\brief Операционная система линейки Linux

\def OS_APPLE
\brief Операционная система линеек OS X / iOS
*******************************************************************************
*/

#if defined(_WIN32) || defined(_WIN64) || defined(_WINNT) ||\
	defined(__WIN32__) || defined(__WIN64__)  || defined(__WINNT__)
	#define OS_WIN
	#undef OS_UNIX
	#undef OS_LINUX
	#undef OS_APPLE
#elif defined(unix) || defined(_unix_) || defined(__unix__) ||\
	defined(__APPLE__)
	#undef OS_WIN
	#define OS_UNIX
	#if defined(__unix__)
		#define OS_LINUX
		#undef OS_APPLE
	#elif defined(__APPLE__)
		#undef OS_LINUX
		#define OS_APPLE
	#endif
#else
	#undef OS_WIN
	#undef OS_UNIX
	#undef OS_LINUX
	#undef OS_APPLE
#endif

/*!
*******************************************************************************
\typedef octet
\brief Октет

\typedef u8
\brief 8-разрядное беззнаковое целое

\typedef i8
\brief 8-разрядное знаковое целое

\typedef u16
\brief 16-разрядное беззнаковое целое

\typedef i16
\brief 16-разрядное знаковое целое

\typedef u32
\brief 32-разрядное беззнаковое целое

\typedef i32
\brief 32-разрядное знаковое целое
*******************************************************************************
*/

#undef U8_SUPPORT
#undef U16_SUPPORT
#undef U32_SUPPORT
#undef U64_SUPPORT
#undef U128_SUPPORT

#if (UCHAR_MAX == 255)
	typedef unsigned char u8;
	typedef signed char i8;
	typedef u8 octet;
	#define U8_SUPPORT
#else
	#error "Unsupported char size"
#endif

#if (USHRT_MAX == 65535)
	typedef unsigned short u16;
	typedef signed short i16;
	#define U16_SUPPORT
#else
	#error "Unsupported short size"
#endif

#if (UINT_MAX == 65535u)
	#if (ULONG_MAX == 4294967295ul)
		typedef unsigned long u32;
		typedef signed long i32;
		#define U32_SUPPORT
	#else
		#error "Unsupported long size"
	#endif
#elif (UINT_MAX == 4294967295u)
	typedef unsigned int u32;
	typedef signed int i32;
	#define U32_SUPPORT
	#if (ULONG_MAX == 4294967295ul)
		#if !defined(ULLONG_MAX) || (ULLONG_MAX == 4294967295ull)
			#error "Unsupported int/long/long long configuration"
		#elif (ULLONG_MAX == 18446744073709551615ull)
			typedef unsigned long long u64;
			typedef signed long long i64;
			#define U64_SUPPORT
		#else
			#error "Unsupported int/long/long long configuration"
		#endif
	#elif (ULONG_MAX == 18446744073709551615ul)
		typedef unsigned long u64;
		typedef signed long i64;
		#define U64_SUPPORT
		#if defined(__GNUC__) && (__WORDSIZE == 64)
			typedef __int128 i128;
			typedef unsigned __int128 u128;
			#define U128_SUPPORT
		#endif
	#else
		#error "Unsupported int/long configuration"
	#endif
#elif (UINT_MAX == 18446744073709551615u)
	#if (ULONG_MAX == 18446744073709551615ul)
		#if !defined(ULLONG_MAX) || (ULLONG_MAX == 18446744073709551615ull)
			#error "Unsupported int/long/long long configuration"
		#elif (ULLONG_MAX == 340282366920938463463374607431768211455ull)
			typedef unsigned long long u128;
			typedef signed long long i128;
			#define U128_SUPPORT
		#else
			#error "Unsupported int/long/long long configuration"
		#endif
	#elif (ULONG_MAX == 340282366920938463463374607431768211455ul)
		typedef unsigned long u128;
		typedef signed long i128;
		#define U128_SUPPORT
	#else
		#error "Unsupported long size"
	#endif
#else
	#error "Unsupported int size"
#endif

#if !defined(U8_SUPPORT) || !defined(U16_SUPPORT) || !defined(U32_SUPPORT)
	#error "One of the base types is not supported"
#endif

/*!
*******************************************************************************
\def B_PER_W
\brief Число битов в машинном слове

\def O_PER_W
\brief Число октетов в машинном слове

\def B_PER_S
\brief Число битов в size_t

\def O_PER_S
\brief Число октетов в size_t

\typedef word
\brief Машинное слово

\typedef dword
\brief Двойное машинное слово
*******************************************************************************
*/

#if defined(__WORDSIZE)
	#if (__WORDSIZE == 16)
		#define B_PER_W 16
		typedef u16 word;
		typedef u32 dword;
	#elif (__WORDSIZE == 32)
		#define B_PER_W 32
		typedef u32 word;
		typedef u64 dword;
	#elif (__WORDSIZE == 64)
		#define B_PER_W 64
		typedef u64 word;
		typedef u128 dword;
	#else
		#error "Unsupported word size"
	#endif
#else
	#if (UINT_MAX == 65535u)
		#define B_PER_W 16
		typedef u16 word;
		typedef u32 dword;
	#elif (UINT_MAX == 4294967295u)
		#define B_PER_W 32
		typedef u32 word;
		typedef u64 dword;
	#elif (UINT_MAX == 18446744073709551615u)
		#define B_PER_W 64
		typedef u64 word;
		typedef u128 dword;
	#else
		#error "Unsupported word size"
	#endif
#endif

#if (B_PER_W != 16 && B_PER_W != 32 && B_PER_W != 64)
	#error "Unsupported word size"
#endif

#define O_PER_W (B_PER_W / 8)
#define O_PER_S (B_PER_S / 8)

#define SIZE_0 ((size_t)0)
#define SIZE_1 ((size_t)1)
#ifndef SIZE_MAX
	#define SIZE_MAX ((size_t)(SIZE_0 - SIZE_1))
#endif

#if (SIZE_MAX == 65535u)
	#define B_PER_S 16
#elif (SIZE_MAX == 4294967295u)
	#define B_PER_S 32
#elif (SIZE_MAX == 18446744073709551615u)
	#define B_PER_S 64
#else
	#error "Unsupported size_t size"
#endif

/*
*******************************************************************************
Макросы конвертации
*******************************************************************************
*/

/*!	\brief Число октетов для размещения nb битов */
#define O_OF_B(nb) (((nb) + 7) / 8)

/*!	\brief Число машинных слов для размещения nb битов */
#define W_OF_B(nb) (((nb) + B_PER_W - 1) / B_PER_W)

/*!	\brief Число битов для размещения no октетов */
#define B_OF_O(no) ((no) * 8)

/*!	\brief Число машинных слов для размещения no октетов */
#define W_OF_O(no) (((no) + O_PER_W - 1) / O_PER_W)

/*!	\brief Число октетов для размещения nw машинных слов */
#define O_OF_W(nw) ((nw) * O_PER_W)

/*!	\brief Число битов для размещения nw машинных слов */
#define B_OF_W(nw) ((nw) * B_PER_W)

/*
*******************************************************************************
Булевы данные
*******************************************************************************
*/

/*!	\brief Булев тип */
typedef int bool_t;

#ifndef TRUE
	#define TRUE ((bool_t)1)
#endif

#ifndef FALSE
	#define FALSE ((bool_t)0)
#endif

/*
*******************************************************************************
Ошибки
*******************************************************************************
*/

/*!	\brief Коды ошибок
	\remark Высокоуровневые функции возвращают значения типа err_t.
	Возврат ERR_OK означает, что функция завершена успешно. Код ERR_MAX
	зарезервирован для описания специальных особых ситуаций.
	Возврат других значений означает ошибку при выполнении функции.
*/
typedef u32 err_t;

/*!	\brief Код успешного завершения */
#define ERR_OK	((err_t)0)

/*!	\brief Максимальный код ошибки */
#define ERR_MAX	(ERR_OK - (err_t)1)

/*!
*******************************************************************************
\brief Невозможное событие

Событие, вероятность наступления которого <= 2^{-B_PER_IMPOSSIBLE}, считается 
невозможным.

\remark Э. Борель: "событие, вероятность которого ниже
10^{-50} \approx 2^{-166}, не произойдет никогда, сколько бы возможностей
ни представилось" [Probability and Life, 1962].
*******************************************************************************
*/

#define B_PER_IMPOSSIBLE 64

/*!
*******************************************************************************
\brief Интерфейс генерации

Функция интерфейса gen_i генерирует count октетов и записывает их в буфер buf.
При генерации может использоваться и изменяться вспомогательная память
(состояние) state.

Функция интерфейса gen_i интерпретируется как генератор с состоянием state.
Используются генераторы двух типов:
-	rng (random number generator): генераторы случайных или
	псевдослучайных чисел;
-	ang (arbitrary number generator): генераторы произвольных чисел,
	которые реализуют принцип "выбрать произвольным образом". Генерируемые
	числа (октеты) могут строиться по меткам времени, значениям монотонного
	счетчика, случайным или псевдослучайным числам. Числа могут использоваться
	в криптографических протоколах для построения синхропосылок, нонсов,
	затравочных значений (seed), "соли" (salt).
.
\pre Буфер buf корректен.
\pre Состояние state корректно.
\expect Состояние state поддерживается постоянным между последовательными
обращениями к функции.
\expect Октеты, формируемые генераторами rng, обладают минимальным
статистическим качеством: каждое значение встречается с примерно равной
частотой.
\expect Октеты, формируемые генераторами ang, почти не повторяются
(повторяются только с пренебрежимо малыми вероятностями или только
на недостижимо больших интервалах наблюдения).
\remark Функция интерфейса gen_i всегда генерирует все запрашиваемые октеты.
Ошибки при генерации не предусмотрены.
*******************************************************************************
*/

typedef void (*gen_i)(
	void* buf,			/*!< [out] случайные числа */
	size_t count,		/*!< [in] число октетов */
	void* state			/*!< [in/out] cостояние */
);

/*!
*******************************************************************************
\brief Интерфейс чтения

Функция интерфейса read_i читает данные из файла file в буфер [count]buf.
По адресу read возвращается число прочитанных октетов.
\pre Буфер buf корректен.
\pre Указатель read корректен.
\pre Файл file корректен.
\return ERR_OK, если прочитано определенное число октетов (возможно меньшее
count и возможно нулевое) и конец файла не достигнут, ERR_MAX, если прочитано
меньше чем count октетов и достигнут конец файла, или другой код ошибки.
\remark Файл -- это произвольный массив или поток данных на произвольном
устройстве. В качестве файла может выступать обычный дисковый файл, сетевое
соединение, источник случайности и т.д.
\remark Для файлов некоторых устройств ошибкой не считается ситуация,
когда прочитано меньше чем count октетов. Данная ситуация может быть связана
с ожиданием данных в канале связи.
\remark Передавая count == 0, можно проверить наличие файла.
*******************************************************************************
*/

typedef err_t (*read_i)(
	size_t* read,		/*!< [out] число прочитанных октетов */
	void* buf,			/*!< [out] прочитанные данные */
	size_t count,		/*!< [in] длина buf в октетах */
	void* file			/*!< [in/out] описание файла */
);

/*!
*******************************************************************************
\brief Интерфейс записи

Функция интерфейса write_i записывает буфер [count]buf в файл file.
По адресу written возвращается число записанных в файл октетов.
\pre Указатель written корректен.
\pre Буфер buf корректен.
\pre Файл file корректен.
\return ERR_OK, если записаны все октеты buf, и код ошибки в противном случае.
*******************************************************************************
*/

typedef err_t (*write_i)(
	size_t* written,	/*!< [out] число записанных октетов */
	const void* buf,	/*!< [in] записываемые данные */
	size_t count,		/*!< [in] длина buf в октетах */
	void* file			/*!< [in/out] описание файла */
);

#endif /* __BEE2_DEFS_H */
