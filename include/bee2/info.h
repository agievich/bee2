/*
*******************************************************************************
\file info.h
\brief Common info
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.01
\version 2016.07.07
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices at the end of this file.
*******************************************************************************
*/

/*!
*******************************************************************************
\file info.h
\brief Общая информация
*******************************************************************************
*/


#ifndef __BEE2_INFO
#define __BEE2_INFO

#define BEE2_NAME				"Bee2"
#define BEE2_VERSION_MAJOR		"2"
#define BEE2_VERSION_MINOR 		"1"
#define BEE2_VERSION_PATCH		"0"

#define BEE2_VERSION\
		BEE2_VERSION_MAJOR "." BEE2_VERSION_MINOR "." BEE2_VERSION_PATCH

#define BEE2_VERSION_NUM\
		2, 1, 0

/*!
*******************************************************************************
\mainpage Библиотека Bee2

\version 2.1.0

\section toc Содержание

-#	\ref descr
-#	\ref make
-#	\ref license

\section descr Описание

Библиотека Bee2 реализует алгоритмы и протоколы криптографических 
стандартов Республики Беларусь (СТБ 34.101.31, 45, 47, 60, 66).

Библиотека написана на языке Си, без ассемблерных вставок и поэтому 
компилируется практически на любой аппаратно-программной платформе. 

В низкоуровневые функции передаются указатели на память, в которой 
размещаются состояния алгоритмов / протоколов и локальные переменные. 
Память может содержать критические объекты (ключи), и поэтому взята под 
контроль. Память выделяется только в высокоуровневых функциях и только 
одним блоком: в нем размещаются и состояние, и стек всех подчиненных 
функций. Блок может защищаться от попадания в файл подкачки. При 
завершении работы с блоком его очистка выполняется так, что не может 
показаться бесполезной оптимизатору, и он ее не исключит из кода 
библиотеки. 

В Bee2 реализуется программа полной регуляризации. Регуляризация состоит в 
отказе от ветвлений, условия которых определяются критическими данными. 
Отказ от ветвлений блокирует атаки, основанные на замерах времени или 
питания. 

Выделены предусловия -- они названы ожиданиями, -- проверить которые 
вычислительно трудно: простота числа, неприводимость многочлена, 
корректность эллиптической кривой. Функции не полагаются на безусловное 
выполнение ожиданий и корректно работают даже при их нарушении.

Высокоуровневые функции объединяются в связки. Функции связки используют 
общее состояние и стек, они похожи на методы класса C++. В необходимых 
случаях объявляются ожидания относительно последовательности вызовов 
функций связки. 

Большое внимание уделено выбору оптимальных арифметических алгоритмов. 
Разработаны новые алгоритмы арифметики больших чисел. 

Работа с алгебраическими структурами реализована через достаточно общие 
интерфейсы. Например, интерфейс qr описывает работу с абстрактным кольцом 
вычетом по модулю его идеала.  Интерфейс qr инстанциируется многими 
способами: zm -- кольцо вычетов целых чисел, pp -- кольцо многочленов, gfp -- 
простое поле из p > 2 элементов, gf2 -- поле характеристики 2. 

\section make Сборка

Подготовка конфигурационных файлов:

\verbatim
mkdir build
cd build
cmake [-DCMAKE_BUILD_TYPE={Release|Debug|Coverage|ASan|ASanDbg|MemSan|MemSanDbg|Check}]\
      [-DBUILD_FAST=ON] ..
\endverbatim

Конфигурации:
   
# Release -- окончательная (по умолчанию);
# Debug -- отладочная;
# Coverage -- со средствами мониторинга покрытия;
# ASan, ASanDbg -- со средствами проверки адресов (AddressSanitizer);
# MemSan, MemSanDbg -- со средствами проверки памяти (MemorySanitizer);
# Check -- строгие правила компиляции.

Опция BUILD_FAST (по умолчанию отключена) переключает между безопасными 
(constant-time) и быстрыми (non-constant-time) редакциями функций.

Компиляция и линковка:

\verbatim
make
\endverbatim

Тестирование:

\verbatim
make test
\endverbatim

Установка:

\verbatim
make install
\endverbatim

\section license Лицензия

Библиотека распространяется на условиях GNU General Public License версии 3
(GNU GPL v3). 

\verbatim

Bee2: a cryptographic library
Copyright (c) 2012-2015, Bee2 authors

This file is part of Bee2. Bee2 is legal property of its developers,
whose names are not listed here. Please refer to source files for contact 
information. 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

\endverbatim
*******************************************************************************
*/

#endif // __BEE2_INFO
