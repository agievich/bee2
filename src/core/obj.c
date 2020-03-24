/*
*******************************************************************************
\file obj.c
\brief Compound objects
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.04.14
\version 2015.05.22
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/obj.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Внутренние макросы
*******************************************************************************
*/

#define objHdr(obj)\
	((obj_hdr_t*)obj)

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

bool_t objIsOperable2(const void* obj)
{
	return memIsValid(obj, sizeof(obj_hdr_t)) &&
		memIsValid(obj, objKeep(obj)) &&
		objOCount(obj) <= objPCount(obj) &&
		sizeof(obj_hdr_t) + sizeof(void*) * objPCount(obj) <= objKeep(obj);
}

bool_t objIsOperable(const void* obj)
{
	size_t i;
	// проверить сам объект
	if (!objIsOperable2(obj))
		return FALSE;
	// проверить ссылочные объекты
	for (i = 0; i < objOCount(obj); ++i)
		if (!objIsOperable(objCPtr(obj, i, void)))
			return FALSE;
	// все нормально
	return TRUE;
}

/*
*******************************************************************************
Копирование
*******************************************************************************
*/

static void objShiftPtrs(void* obj, ptrdiff_t diff)
{
	size_t i;
	// просмотреть объекты
	for (i = 0; i < objOCount(obj); ++i)
		// вложенный объект?
		if ((octet*)obj <= objPtr(obj, i, octet) + diff && 
			objPtr(obj, i, octet) + diff < objEnd(obj, octet))
		{
			objShiftPtrs(objPtr(obj, i, void), diff);
			objPtr(obj, i, octet) += diff;
		}
	// просмотреть оставшиеся указатели
	for (; i < objPCount(obj); ++i)
		// вложенный указатель?
		if ((octet*)obj <= objPtr(obj, i, octet) + diff && 
			objPtr(obj, i, octet) + diff < objEnd(obj, octet))
			objPtr(obj, i, octet) += diff;
}

void objCopy(void* dest, const void* src)
{
	ASSERT(objIsOperable(src));
	ASSERT(memIsValid(dest, objKeep(src)));
	// скопировать данные
	memMove(dest, src, objKeep(src));
	// сдвинуть указатели
	objShiftPtrs(dest, (const octet*)dest - (const octet*)src);
}

void objAppend(void* dest, const void* src, size_t i)
{
	size_t t;
	// pre
	ASSERT(objIsOperable(src));
	ASSERT(objIsOperable(dest));
	ASSERT(memIsValid(objEnd(dest, void), objKeep(src)));
	ASSERT(i < objOCount(dest));
	// запомнить размер src
	t = objKeep(src);
	// скопировать src в конец dest
	objCopy(objEnd(dest, void), src);
	// установить ссылку на конец dest
	objPtr(dest, i, void) = objEnd(dest, void);
	// расширить dest
	objHdr(dest)->keep += t;
}
