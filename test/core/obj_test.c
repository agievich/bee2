/*
*******************************************************************************
\file obj_test.c
\brief Tests for compound objects
\project bee2/test
\created 2013.04.16
\version 2025.04.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/obj.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

struct obj_test1_t
{
	obj_hdr_t hdr;
	octet* p1;
	word* p2;
	octet a1[12];
	word a2[12];
};

struct obj_test2_t
{
	obj_hdr_t hdr;
	struct obj_test1_t* p1;
	octet* p2;
	octet a2[123];
};

bool_t objTest()
{
	octet buf[1024];
	struct obj_test1_t obj1[1];
	struct obj_test2_t obj2[1];
	void* t;
	// настроить obj1
	obj1->hdr.keep = sizeof(struct obj_test1_t);
	obj1->hdr.p_count = 2;
	obj1->hdr.o_count = 0;
	obj1->p1 = obj1->a1;
	obj1->p2 = obj1->a2;
	memSet(obj1->a1, 0x11, sizeof(obj1->a1));
	memSet(obj1->a2, 0x12, sizeof(obj1->a2));
	// настроить obj2
	obj2->hdr.keep = sizeof(struct obj_test2_t);
	obj2->hdr.p_count = 2;
	obj2->hdr.o_count = 1;
	obj2->p1 = obj1;
	obj2->p2 = obj2->a2;
	memSet(obj2->a2, 0x22, sizeof(obj2->a2));
	// подготовить буфер
	if (sizeof(buf) < objKeep(obj1) + 2 * objKeep(obj2))
		return FALSE;
	memSetZero(buf, sizeof(buf));
	// копировать obj2 в buf
	objCopy(buf, obj2);
	// присоединить obj1 к buf
	objAppend(buf, obj1, 0);
	// получить встроенный объект
	t = objPtr(buf, 0, void);
	// проверить
	if (memCmp(objPtr(t, 0, void), obj1->a1, sizeof(obj1->a1)) != 0 ||
		memCmp(objPtr(t, 1, void), obj1->a2, sizeof(obj1->a2)) != 0 ||
		memCmp(objPtr(buf, 1, void), obj2->a2, sizeof(obj2->a2)))
		return FALSE;
	// присоединить buf к buf
	objAppend(buf, buf, 0);
	// получить встроенный объект
	t = objPtr(buf, 0, void);
	// проверить
	if (memCmp(objPtr(t, 1, void), obj2->a2, sizeof(obj2->a2)) != 0)
		return FALSE;
	// все нормально
	return TRUE;
}
