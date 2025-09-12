/*
*******************************************************************************
\file blob.c
\brief Blobs
\project bee2 [cryptographic library]
\created 2012.04.01
\version 2025.09.12
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdarg.h>
#include "bee2/core/blob.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Создание / изменение размера

В куче выделяется память под указатель ptr. Память выделяется страницами.

Первые sizeof(mem_align_t) октетов по адресу ptr --- заголовок блоба,
следующие за заголовком октеты --- собственно блоб. В заголовке указывается 
длина блоба. Длина заголовка выбрана так, чтобы блоб был выровнен на границу
фундаментального блока.

\todo Обеспечить защиту памяти блоба от утечек.
\todo Полноценная проверка корректности блоба.
*******************************************************************************
*/

// память для блобов выделяется страницами
#define BLOB_PAGE_SIZE 1024

// требуется страниц
#define blobPageCount(size)\
	(((size) + sizeof(mem_align_t) + BLOB_PAGE_SIZE - 1) / BLOB_PAGE_SIZE)

// требуется памяти на страницах
#define blobActualSize(size)\
	(blobPageCount(size) * BLOB_PAGE_SIZE)

// заголовок блоба
#define blobHdrOf(blob) ((mem_align_t*)(blob) - 1)

// heap-указатель блоба
#define blobPtrOf(blob) ((void*)blobHdrOf(blob))

// размер блоба
#define blobSizeOf(blob) (blobHdrOf(blob)->s)

// страничный размер блоба
#define blobActualSizeOf(blob) (blobActualSize(blobSizeOf(blob)))

// блоб по heap-указателю
#define blobValueOf(ptr) ((blob_t)((mem_align_t*)(ptr) + 1))

blob_t blobCreate(size_t size)
{
	void* ptr;
	if (size == 0)
		return 0;
	ptr = memAlloc(blobActualSize(size));
	if (ptr == 0)
		return 0;
	ASSERT(memIsAligned(ptr, sizeof(mem_align_t)));
	((mem_align_t*)ptr)->s = size;
	memSetZero(blobValueOf(ptr), size);
	return blobValueOf(ptr);
}

blob_t blobResize(blob_t blob, size_t size)
{
	size_t old_size;
	void* ptr;
	// pre
	ASSERT(blobIsValid(blob));
	// создать блоб
	if (blob == 0)
		return blobCreate(size);
	// освободить блоб
	if (size == 0)
	{
		blobClose(blob);
		return 0;
	}
	// сохранить размер
	old_size = blobSizeOf(blob);
	// перераспределить память?
	ptr = blobPtrOf(blob);
	if (blobActualSizeOf(blob) != blobActualSize(size))
	{
		ptr = memRealloc(ptr, blobActualSize(size));
		if (ptr == 0)
			return 0;
		ASSERT(memIsAligned(ptr, sizeof(mem_align_t)));
	}
	// настроить и возвратить блоб
	((mem_align_t*)ptr)->s = size;
	blob = blobValueOf(ptr);
	if (size > old_size)
		memSetZero((octet*)blob + old_size, size - old_size);
	return blob;
}

/*
*******************************************************************************
Создание с разметкой памяти
*******************************************************************************
*/

extern size_t memSliceSizeArgs(size_t c1, va_list args);
extern void memSliceArgs(const void* buf, size_t c1, va_list args);

blob_t blobCreate2(size_t c1, ...)
{
	va_list args;
	size_t size;
	blob_t blob;
	// определить требуемый размер блоба
	va_start(args, c1);
	size = memSliceSizeArgs(c1, args);
	va_end(args);
	// создать блоб
	blob = blobCreate(size);
	// разметить память
	if (blob)
	{
		va_start(args, c1);
		memSliceArgs(blob, c1, args);
		va_end(args);
	}
	return blob;
}

/*
*******************************************************************************
Другие функции
*******************************************************************************
*/

bool_t blobIsValid(const blob_t blob)
{
	return blob == 0 || memIsValid(blobPtrOf(blob), blobActualSizeOf(blob));
}

void blobWipe(blob_t blob)
{
	ASSERT(blobIsValid(blob));
	if (blob != 0)
		memWipe(blob, blobSizeOf(blob));
}

void blobClose(blob_t blob)
{
	ASSERT(blobIsValid(blob));
	if (blob)
	{
		memWipe(blobPtrOf(blob), blobActualSizeOf(blob));
		memFree(blobPtrOf(blob));
	}
}

size_t blobSize(const blob_t blob)
{
	ASSERT(blobIsValid(blob));
	return blob == 0 ? 0 : blobSizeOf(blob);
}

blob_t blobCopy(blob_t dest, const blob_t src)
{
	size_t size;
	ASSERT(blobIsValid(dest) && blobIsValid(src));
	if (dest == src)
		return dest;
	size = blobSize(src);
	dest = blobResize(dest, size);
	if (dest)
		memCopy(dest, src, size);
	return dest;
}

bool_t blobEq(const blob_t blob1, const blob_t blob2)
{
	ASSERT(blobIsValid(blob1) && blobIsValid(blob2));
	return blobSize(blob1) == blobSize(blob2) &&
		memEq(blob1, blob2, blobSize(blob1));
}

int blobCmp(const blob_t blob1, const blob_t blob2)
{
	ASSERT(blobIsValid(blob1) && blobIsValid(blob2));
	if (blobSize(blob1) != blobSize(blob2))
		return blobSize(blob1) < blobSize(blob2) ? - 1 : 1;
	return memCmp(blob1, blob2, blobSize(blob1));
}
