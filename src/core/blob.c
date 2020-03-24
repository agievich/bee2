/*
*******************************************************************************
\file blob.c
\brief Blobs
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.01
\version 2015.12.09
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Блоб: реализация

В куче выделяется память под указатель ptr. Память выделяется страницами.

Первые sizeof(size_t) октетов по адресу ptr --- размер блоба,
следующие октеты --- собственно блоб.

\todo Обеспечить защиту памяти блоба от утечек.

\todo Полноценная проверка корректности блоба.
*******************************************************************************
*/

// память для блобов выделяется страницами
#define BLOB_PAGE_SIZE 1024

// требуется страниц
#define blobPageCount(size)\
	(((size) + sizeof(size_t) + BLOB_PAGE_SIZE - 1) / BLOB_PAGE_SIZE)

// требуется памяти на страницах
#define blobActualSize(size)\
	(blobPageCount(size) * BLOB_PAGE_SIZE)

// heap-указатель для блоба
#define blobPtrOf(blob) ((size_t*)blob - 1)

// размер блоба
#define blobSizeOf(blob) (*blobPtrOf(blob))

// страничный размер блоба
#define blobActualSizeOf(blob) (blobActualSize(blobSizeOf(blob)))

// блоб для heap-указателя
#define blobValueOf(ptr) ((blob_t)((size_t*)ptr + 1))

blob_t blobCreate(size_t size)
{
	size_t* ptr;
	if (size == 0)
		return 0;
	ptr = (size_t*)memAlloc(blobActualSize(size));
	if (ptr == 0)
		return 0;
	*ptr = size;
	memSetZero(blobValueOf(ptr), size);
	return blobValueOf(ptr);
}

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

blob_t blobResize(blob_t blob, size_t size)
{
	size_t old_size;
	size_t* ptr;
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
		ptr = (size_t*)memRealloc(ptr, blobActualSize(size));
		if (ptr == 0)
			return 0;
	}
	// настроить и возвратить блоб
	*ptr = size;
	blob = blobValueOf(ptr);
	if (size > old_size)
		memSetZero((octet*)blob + old_size, size - old_size);
	return blob;
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
	size = blobSizeOf(src);
	dest = blobResize(dest, size);
	if (dest)
		memCopy(dest, src, size);
	return dest;
}

bool_t blobEq(const blob_t blob1, const blob_t blob2)
{
	ASSERT(blobIsValid(blob1) && blobIsValid(blob2));
	return blobSizeOf(blob1) == blobSizeOf(blob2) &&
		memEq(blob1, blob2, blobSizeOf(blob1));
}

int blobCmp(const blob_t blob1, const blob_t blob2)
{
	ASSERT(blobIsValid(blob1) && blobIsValid(blob2));
	if (blobSizeOf(blob1) != blobSizeOf(blob2))
		return blobSizeOf(blob1) < blobSizeOf(blob2) ? - 1 : 1;
	return memCmp(blob1, blob2, blobSizeOf(blob1));
}
