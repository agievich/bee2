/*
*******************************************************************************
\file blob_test.c
\brief Tests for blob functions
\project bee2/test
\created 2023.03.21
\version 2025.08.27
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/mem.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t blobTest()
{
	blob_t b1 = 0;
	blob_t b2 = 0;
	blob_t b3 = 0;
	// create / resize
	b1 = blobCreate(123);		
	b2 = blobResize(b2, 120);
	if (!blobIsValid(b1) || !blobIsValid(b2))
	{
		blobClose(b2), blobClose(b1);
		return FALSE;
	}
	// copy / cmp
	memSet(b1, 0x36, blobSize(b1));
	b2 = blobCopy(b2, b1);
	if (!blobIsValid(b2) || 
		blobSize(b1) != blobSize(b2) ||
		!memEq(b1, b2, blobSize(b1)) ||
		!blobEq(b1, b2))
	{
		blobClose(b2), blobClose(b1);
		return FALSE;
	}
	memSet(b2, 0x5C, blobSize(b2));
	if (blobCmp(b1, b2) >= 0)
	{
		blobClose(b2), blobClose(b1);
		return FALSE;
	}
	b2 = blobResize(b2, blobSize(b2) - 100);
	if (blobCmp(b1, b2) <= 0)
	{
		blobClose(b2), blobClose(b1);
		return FALSE;
	}
	// slice
	{
		void* p;
		void* p1;
		void* p2;
		b3 = blobSlice(0,
			(size_t)11, &p,
			(size_t)10, &p1,
			(size_t)32 | SIZE_HI, &p2, 
			SIZE_MAX);
		if (!b3 || 
			!memIsAligned(b3, sizeof(mem_align_t)) ||
			!memIsAligned(p1, sizeof(mem_align_t)) ||
			b3 != p || p == p1 || p1 != p2)
		{
			blobClose(b3);
			return FALSE;
		}
		b3 = blobSlice(b3,
			(size_t)127, &p,
			(size_t)11, &p1,
			SIZE_MAX);
		if (!b3 || 
			!memIsAligned(b3, sizeof(mem_align_t)) ||
			!memIsAligned(p1, sizeof(mem_align_t)) ||
			b3 != p || p1 == p)
		{
			blobClose(b3);
			return FALSE;
		}
	}
	// wipe / close
	blobClose(b3);
	blobWipe(b2);
	blobClose(b2);
	blobClose(b1);
	return TRUE;
}
