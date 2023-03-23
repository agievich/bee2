/*
*******************************************************************************
\file blob_test.c
\brief Tests for blob functions
\project bee2/test
\created 2023.03.21
\version 2023.03.23
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
	// wipe / close
	blobWipe(b2);
	blobClose(b2);
	blobClose(b1);
	return TRUE;
}
