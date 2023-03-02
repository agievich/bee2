/* 
*******************************************************************************
\file stamp_pe.c
\brief Parsing of Windows PE Executables
\project bee2/cmd
\created 2011.10.18
\version 2016.05.24
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/* 
*******************************************************************************
Разбор PE-файлов ведется по документу
	Microsoft Portable Executable and Common Object File Format Specification
	Revision 8.2 – September 21, 2010

Контрольная характеристика размещается в ресурсе типа STAMP_TYPE 
с идентификатором STAMP_ID и представляет собой буфер памяти из STAMP_SIZE 
октетов. 

\warning Если ресурс STAMP_ID типа STAMP_TYPE задан для нескольких языков, 
то выбирается первый язык.
*******************************************************************************
*/

#include <windows.h>

#define STAMP_TYPE	256
#define STAMP_ID	1
#define STAMP_SIZE	32

/* 
*******************************************************************************
Вспомогательные макросы
*******************************************************************************
*/

#define _CHECK_PTR(ptr, end)\
	if ((const void*)((UINT8*)(ptr) + sizeof(*(ptr))) > (end))\
		return (DWORD)-1;
	
#define _CAST_PTR(T, ptr)\
	((ptr) == NULL ? NULL : (T*)(ptr))

#define _CAST_PTR_OFFSET(T, ptr, offset)\
	((ptr) == NULL ? NULL : (T*)((UINT8*)(ptr) + (offset)))

/* 
*******************************************************************************
Разбор PE-файла

Определяется смещение контрольной характеристики в образе image размера size.
\return Смещение или -1 в случае ошибки.
*******************************************************************************
*/

DWORD stampFindOffset(const UINT8* image, DWORD size)
{
	IMAGE_DOS_HEADER* pDOSHeader;
	IMAGE_NT_HEADERS* pNTHeader;
	IMAGE_FILE_HEADER* pFileHeader;
	IMAGE_RESOURCE_DIRECTORY* pSection;
	IMAGE_SECTION_HEADER* pSectionHeader;
	IMAGE_RESOURCE_DIRECTORY_ENTRY* pEntry;
	IMAGE_RESOURCE_DIRECTORY* pSubDir;
	IMAGE_RESOURCE_DATA_ENTRY* pData;
	DWORD offset;
	WORD pos;
	// окончание образа
	const void* image_end = image + size;
	if (size < STAMP_SIZE)
		return -1;
	// заголовки
	pDOSHeader = _CAST_PTR(IMAGE_DOS_HEADER, image);
	_CHECK_PTR(pDOSHeader, image_end);
	pNTHeader = _CAST_PTR_OFFSET(IMAGE_NT_HEADERS, pDOSHeader, 
		pDOSHeader->e_lfanew);
	_CHECK_PTR(pNTHeader, image_end);
	pFileHeader = _CAST_PTR(IMAGE_FILE_HEADER, &pNTHeader->FileHeader); 
	_CHECK_PTR(pFileHeader, image_end);
	// поиск секции ресурсов
	pSection = NULL;
	pSectionHeader = _CAST_PTR_OFFSET(IMAGE_SECTION_HEADER, 
		&pNTHeader->OptionalHeader, pFileHeader->SizeOfOptionalHeader);
	pos = 0;
	for (; pos < pFileHeader->NumberOfSections; ++pos, ++pSectionHeader)
	{
		_CHECK_PTR(pSectionHeader, image_end);
		if (strcmp((char*)&pSectionHeader->Name[0], ".rsrc") == 0)
		{
			pSection = _CAST_PTR_OFFSET(IMAGE_RESOURCE_DIRECTORY, image, 
				pSectionHeader->PointerToRawData);
			break;
		}
	}
	if (pSection == NULL)
		return -1;
	_CHECK_PTR(pSection, image_end);
	// поиск ресурсов типа STAMP_TYPE
	pEntry = _CAST_PTR_OFFSET(IMAGE_RESOURCE_DIRECTORY_ENTRY, pSection, 
		sizeof(IMAGE_RESOURCE_DIRECTORY));
	pos = pSection->NumberOfNamedEntries + pSection->NumberOfIdEntries;
	for (; pos--; ++pEntry)
	{
		_CHECK_PTR(pEntry, image_end);
		if (pEntry->DataIsDirectory && pEntry->Name == STAMP_TYPE)
			break;
	}
	if (pos == (WORD)-1)
		return -1;
	_CHECK_PTR(pEntry, image_end);
	// поиск ресурса с идентификатором STAMP_ID
	pSubDir = _CAST_PTR_OFFSET(IMAGE_RESOURCE_DIRECTORY, pSection,
		pEntry->OffsetToDirectory);
	_CHECK_PTR(pSubDir, image_end);
	pEntry = _CAST_PTR_OFFSET(IMAGE_RESOURCE_DIRECTORY_ENTRY, pSubDir,
		sizeof(IMAGE_RESOURCE_DIRECTORY));
	pos = pSubDir->NumberOfNamedEntries + pSubDir->NumberOfIdEntries;
	for (; pos--; ++pEntry)
	{
		_CHECK_PTR(pEntry, image_end);
		if (pEntry->DataIsDirectory && pEntry->Name == STAMP_ID)
			break;
	}
	if (pos == (WORD)-1)
		return -1;
	_CHECK_PTR(pEntry, image_end);
	// выбираем первый язык для ресурса
	pSubDir = _CAST_PTR_OFFSET(IMAGE_RESOURCE_DIRECTORY, pSection,
		pEntry->OffsetToDirectory);
	_CHECK_PTR(pSubDir, image_end);
	if (pSubDir->NumberOfIdEntries + pSubDir->NumberOfNamedEntries == 0)
		return -1;
	pEntry = _CAST_PTR_OFFSET(IMAGE_RESOURCE_DIRECTORY_ENTRY, pSubDir,
		sizeof(IMAGE_RESOURCE_DIRECTORY));
	_CHECK_PTR(pEntry, image_end);
	if (pEntry->DataIsDirectory)
		return -1;
	// выбираем данные
	pData = _CAST_PTR_OFFSET(IMAGE_RESOURCE_DATA_ENTRY, pSection,
		pEntry->OffsetToData);
	_CHECK_PTR(pData, image_end);
	if (pData->Size != STAMP_SIZE)
		return -1;
	// смещение
	offset = pData->OffsetToData;
	// подправка смещения
	offset -= pSectionHeader->VirtualAddress;
	offset += pSectionHeader->PointerToRawData;
	if (offset >= size - 32)
		return -1;
	// все нормально
	return offset;
}
