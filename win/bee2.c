/*
*******************************************************************************
\file bee2.c
\brief Bee2 DLL entry points
*******************************************************************************
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.02.25
\version 2017.01.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <bee2/info.h>
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/util.h>
#include <bee2/core/stack.h>
#include <bee2/crypto/belt.h>

/* 
*******************************************************************************
Прочитать / определить контрольную характеристику
*******************************************************************************
*/

#include "..\apps\stamp\stamp_pe.c"

static err_t beeReadAndCalcStamp(octet stampRead[STAMP_SIZE], 
	octet stampCalc[STAMP_SIZE])
{
	err_t code = ERR_OK;
	char name[MAX_PATH];
	HANDLE hFile, hMapping;
	DWORD size, offset;
	octet* image;
	void* hash_state;
	// имя модуля
	if (!GetModuleFileNameA(GetModuleHandleA("bee2.dll"), name, sizeof(name)))
		return ERR_SYS;
	// открыть файл
	hFile = CreateFileA(name, GENERIC_READ,	0, NULL, OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return ERR_FILE_OPEN;
	// длина файла
	size = SetFilePointer(hFile, 0, NULL, FILE_END);
	if (size == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return ERR_SYS;
	}
	// проецировать файл в память
	hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == NULL)
	{
		CloseHandle(hFile);
		return ERR_SYS;
	}
	// отобразить файл в память
	image = (octet*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (image == NULL)
	{
		CloseHandle(hMapping), CloseHandle(hFile);
		return ERR_SYS;
	}
	// найти смещение контрольной характеристики
	offset = stampFindOffset(image, size);
	if (offset == (DWORD)-1)
	{
		UnmapViewOfFile(image), CloseHandle(hMapping), CloseHandle(hFile);
		return ERR_BAD_FORMAT;
	}
	// сохранить характеристику
	memCopy(stampRead, image + offset, STAMP_SIZE);
	// вычислить характеристику
	CASSERT(STAMP_SIZE >= 32);
	memSetZero(stampCalc, STAMP_SIZE);
	hash_state = blobCreate(beltHash_keep());
	if (hash_state)
	{
		// хэшировать
		beltHashStart(hash_state);
		beltHashStepH(image, offset, hash_state);
		beltHashStepH(image + offset + STAMP_SIZE, 
			size - offset - STAMP_SIZE, hash_state);
		beltHashStepG(stampCalc, hash_state);
		blobClose(hash_state);
	}
	else
		code = ERR_OUTOFMEMORY;
	// очистка и выход
	UnmapViewOfFile(image);
	CloseHandle(hMapping);
	CloseHandle(hFile);
	return code;
}

/* 
*******************************************************************************
Контроль целостности
*******************************************************************************
*/

static err_t beeSelfCheck()
{
	// характеристики
	octet stampRead[STAMP_SIZE], stampCalc[STAMP_SIZE];
	err_t code = beeReadAndCalcStamp(stampRead, stampCalc);
	ERR_CALL_CHECK(code);
	// сравнить
	return memEq(stampRead, stampCalc, STAMP_SIZE) ? ERR_OK : ERR_BAD_HASH;
}

/* 
*******************************************************************************
Печать форматированных данных в конец строки
*******************************************************************************
*/

static err_t beeSprintf(blob_t* str, const char* format,...)
{
	va_list args;
	size_t offset;
	int count;
	// строка не пустая?
	offset = blobSize(*str);
	if (offset)
	{
		// проверка
		if (((char*)*str)[offset - 1] != '\0')
			return ERR_BAD_INPUT;
		// подправка
		--offset;
	}
	// сколько требуется символов?
	va_start(args, format);
	count = _vscprintf(format, args);
	va_end(args);
	if (count < 0)
		return ERR_BAD_INPUT;
	// выделение памяти
	*str = blobResize(*str, offset + (size_t)count + 1);
	if (*str == 0)
		return ERR_OUTOFMEMORY;
	// печать в строку
	va_start(args, format);
	vsprintf_s((char*)*str + offset, count + 1, format, args);
	va_end(args);
	// выйти
	return ERR_OK;
}

/* 
*******************************************************************************
Печать информации о сборке
*******************************************************************************
*/

static err_t beePrintBuildInfo(blob_t* str)
{
	// прочитать контрольную характеристику
	octet stampRead[STAMP_SIZE], stampCalc[STAMP_SIZE];
	err_t code = beeReadAndCalcStamp(stampRead, stampCalc);
	octet stamp[2 * STAMP_SIZE + STAMP_SIZE * 4 / 16 + 1], pos, *ptr;
	// ошибка чтения?
	if (code != ERR_OK)
		return beeSprintf(str, 
			"Platform: Win%d\r\n"
			"Version: %s\r\n"
			"Stamp: read error", 
			sizeof(size_t) == 4 ? 32 : 64, 
			BEE2_VERSION);
	// напечатать контрольную характеристику
	for (pos = 0, ptr = stamp; pos < STAMP_SIZE; ++pos)
	{
		if (pos % 16 == 0)
			*ptr++ = '\r', *ptr++ = '\n', *ptr++ = ' ', *ptr++ = ' ';
		sprintf(ptr, "%02X", (unsigned)stampRead[pos]);
		++ptr, ++ptr;
	}
	return beeSprintf(str, 
		"Platform: Win%d\r\n"
		"Version: %s\r\n"
		"Stamp: %s [%s]", 
		sizeof(size_t) == 4 ? 32 : 64,
		BEE2_VERSION, 
		stamp, 
		memEq(stampRead, stampCalc, STAMP_SIZE) ? "OK" : "error");
}

/* 
*******************************************************************************
Обработчик сообщений диалогового окна
*******************************************************************************
*/

static BOOL CALLBACK beeLogoDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, 
	LPARAM lParam)
{
	// начало
	if (uMsg == WM_INITDIALOG)
	{
		blob_t str = 0;
		// печать информации о версии
		beePrintBuildInfo(&str);
		if (str != 0)
		{
			SetDlgItemTextA(hDlg, 102, (const char*)str);
			blobClose(str);
		}
		return TRUE;
	}
	// выход
	if (uMsg == WM_COMMAND && 
		HIWORD(wParam) == BN_CLICKED && 
		(LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL))
	{
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

/* 
*******************************************************************************
Обработчик окон верхнего уровня (для поиска главного окна)
*******************************************************************************
*/

static BOOL CALLBACK beeEnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	// нулевой идентификатор присваивается System Idle Process?
	DWORD id = 0;
	// нашли?
	GetWindowThreadProcessId(hWnd, &id);
	if (id == GetCurrentProcessId())
	{
		*((HWND*)lParam) = hWnd;
		return FALSE;
	}
	return TRUE;
}

/* 
*******************************************************************************
Найти главное окно
*******************************************************************************
*/

static HWND beeFindMainWindow()
{
	HWND hWnd = 0;
    char title[1024];
    char title_tmp[8 + 8 + 2];
	// ищем обычное окно
	EnumWindows(beeEnumWindowsProc, (LPARAM)&hWnd);
	if (hWnd != 0)
		return hWnd;
	// ищем консольное окно (http://support.microsoft.com/kb/124103)
    if (GetConsoleTitleA(title, sizeof(title)) == 0)
		return 0;
	sprintf(title_tmp, "%08X/%08X", GetTickCount(), GetCurrentProcessId());
	if (!SetConsoleTitleA(title_tmp))
		return 0;
	Sleep(40);
	hWnd = FindWindowA(NULL, title_tmp);
	SetConsoleTitleA(title);
	return hWnd;
}

/* 
*******************************************************************************
Напечатать лого
*******************************************************************************
*/

err_t beeLogo()
{
	// вызвать диалог
	if (DialogBoxA(GetModuleHandleA("bee2.dll"), 
		"BEELOGO", beeFindMainWindow(), (DLGPROC)beeLogoDlgProc) == -1)
		return ERR_SYS;
	return ERR_OK;
}

/* 
*******************************************************************************
Точка входа
*******************************************************************************
*/

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, 
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
