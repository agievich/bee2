/*
*******************************************************************************
\file bee2.c
\brief Bee2 DLL entry points
\project bee2 [cryptographic library]
\created 2013.02.25
\version 2025.04.21
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
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

extern const char bash_platform[];

static err_t beePrintBuildInfo(blob_t* str)
{
	return beeSprintf(str, 
		"Version: %s [%s]\r\n"
		"B_PER_S: %u\r\n"
		"B_PER_W: %u\r\n"
		"Endianness: %s\r\n"
		"NDEBUG: %s\r\n"
		"Safe (constant-time): %s\r\n"
		"Bash_platform: %s",
		BEE2_VERSION, __DATE__, 
		(unsigned)B_PER_S,
		(unsigned)B_PER_W,
#if defined(LITTLE_ENDIAN)
		"LE",
#else
		"BE",
#endif
#ifdef NDEBUG
		"ON",
#else
		"OFF",
#endif
#ifdef SAFE_FAST
		"OFF",
#else
		"ON",
#endif
		bash_platform
	);
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
