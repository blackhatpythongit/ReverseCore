#include "stdio.h"
#include "windows.h"
#include "shlobj.h"
#include "Wininet.h"
#include "tchar.h"

#pragma comment(lib, "urlmon.lib")

#define DEF_BUF_SIZE 4096
#define DEF_URL "http://www.google.com/index.html"
#define DEF_INDEX_FILE "index.html"

HWND g_hWnd = NULL;
HMODULE g_hMod = NULL;

BOOL DownloadURL(LPCTSTR szURL, LPCTSTR szFile)
{
	TCHAR szPath[_MAX_PATH] = {0,};
	if( !GetModuleFileName( NULL, szPath, MAX_PATH) )
		return FALSE;
	
	TCHAR *p = _tcsrchr( szPath, '\\' );
	if( !p )
		return FALSE;
	
	_tcscpy(p+1, DEF_INDEX_FILE);
	
	URLDownloadToFile(NULL, DEF_URL, szPath, 0, NULL);
	return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	DWORD dwPID = 0;
	
	GetWindowThreadProcessId(hWnd, &dwPID);
	
	if (dwPID == (DWORD)lParam)
	{
		g_hWnd = hWnd;
		return FALSE;
	}
	
	return TRUE;
}

HWND GetWindowHandleFromPID(DWORD dwPID)
{
	EnumWindows(EnumWindowsProc, dwPID);
	
	return g_hWnd;
}

BOOL DropFile(LPCTSTR wcsFile)
{
	HWND hWnd = NULL;
	DWORD dwBufSize = 0;
	BYTE *pBuf = NULL;
	DROPFILES *pDrop = NULL;
	char szFile[MAX_PATH] = {0,};
	HANDLE hMem = 0;
	
	dwBufSize = sizeof(DROPFILES) + strlen(wcsFile) + 1;
	
	if ( !(hMem = GlobalAlloc(GMEM_ZEROINIT, dwBufSize)) )
	{
		OutputDebugString("GlobalAlloc() failed!!!");
		return FALSE;
	}
	
	pBuf = (LPBYTE)GlobalLock(hMem);
	
	pDrop = (DROPFILES*)pBuf;
	pDrop->pFiles = sizeof(DROPFILES);
	strcpy((char*)(pBuf + sizeof(DROPFILES)), wcsFile);
	
	GlobalUnlock(hMem);
	
	if( !(hWnd = GetWindowHandleFromPID(GetCurrentProcessId())) )
	{
		OutputDebugString("GetWndHandleFromPID() failed!!!");
		return FALSE;
	}
	
	PostMessage(hWnd, WM_DROPFILES, (WPARAM)pBuf, NULL);
	
	return TRUE;
}

DWORD WINAPI ThreadProc(LPVOID lParam)
{
	TCHAR szPath[MAX_PATH] = {0,};
	TCHAR *p = NULL;
	
	GetModuleFileName(NULL, szPath, sizeof(szPath));
	
	if( p = _tcsrchr(szPath, '\\') )
	{
		_tcscpy(p+1, DEF_INDEX_FILE);
		
		if( DownloadURL(DEF_URL, szPath) )
		{
			DropFile(szPath);
		}
	}
	
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved)
{
	g_hMod = (HMODULE)hinstDll;
	switch( fdwReason )
	{
	case DLL_PROCESS_ATTACH:
		CloseHandle(CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL));
		break;
	}
	
	return TRUE;
}

#ifdef __cplusplus
extern "C" {
#endif
	// 出现在IDT中的dump export function...
	__declspec(dllexport) void dummy()
	{
		return;
	}
#ifdef __cplusplus
}
#endif
