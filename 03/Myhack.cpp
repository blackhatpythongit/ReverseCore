// myhack.cpp

#include "windows.h"
#include "tchar.h"

#pragma comment(lib, "urlmon.lib")

#define DEF_URL ("http://www.naver.com/index.html")
#define DEF_FILE_NAME ("index.html")

HMODULE g_hMod = NULL;

DWORD WINAPI ThreadProc(LPVOID lParam)
{
	TCHAR szPath[_MAX_PATH] = {0,};
	if( !GetModuleFileName( g_hMod, szPath, MAX_PATH) )
		return FALSE;
	
	TCHAR *p = _tcsrchr( szPath, '\\' );
	if( !p )
		return FALSE;
	
	_tcscpy(p+1, DEF_FILE_NAME);
	
	URLDownloadToFile(NULL, DEF_URL, szPath, 0, NULL);
	
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved)
{
	HANDLE hThread = NULL;
	
	g_hMod = (HMODULE)hinstDll;
	
	switch( fdwReason )
	{
	case DLL_PROCESS_ATTACH:
		OutputDebugString("myhack.dll Injection!!!");
		hThread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
		CloseHandle(hThread);
		break;
	}
	
	return TRUE;
}
