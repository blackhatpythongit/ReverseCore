// KeyHook.cpp

#include "stdio.h"
#include "windows.h"

#define DEF_PROCESS_NAME "notepad.exe"

HINSTANCE g_hInstance = NULL;
HHOOK g_hHook = NULL;
HWND g_hWnd = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpvReserved)
{
	switch( dwReason )
	{
	case DLL_PROCESS_ATTACH:
		g_hInstance = hinstDll;
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return true;
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	char szPath[MAX_PATH] = {0,};
	char *p = NULL;
	
	if( nCode == 0)
	{
		// bit 31: 0 = key press, 1 = key release
		if( !(lParam & 0x80000000) ) // 释放键盘按钮时
		{
			GetModuleFileName(NULL, szPath, MAX_PATH);
			p = strrchr(szPath, '\\');
			
			//  比较当前进程名称，若为notepad.exe，则消息不会传递给应用程序（或下一个“钩子”）
			if( !_stricmp(p + 1, DEF_PROCESS_NAME) )
				return 1;
		}
	}
	
	//  若非notepad.exe，则调用CallNextHookEx()函数，将消息传递给应用程序（或下一个“钩子”）。
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) void HookStart()
{
	g_hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hInstance, 0);
}
__declspec(dllexport) void HookStop()
{
	if( g_hHook )
	{
		UnhookWindowsHookEx(g_hHook);
		g_hHook = NULL;
	}
}
#ifdef __cplusplus
}
#endif