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
		if( !(lParam & 0x80000000) ) // �ͷż��̰�ťʱ
		{
			GetModuleFileName(NULL, szPath, MAX_PATH);
			p = strrchr(szPath, '\\');
			
			//  �Ƚϵ�ǰ�������ƣ���Ϊnotepad.exe������Ϣ���ᴫ�ݸ�Ӧ�ó��򣨻���һ�������ӡ���
			if( !_stricmp(p + 1, DEF_PROCESS_NAME) )
				return 1;
		}
	}
	
	//  ����notepad.exe�������CallNextHookEx()����������Ϣ���ݸ�Ӧ�ó��򣨻���һ�������ӡ�����
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