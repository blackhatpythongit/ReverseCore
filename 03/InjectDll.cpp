// InjectDll.cpp

#include "windows.h"
#include "stdio.h"
#include "tchar.h"

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath)+1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;
	
	// #1. 使用dwPID获取目标进程（notepad.exe）句柄。
	if( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf("OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}
	
	// #2. 在目标进程（notepad.exe）内存中分配szDllName大小的内存。
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	
	// #3. 将myhack.dll路径写入分配的内存。
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);
	
	// #4. 获取LoadLibraryA() API的地址。
	hMod = GetModuleHandle("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	
	// #5. 在notepad.exe进程中运行线程。
	hThread = CreateRemoteThread(hProcess,			// hProcess
		NULL,			// lpThreadAttributes
		0,				// dwStackSize
		pThreadProc,	// lpStartAddress
		pRemoteBuf,		// lpParameter
		0,				// dwCreationFlags
		NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	
	return TRUE;
}

int _tmain(int argc, TCHAR *argv[])
{
	if( argc != 3)
	{
		_tprintf("Usage :  %s pid dll_path\n", argv[0]);
		return 1;
	}
	
	// inject dll
	if( InjectDll((DWORD)strtol(argv[1], NULL, 0), argv[2]) )
		_tprintf("InjectDll(\"%s\") success!!!\n", argv[2]);
	else
		_tprintf("InjectDll(\"%s\") failed!!!\n", argv[2]);
	
	return 0;
}