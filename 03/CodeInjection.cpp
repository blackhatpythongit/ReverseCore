#include "windows.h"
#include "stdio.h"

// Thread Parameter
typedef struct _THREAD_PARAM 
{
	FARPROC pFunc[2];		// LoadLibraryA(), GetProcAddress()
	char szBuf[4][128];		// "user32.dll", "MessageBoxA",
	// "www.reversecore.com", "ReverseCore"
}THREAD_PARAM, *PTHREAD_PARAM;

// LoadLibraryA()
typedef HMODULE (WINAPI *PFLOADLIBRARYA)(LPCSTR lpLibFileName);

// GetProcAddress()
typedef FARPROC (WINAPI *PFGETPROCADDRESS)(HMODULE hModule, LPCSTR lpProcName);

// MessageBoxA()
typedef int (WINAPI *PFMESSAGEBOXA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

// Thread Procedure
DWORD WINAPI ThreadProc(LPVOID lParam)
{
	PTHREAD_PARAM pParam = (PTHREAD_PARAM)lParam;
	HMODULE hMod = NULL;
	FARPROC pFunc = NULL;
	
	// LoadLibrary("user32.dll")
	//  pParam->pFunc[0] -> kernel32!loadLibraryA()
	//  pParam->szBuf[0] -> "user32.dll"
	hMod = ((PFLOADLIBRARYA)pParam->pFunc[0])(pParam->szBuf[0]);
	
	// GetProcAddress("MessageBoxA")
	//  pParam->pFunc[1] -> kernel32!GetProcAddress()
	//  pParam->szBuf[1] -> "MessageBoxA"
	pFunc = (FARPROC)((PFGETPROCADDRESS)pParam->pFunc[1])(hMod, pParam->szBuf[1]);
	
	// MessageBoxA(NULL, "www.reversecore.com", "ReverseCore", MB_OK)
	//  pParam->szBuf[2] -> "www.reversecore.com"
	//  pParam->szBuf[3] -> "ReverseCore"
	((PFMESSAGEBOXA)pFunc)(NULL, pParam->szBuf[2], pParam->szBuf[3], MB_OK);
	
	return 0;
}

BOOL InjectCode(DWORD dwPID)
{
	HMODULE hMod = NULL;
	THREAD_PARAM param = {0,};
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pRemoteBuf[2] = {0,};
	DWORD dwSize = 0;
	
	hMod = GetModuleHandleA("kernel32.dll");
	
	// set THREAD_PARAM
	param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
	param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");
	strcpy(param.szBuf[0], "user32.dll");
	strcpy(param.szBuf[1], "MessageBoxA");
	strcpy(param.szBuf[2], "www.reversecore.com");
	strcpy(param.szBuf[3], "ReverseCore");
	
	// Open Process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS,	// dwDesiredAccess
		FALSE,				// bInheritHandle
		dwPID);				// dwProcessId
	
	// Alloation for THREAD_PARAM
	dwSize = sizeof(THREAD_PARAM);
	pRemoteBuf[0] = VirtualAllocEx(hProcess,			// hProcess
		NULL,				// lpAddress
		dwSize,				// dwSize
		MEM_COMMIT,			// flAllocationType
		PAGE_READWRITE);	// flProtect
	
	WriteProcessMemory(hProcess,		//hProcess
		pRemoteBuf[0],					// lpBaseAddress
		(LPVOID)&param,					// lpBuffer
		dwSize,							// nSize
		NULL);							// [out]
	// lpNumberOfBytesWritten
	
	// Allocation for ThreadProc()
	dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;
	pRemoteBuf[1] = VirtualAllocEx(hProcess,		// hProcess
		NULL,										// lpAddress
		dwSize,										// dwSize
		MEM_COMMIT,									// flAllocationType
		PAGE_EXECUTE_READWRITE);					// flProtect
	
	WriteProcessMemory(hProcess,			// hProcess
		pRemoteBuf[1],						// lpBaseAddress
		(LPVOID)ThreadProc,					// lpBuffer
		dwSize,								// nSize
		NULL);								// [out]
	// lpNumberOfBytesWritten
	
	hThread = CreateRemoteThread(hProcess,		// hProcess
								NULL,			// lpThreadAttributes
								0,				// dwStackSize
								(LPTHREAD_START_ROUTINE)((DWORD)pRemoteBuf[1]),
								pRemoteBuf[0],	// lpParameter
								0,				// dwCreationFlags
								NULL);			// lpThread
	
	WaitForSingleObject(hThread, INFINITE);
	
	CloseHandle(hThread);
	CloseHandle(hProcess);
	
	return TRUE;
}

int main(int argc, char *argv[])
{
	DWORD dwPID = 0;
	
	if( argc != 2 )
	{
		printf("Usage : %s pid\n", argv[0]);
		return 1;
	}
	
	// code injection
	dwPID = (DWORD)atol(argv[1]);
	InjectCode(dwPID);
	
	return 0;
}