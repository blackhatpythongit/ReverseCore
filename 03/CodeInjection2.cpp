#include "windows.h"
#include "stdio.h"

typedef struct _THREAD_PARAM
{
	FARPROC pFunc[2];		// LoadLibrary(), GetProcAddress()
} THREAD_PARAM, *PTHREAD_PARAM;

// ThreadProc()
BYTE g_InjectionCode[] = 
{
	0x55,0x8B,0xEC,0x8B,0x75,0x08,0x68,0x6C,0x6C,0x00,0x00,0x68,0x33,0x32,0x2E,0x64,0x68,0x75,0x73,0x65,0x72,0x54,0xFF,0x16,0x68,0x6F,0x78,0x41,0x00,0x68,0x61,0x67,0x65,0x42,0x68,0x4D,0x65,0x73,0x73,0x54,0x50,0xFF,0x56,0x04,0x6A,0x00,0xE8,0x0C,0x00,0x00,0x00,0x52,0x65,0x76,0x65,0x72,0x73,0x65,0x43,0x6F,0x72,0x65,0x00,0xE8,0x14,0x00,0x00,0x00,0x77,0x77,0x77,0x2E,0x72,0x65,0x76,0x65,0x72,0x73,0x65,0x63,0x6F,0x72,0x65,0x2E,0x63,0x6F,0x6D,0x00,0x6A,0x00,0xFF,0xD0,0x33,0xC0,0x8B,0xE5,0x5D,0xC3
};

BOOL InjectCode(DWORD dwPID)
{
	HMODULE hMod = NULL;
	THREAD_PARAM param = {0,};
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pRemoteBuf[2] = {0,};

	hMod = GetModuleHandleA("kernel32.dll");

	// set THREAD_PARAM
	param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
	param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");

	// Open Process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS,
							FALSE,
							dwPID);

	// Allocation for THREAD_PARAM
	pRemoteBuf[0] = VirtualAllocEx(hProcess,
									NULL,
									sizeof(THREAD_PARAM),
									MEM_COMMIT,
									PAGE_READWRITE);

	WriteProcessMemory(hProcess,
						pRemoteBuf[0],
						(LPVOID)&param,
						sizeof(THREAD_PARAM),
						NULL);

	// Allocation for g_InjectionCode
	pRemoteBuf[1] = VirtualAllocEx(hProcess,
									NULL,
									sizeof(g_InjectionCode),
									MEM_COMMIT,
									PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess,
						pRemoteBuf[1],
						(LPVOID)&g_InjectionCode,
						sizeof(g_InjectionCode),
						NULL);

	hThread = CreateRemoteThread(hProcess,
								NULL,
								0,
								(LPTHREAD_START_ROUTINE)pRemoteBuf[1],
								pRemoteBuf[0],
								0,
								NULL);

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