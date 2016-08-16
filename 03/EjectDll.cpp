// EjectDll.exe

#include "windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "stdio.h"

#define DEF_PROC_NAME "notepad.exe"
#define DEF_DLL_NAME "myhack.dll"

DWORD FindProcessID(LPCSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	// ��ȡϵͳ���գ�SnapShot��
	pe.dwSize = sizeof( PROCESSENTRY32 );
	hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPALL, NULL );

	// ���ҽ���
	Process32First(hSnapShot, &pe);
	do
	{
		if(!_tcsicmp(szProcessName, (LPCSTR)pe.szExeFile))
		{
			dwPID=pe.th32ProcessID;
			break;
		}
	}while(Process32Next(hSnapShot, &pe));
	
	CloseHandle(hSnapShot);

	return dwPID;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if( !OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) )
	{
		_tprintf("OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if( !LookupPrivilegeValue(NULL,				// lookup privilege on local system
								lpszPrivilege,	// privilege to lookup
								&luid) )			// reveives LUID of privilege
	{
		_tprintf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if( bEnablePrivilege )
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if( !AdjustTokenPrivileges(hToken,
								FALSE,
								&tp,
								sizeof(TOKEN_PRIVILEGES),
								(PTOKEN_PRIVILEGES) NULL,
								(PDWORD) NULL) )
	{
		_tprintf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if( GetLastError() == ERROR_NOT_ALL_ASSIGNED )
	{
		_tprintf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCSTR szDllName)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE pThreadProc;

	// dwPID=notepad����ID
	// ʹ��TH32CS_SNAPMODULE��������ȡ���ص�notepad���̵�DLL����
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	
	bMore = Module32First(hSnapshot, &me);
	for( ; bMore ; bMore = Module32Next(hSnapshot, &me) )
	{
		if( !_tcsicmp((LPCTSTR)me.szModule, szDllName) || !_tcsicmp((LPCTSTR)me.szExePath, szDllName) )
		{
			bFound = TRUE;
			break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf("OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}

	hModule = GetModuleHandle("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		pThreadProc, me.modBaseAddr,
		0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
	DWORD dwPID = 0xFFFFFFFF;

	// ����process
	dwPID = FindProcessID(DEF_PROC_NAME);
	if (dwPID == 0xFFFFFFFF)
	{
		_tprintf("There is no %s process!\n", DEF_PROC_NAME);
		return 1;
	}

	_tprintf("PID of \"%s\" is %d\n", DEF_PROC_NAME, dwPID);

	// ����privilege
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
		return 1;

	// eject dll
	if (EjectDll(dwPID, DEF_DLL_NAME))
		_tprintf("EjectDll(%d, \"%s\") success!!!\n", dwPID, DEF_DLL_NAME);
	else
		_tprintf("EjectDll(%d, \"%s\") success!!!\n", dwPID, DEF_DLL_NAME);

	return 0;
}