#include "windows.h"
#include "stdio.h"

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	// ��ȡWriteFile() API��ַ
	g_pfWriteFile = GetProcAddress(GetModuleHandle("kernel32.dll"), "WriteFile");
	
	// API"����" - WriteFile()
	//   ���ĵ�һ���ֽ�Ϊ0xCC (INT3)
	//   originalbyte��g_chOrgByte����
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
	ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);
	WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chINT3, sizeof(BYTE), NULL);
	return TRUE;
}

BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
	CONTEXT ctx;
	PBYTE lpBuffer = NULL;
	DWORD dwNumberOfBytesToWrite, dwAddrOfBuffer, i;
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;
	
	// �Ƕϵ��쳣��int3��ʱ
	if ( EXCEPTION_BREAKPOINT == per->ExceptionCode)
	{
		// �ϵ��ַΪWriteFile() API��ַʱ
		if (g_pfWriteFile == per->ExceptionAddress)
		{
			// #1. Unhook
			//   ��0xCC�ָ�Ϊoriginal byte
			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
				&g_chOrgByte, sizeof(BYTE), NULL);
			
			// #2. ��ȡ�߳�������
			ctx.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(g_cpdi.hThread, &ctx);
			
			// #3. ��ȡWriteFile()��param 2��3ֵ
			//     ����������������Ӧ���̵�ջ
			//     param 2 : ESP + 0x8
			//     param 3 : ESP + 0xC
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8),
				&dwAddrOfBuffer, sizeof(DWORD), NULL);
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC),
				&dwNumberOfBytesToWrite, sizeof(DWORD), NULL);
			
			// #4. ������ʱ������
			lpBuffer = (PBYTE)malloc(dwNumberOfBytesToWrite+1);
			memset(lpBuffer, 0, dwNumberOfBytesToWrite+1);
			
			// #5. ����WriteFile()����������ʱ������
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
				lpBuffer, dwNumberOfBytesToWrite, NULL);
			
			printf("\n### original string : %s\n", lpBuffer);
			
			// #6. ��Сд��ĸת��Ϊ��д��ĸ
			for ( i = 0; i < dwNumberOfBytesToWrite; i++)
			{
				if ( 0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7a)
					lpBuffer[i] -= 0x20;
			}
			
			printf("\n### converted string : %s\n", lpBuffer);
			
			// #7. ���任��Ļ��������Ƶ�WriteFile()������
			WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
				lpBuffer, dwNumberOfBytesToWrite, NULL);
			
			// #8. �ͷ���ʱ������
			free(lpBuffer);
			
			// #9. ���߳������ĵ�EIP����ΪWriteFile()�׵�ַ
			//   (��ǰΪWriteFile()+1λ�ã�INT3����֮��)
			ctx.Eip = (DWORD)g_pfWriteFile;
			SetThreadContext(g_cpdi.hThread, &ctx);
			
			// #10. ���б����Խ���
			ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
			
			Sleep(0);
			
			// #11. API�����ӡ�
			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
				&g_chINT3, sizeof(BYTE), NULL);
			
			return TRUE;
		}
	}
	return FALSE;
}

void DebugLoop()
{
	DEBUG_EVENT de;
	DWORD dwContinueStatus;
	
	// �ȴ��������߷����¼�
	while( WaitForDebugEvent(&de, INFINITE) )
	{
		dwContinueStatus = DBG_CONTINUE;
		// �����Խ������ɻ��߸����¼�
		if ( CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			OnCreateProcessDebugEvent(&de);
		}
		// �쳣�¼�
		else if ( EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode )
		{
			if ( OnExceptionDebugEvent(&de) )
				continue;
		}
		// �����Խ�����ֹ�¼�
		else if( EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode )
		{
			// ����������ֹ-��������ֹ
			break;
		}
		// �ٴ����б�������
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}

int main(int argc, char* argv[])
{
	DWORD dwPID;
	
	if (argc != 2)
	{
		printf("Usage: hookdbg.exe pid\n");
		return 1;
	}
	
	// Attach Process
	dwPID = atoi(argv[1]);
	if (!DebugActiveProcess(dwPID))
	{
		printf("DebugActiveProcess(%d) failed!!!\n"
			"Error Code = %d\n", dwPID, GetLastError());
		return 1;
	}
	
	// ������ѭ��
	DebugLoop();
	
	return 0;
}