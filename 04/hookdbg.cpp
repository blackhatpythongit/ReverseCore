#include "windows.h"
#include "stdio.h"

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	// 获取WriteFile() API地址
	g_pfWriteFile = GetProcAddress(GetModuleHandle("kernel32.dll"), "WriteFile");
	
	// API"钩子" - WriteFile()
	//   更改第一个字节为0xCC (INT3)
	//   originalbyte是g_chOrgByte备份
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
	
	// 是断点异常（int3）时
	if ( EXCEPTION_BREAKPOINT == per->ExceptionCode)
	{
		// 断点地址为WriteFile() API地址时
		if (g_pfWriteFile == per->ExceptionAddress)
		{
			// #1. Unhook
			//   将0xCC恢复为original byte
			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
				&g_chOrgByte, sizeof(BYTE), NULL);
			
			// #2. 获取线程上下文
			ctx.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(g_cpdi.hThread, &ctx);
			
			// #3. 获取WriteFile()的param 2、3值
			//     函数参数存在于相应进程的栈
			//     param 2 : ESP + 0x8
			//     param 3 : ESP + 0xC
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8),
				&dwAddrOfBuffer, sizeof(DWORD), NULL);
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC),
				&dwNumberOfBytesToWrite, sizeof(DWORD), NULL);
			
			// #4. 分配临时缓冲区
			lpBuffer = (PBYTE)malloc(dwNumberOfBytesToWrite+1);
			memset(lpBuffer, 0, dwNumberOfBytesToWrite+1);
			
			// #5. 复制WriteFile()缓冲区到临时缓冲区
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
				lpBuffer, dwNumberOfBytesToWrite, NULL);
			
			printf("\n### original string : %s\n", lpBuffer);
			
			// #6. 将小写字母转换为大写字母
			for ( i = 0; i < dwNumberOfBytesToWrite; i++)
			{
				if ( 0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7a)
					lpBuffer[i] -= 0x20;
			}
			
			printf("\n### converted string : %s\n", lpBuffer);
			
			// #7. 将变换后的缓冲区复制到WriteFile()缓冲区
			WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
				lpBuffer, dwNumberOfBytesToWrite, NULL);
			
			// #8. 释放临时缓冲区
			free(lpBuffer);
			
			// #9. 将线程上下文的EIP更改为WriteFile()首地址
			//   (当前为WriteFile()+1位置，INT3命令之后)
			ctx.Eip = (DWORD)g_pfWriteFile;
			SetThreadContext(g_cpdi.hThread, &ctx);
			
			// #10. 运行被调试进程
			ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
			
			Sleep(0);
			
			// #11. API“钩子”
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
	
	// 等待被调试者发生事件
	while( WaitForDebugEvent(&de, INFINITE) )
	{
		dwContinueStatus = DBG_CONTINUE;
		// 被调试进程生成或者附加事件
		if ( CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			OnCreateProcessDebugEvent(&de);
		}
		// 异常事件
		else if ( EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode )
		{
			if ( OnExceptionDebugEvent(&de) )
				continue;
		}
		// 被调试进程终止事件
		else if( EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode )
		{
			// 被调试者终止-调试器终止
			break;
		}
		// 再次运行被调试者
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
	
	// 调试器循环
	DebugLoop();
	
	return 0;
}