#include "windows.h"

typedef BOOL (WINAPI *PFSETWINDOWTEXTW)(HWND hWnd, LPWSTR lpString);

PROC g_pOrgFunc;

BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
	wchar_t* pNum = L"零一二三四五六七八九";
	wchar_t temp[2] = {0,};
	int i = 0, nLen = 0, nIndex = 0;
	
	nLen = wcslen(lpString);
	for(i=0; i <nLen; i++)
	{
		// 将阿拉伯数字转换为中文数字
		//   lpString是宽字符版本（2个字节）字符串
		if( L'0'<= lpString[i] && lpString[i] <= L'9')
		{
			temp[0] = lpString[i];
			nIndex = _wtoi(temp);
			lpString[i] = pNum[nIndex];
		}
	}
	
	// 调用user32.SetWindowTextW() API
	// (修改lpString缓冲区中的内容)
	return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}

BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;
	
	// hMod, pAddr = ImageBase of calc.exe
	//             = VA to MZ signature (IMAGE_DOS_HEADER)
	hMod = GetModuleHandle(NULL);
	pAddr = (PBYTE)hMod;
	
	// pAddr = VA to PE signature (IMAGE_NT_HEADER)
	pAddr += *((DWORD*)&pAddr[0x3C]);
	
	// dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
	dwRVA = *((DWORD*)&pAddr[0x80]);
	
	// pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod+dwRVA);
	
	for( ; pImportDesc->Name; pImportDesc++ )
	{
		// szLibName = VA to IMAGE_IMPORT_DESCRIPTOR.Name
		szLibName = (LPCTSTR)((DWORD)hMod+pImportDesc->Name);
		
		if( !stricmp(szLibName, szDllName) )
		{
			// pThunk = IMAGE_IMPORT_DESCRIPTOR.FirstThunk
			//        = VA to IAT(Import Address Table)
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);
			
			// pThunk->u1.Function = VA to API
			for ( ;pThunk->u1.Function; pThunk++ )
			{
				if ( (DWORD)pThunk->u1.Function == (DWORD)pfnOrg )
				{
					// 更改内存属性为E/R/M
					VirtualProtect((LPVOID)&pThunk->u1.Function,
						4,
						PAGE_EXECUTE_READWRITE,
						&dwOldProtect);
					
					// 修改IAT值（钩取）
					pThunk->u1.Function = (unsigned long *)pfnNew;
					
					// 恢复内存属性
					VirtualProtect((LPVOID)&pThunk->u1.Function,
						4,
						dwOldProtect,
						&dwOldProtect);
					
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved)
{
	switch( fdwReason )
	{
	case DLL_PROCESS_ATTACH:
		// 保存原始API地址
		g_pOrgFunc = GetProcAddress(GetModuleHandle("user32.dll"), "SetWindowTextW");
		
		// # hook
		//   用hookiat.MySetWindowText()钩取user32.SetWindowTextW()
		hook_iat("user32.dll", g_pOrgFunc, (PROC)MySetWindowTextW);
		break;
		
	case DLL_PROCESS_DETACH:
		// # unhook
		//   将calc.exe的IAT恢复原值
		hook_iat("user32.dll", (PROC)MySetWindowTextW, g_pOrgFunc);
		break;
	}
	
	return TRUE;
}