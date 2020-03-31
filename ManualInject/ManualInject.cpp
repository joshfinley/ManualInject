// ManualInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// Great post explaining how this works: https://www.elitepvpers.com/forum/c-c/4175990-how-does-manual-mapping-work-example.html
//

#include <iostream>
#include "Injection.h"

bool IsCorrectTargetArch(HANDLE hProc)
{
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget))
	{

		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}


int main()
{
#ifdef _WIN64
	#ifdef _DEBUG
		const char szDllFile[]  = "C:\\Users\\finle\\source\\repos\\ManualInject\\x64\\Debug\\PayloadLibrary.dll";
	#else
		const char szDllFile[] = "C:\\Users\\finle\\source\\repos\\ManualInject\\x64\\Release\\PayloadLibrary.dll";
	#endif
#else
	#ifdef _DEBUG
		const char szDllFile[] = "C:\\Users\\finle\\source\\repos\\ManualInject\\x86\\Debug\\PayloadLibrary.dll";
	#else
		const char szDllFile[] = "C:\\Users\\finle\\PayloadLibrary.dll";
	#endif
#endif
    const char szProc[] = "ac_client.exe";

	DWORD pid = GetProcId(szProc);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc) {
		printf("[-] OpenProcess failed: 0x%X\n", GetLastError());
		system("PAUSE");
		return GetLastError();
	}

	if (!IsCorrectTargetArch(hProc)) {
		printf("[-] Invalid target process.\n");
		CloseHandle(hProc);
		system("PAUSE");
		return 0;
	}

	if (!ManualMap(hProc, szDllFile)) {
		printf("Something went wrong\n");
		CloseHandle(hProc);
		system("PAUSE");
		return 0;
	}

	CloseHandle(hProc);
	return 0;
}