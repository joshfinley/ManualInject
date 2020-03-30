// ManualInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Injection.h"

int main()
{
    const char szDllFile[]  = "C:\\Users\\finle\\source\\repos\\ManualInject\\PayloadLibrary.dll";
    const char szProc[] = "PayloadTarget.exe";

	DWORD pid = GetProcId(szProc);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc)
		return GetLastError();

	if (!ManualMap(hProc, szDllFile)) {
		CloseHandle(hProc);
		return 0;
	}

	CloseHandle(hProc);
	return 0;

}