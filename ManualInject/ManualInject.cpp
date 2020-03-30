// ManualInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// Great post explaining how this works: https://www.elitepvpers.com/forum/c-c/4175990-how-does-manual-mapping-work-example.html
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