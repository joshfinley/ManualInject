#include "Injection.h"

bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE *					pSrcData		= nullptr;
	IMAGE_NT_HEADERS *		pOldNtHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER *		pOldFileHeader	= nullptr;
	BYTE *					pTargetBase		= nullptr;

	if (!GetFileAttributesA(szDllFile))
		return false;

	std::ifstream file(szDllFile, std::ios::binary | std::ios::ate);
	if (file.fail())
		return false;

	auto fileSize = file.tellg();
	if (fileSize < 0x1000) {
		file.close();
		return false;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(fileSize)];
	if (!pSrcData) {
		file.close();
		return false;
	}

	file.seekg(0, std::ios::beg);
	file.read(reinterpret_cast<char*>(pSrcData), fileSize);
	file.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) // 0x5A4D == MZ
	{
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(
		pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew
	);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_i386) {
		delete[] pSrcData;
		return false;
	}
#endif

	pTargetBase = reinterpret_cast<BYTE*>(
		VirtualAllocEx(
			hProc, 
			reinterpret_cast<void*>(pOldOptHeader->ImageBase), 
			pOldOptHeader->SizeOfImage, 
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
		)
	);
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(
			VirtualAllocEx(
				hProc,
				nullptr,
				pOldOptHeader->SizeOfImage,
				MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
			)
		);
		if (!pTargetBase)
		{
			delete[] pSrcData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA mapData{ 0 };
	mapData.pLoadLibraryA = LoadLibraryA;
	mapData.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto * pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(
				hProc,
				pTargetBase + pSectionHeader->VirtualAddress,
				pSrcData + pSectionHeader->PointerToRawData,
				pSectionHeader->SizeOfRawData,
				nullptr)
				) {
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase,  MEM_RELEASE);
				return false;
			}
		}
	}

	delete[] pSrcData;
}


DWORD GetProcId(const char* processName)
{
	DWORD pid = 0;
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return GetLastError();

	BOOL moreProcesses = Process32First(hSnap, &PE32);
	while (moreProcesses)
	{
		if (!strcmp(processName, PE32.szExeFile)){
			pid = PE32.th32ProcessID;
			break;
		}
		moreProcesses = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	return pid;
}



void __stdcall ShellCode(MANUAL_MAPPING_DATA * pData)
{
	if (!pData)
		return;

	BYTE * pBase = reinterpret_cast<BYTE *>(pData);
	auto * pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(
			pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew
		)->OptionalHeader;

	auto _LoadLibraryA		= pData->pLoadLibraryA;
	auto _GetProcAddress	= pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE * LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;
	}
}
