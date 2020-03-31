#include "Injection.h"

void __stdcall Shellcode(MANUAL_MAPPING_DATA * pData);

bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE *					pSrcData		= nullptr;
	IMAGE_NT_HEADERS *		pOldNtHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER * pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER *		pOldFileHeader	= nullptr;
	BYTE *					pTargetBase		= nullptr;

	/*
	  1. Read target process file contents into this address space  
	 	 using its handle											 
	*/
	if (!GetFileAttributesA(szDllFile))
		return false;

	std::ifstream file(szDllFile, std::ios::binary | std::ios::ate);
	if (file.fail()) {
		printf("[-] The file failed: %X\n", (DWORD)file.rdstate());
		file.close();
		return false;
	}

	auto fileSize = file.tellg();
	if (fileSize < 0x1000) {
		printf("[-] Filesize is invalid.\n");
		file.close();
		return false;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(fileSize)];
	if (!pSrcData) {
		printf("[-] Memory allocating failed\n");
		file.close();
		return false;
	}

	file.seekg(0, std::ios::beg);
	file.read(reinterpret_cast<char*>(pSrcData), fileSize);
	file.close();



	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) // 0x5A4D == MZ (little endian)
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
		printf("[-] Invalid platform\n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
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
			printf("[-] Memory allocation failed (VirtualAllocEx) 0x%X\n", GetLastError());
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
				printf("[-] Can't map sections: 0x%X\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, &mapData, sizeof(mapData));
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	void * pShellcode = VirtualAllocEx(
		hProc,
		nullptr,
		0x1000,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		printf("[-] Memory allocation failed (ex) 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}		

	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr);

	HANDLE hThread = CreateRemoteThread(
		hProc, 
		nullptr, 
		0, 
		reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode),
		pTargetBase,
		0,
		nullptr);

	if (!hThread) {
		printf("[-] Thread creation failed (ex) 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);
	
	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		printf("[+] checking data\n");
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	return true;
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


#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA * pData)
{
	if (!pData)
		return;

	BYTE * pBase = reinterpret_cast<BYTE*>(pData);
	auto * pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(
		pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE * LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto * pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD * pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR * pPatch = reinterpret_cast<UINT_PTR*>(
						pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));

					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto * pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
			pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescr->Name)
		{
			char * szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR * pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR * pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto * pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto * pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
