#include "pch.h"

#include <Windows.h>

DWORD __stdcall Thread(void* pParam)
{
	DWORD dwBase = 0x50F4F4;
	DWORD ofHealth = 0xF8;
	DWORD ofPistolAmmo = 0x13C;
	DWORD ofRifleAmmo = 0x150;

	bool bHealth = true;
	bool bPistolAmmo = true;
	bool bRifleAmmo = true;

	while (true)
	{
		if (GetAsyncKeyState(VK_F1) & 1)
			bHealth = !bHealth;

		if (GetAsyncKeyState(VK_F2) & 1)
			bPistolAmmo = !bPistolAmmo;

		if (GetAsyncKeyState(VK_F3) & 1)
			bRifleAmmo = !bRifleAmmo;

		DWORD dwBuffer = *(DWORD*)dwBase;
		if (dwBuffer)
		{
			if (bHealth)
				*(DWORD*)(dwBuffer + ofHealth) = 1337;

			if (bPistolAmmo)
				*(DWORD*)(dwBuffer + ofPistolAmmo) = 1337;

			if (bRifleAmmo)
				*(DWORD*)(dwBuffer + ofRifleAmmo) = 1337;
		}
	}
}

BOOL __stdcall DllMain(HINSTANCE hDll, DWORD dwReason, void* pReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
	}
	return TRUE;
}