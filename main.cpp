#include <Windows.h>
#include "memhack.h"
#include "patternscan.h"
#include "processtools.h"

int main()
{
	DWORD processID = GetProcId(L"ac_client.exe");

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

	void* healthDecAddress = PatternScannExModule(hProcess, (wchar_t*)L"ac_client.exe", (wchar_t*)L"ac_client.exe", (char*)"\x29\x7b\x00\x8b\xc7", (char*)"xx?xx");

	NopEx(hProcess, healthDecAddress, 5);

	return 0;
}