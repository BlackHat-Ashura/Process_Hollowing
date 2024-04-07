
#ifndef HOLLOWPROCESS_HPP
#define HOLLOWPROCESS_HPP

typedef NTSTATUS(WINAPI* NtUnmapViewOfSection_t)(HANDLE hProcess, LPVOID section);

void HollowProcess(PROCESS_INFORMATION* ppi, LPVOID actualProcessContent);

#endif