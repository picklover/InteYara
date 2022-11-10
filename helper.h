#pragma once
#include <windows.h>
#include <tlhelp32.h>
DWORD getPid(const char* lpProcessName)//���ݽ��������ҽ���PID 
{
	DWORD dwRet = 0;
	HANDLE hSnapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE)
		return dwRet;
	PROCESSENTRY32 pe32;//����������ڶ��� 
	pe32.dwSize = sizeof(PROCESSENTRY32);//��������ڶ����С 
	::Process32First(hSnapShot, &pe32);//���������б� 
	do
	{
		if (!lstrcmp(pe32.szExeFile, (LPCSTR)lpProcessName))//����ָ����������PID 
		{
			dwRet = pe32.th32ProcessID;
			break;
		}
	} while (::Process32Next(hSnapShot, &pe32));
	::CloseHandle(hSnapShot);
	return dwRet;
}

void CreateNotepadProcess()
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	TCHAR szCommandLine[] = TEXT("notepad.exe");
	CreateProcess(NULL, szCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}