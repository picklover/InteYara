#pragma once
#include <windows.h>
#include <tlhelp32.h>
DWORD getPid(const char* lpProcessName)//根据进程名查找进程PID 
{
	DWORD dwRet = 0;
	HANDLE hSnapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE)
		return dwRet;
	PROCESSENTRY32 pe32;//声明进程入口对象 
	pe32.dwSize = sizeof(PROCESSENTRY32);//填充进程入口对象大小 
	::Process32First(hSnapShot, &pe32);//遍历进程列表 
	do
	{
		if (!lstrcmp(pe32.szExeFile, (LPCSTR)lpProcessName))//查找指定进程名的PID 
		{
			dwRet = pe32.th32ProcessID;
			break;
		}
	} while (::Process32Next(hSnapShot, &pe32));
	::CloseHandle(hSnapShot);
	return dwRet;
}