#include "JonMon-Lite-Global.h"
#include "JonMon-Lite-Creation.h"
#include "JonMon-Lite-Collector.h"
#include "JonMon-Lite.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <iostream>

using json = nlohmann::json;

BOOL g_Process = TRUE;

HANDLE programExit = NULL;
HANDLE finishJobs = NULL;

VOID ParseConfig(
	_In_ std::wstring ConfigFile,
	_Out_ JonMon_Lite_Config* Config
)
{
	std::ifstream jsonFile(ConfigFile.c_str());
	if (!jsonFile.is_open()) {
		wprintf(L"Failed to open file: %s\n", ConfigFile.c_str());
		return;
	}

	json jsonData;
	jsonFile >> jsonData;

	std::string tempXMLFilePath = jsonData["XMLFilePath"].get<std::string>();
	Config->XMLFilePath = std::wstring(tempXMLFilePath.begin(), tempXMLFilePath.end());

	std::string tempRootFilePath = jsonData["RootPath"].get<std::string>();
	Config->RootFilePath = std::wstring(tempRootFilePath.begin(), tempRootFilePath.end());

	std::string tempTraceName = jsonData["TraceName"].get<std::string>();
	Config->TraceName = std::wstring(tempTraceName.begin(), tempTraceName.end());

	std::vector<std::string> tempWorkstationNames = jsonData["WorkstationName"].get<std::vector<std::string>>();
	for (const auto& name : tempWorkstationNames) {
		Config->WorkstationName.push_back(std::wstring(name.begin(), name.end()));
	}

	std::string tempUser = jsonData["User"].get<std::string>();
	Config->User = std::wstring(tempUser.begin(), tempUser.end());

	std::string tempPassword = jsonData["Password"].get<std::string>();
	Config->Password = std::wstring(tempPassword.begin(), tempPassword.end());

	std::string tempETLFilePath = jsonData["ETLFilePath"].get<std::string>();
	Config->ETLFilePath = std::wstring(tempETLFilePath.begin(), tempETLFilePath.end());
	
	return;
}

VOID CALLBACK ProcessingThreadCallback
(
	_In_ PTP_CALLBACK_INSTANCE Instance,
	_In_ PVOID Context,
	_In_ PTP_WORK Work
)
{
	Etw_Processing* config = static_cast<Etw_Processing*>(Context);

	StartCollector(config);

Exit:

	wprintf(L"Cleaning up ProcessingThreadCallback\n");
	delete config;
	return;
}

DWORD UninstallManifest() {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD result = 0;
	wchar_t cmdLine[] = L"C:\\Windows\\System32\\wevtutil.exe um JonMon-Lite-Provider.man";

	EventUnregisterJonMon_Lite();

	printf("Uninstalling ETW Manifest\n");

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		result = GetLastError();
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	DeleteFileW(L"C:\\Windows\\JonMon-Lite-Provider.dll");

Exit:
	if (pi.hProcess)
	{
		CloseHandle(pi.hProcess);
	}
	if (pi.hThread) 
	{
		CloseHandle(pi.hThread);
	}
	return result;
}

DWORD InstallManifest() {
	STARTUPINFOW si{};
	PROCESS_INFORMATION pi{};
	BOOL FileCopy = FALSE;
	DWORD result = UninstallManifest();
	wchar_t cmdLine[] = L"C:\\Windows\\System32\\wevtutil.exe im JonMon-Lite-Provider.man";

	
	printf("Installing ETW Manifest\n");
	FileCopy = CopyFileW(L"JonMon-Lite-Provider.dll", L"C:\\Windows\\JonMon-Lite-Provider.dll", FALSE);
	if (FileCopy == FALSE) {
		printf("[-] JonMon-Lite-Provider.dll did not copy to C:\\Windows\\JonMon-Lite-Provider.dll\n");
		printf("error: %d", GetLastError());
		result = 1;
		goto Exit;
	}

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		result = GetLastError();
	}
	result = 0;
	WaitForSingleObject(pi.hProcess, INFINITE);

	EventRegisterJonMon_Lite();

Exit:
	if (pi.hProcess)
	{
		CloseHandle(pi.hProcess);
	}
	if (pi.hThread)
	{
		CloseHandle(pi.hThread);
	}
	return result;
}

VOID CALLBACK CollectionCreationCallback
(
	_In_ PTP_CALLBACK_INSTANCE Instance,
	_In_ PVOID Context,
	_In_ PTP_WORK Work
)
{
	Create_Collector_Set* config = static_cast<Create_Collector_Set*>(Context);

	CreateCollectorSet(
		config->WorkstationName.c_str(),
		config->TraceName.c_str(),
		config->XMLFilePath.c_str(),
		config->RootFilePath.c_str(),
		config->User.c_str(),
		config->Password.c_str()
	);

Exit:
	wprintf(L"Cleaning up CollectionCreationCallback\n");
	delete config;
	return;
}

int wmain(int argc, wchar_t* argv[])
{
	std::wstring ConfigFilePath = L"JonMon-Lite.json";
	NTSTATUS status = ERROR_SUCCESS;
	PTP_POOL processesingPool = NULL;
	TP_CALLBACK_ENVIRON processesingPoolEnv;
	PTP_WORK processessingWork, collectionWork;
	PTP_CLEANUP_GROUP cleanupGroup = NULL;
	DWORD waitResult, manifestResult;
	std::wstring uncPath;


	programExit = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (programExit == NULL)
	{
		wprintf(L"Error creating synchronization object: %d\n", GetLastError());
		return GetLastError();
	}

	finishJobs = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (programExit == NULL)
	{
		wprintf(L"Error creating synchronization object: %d\n", GetLastError());
		return GetLastError();
	}

	if (argc == 2)
	{
		ConfigFilePath = argv[1];
	}

	JonMon_Lite_Config* config = new JonMon_Lite_Config();


	wprintf(L"Reading JonMon-Lite Config File...\n\n");

	ParseConfig(ConfigFilePath, config);

	manifestResult = InstallManifest();
	if (manifestResult != 0)
	{
		wprintf(L"Manifest installation failed...exiting\n");
		goto Exit;
	}

	//
	// Creating thread pool to handle processing
	//
	processesingPool = CreateThreadpool(NULL);

	InitializeThreadpoolEnvironment(&processesingPoolEnv);

	SetThreadpoolThreadMaximum(processesingPool, 5);
	if (!SetThreadpoolThreadMinimum(processesingPool, 3))
	{
		wprintf(L"Error with SetThreadpoolThreadMinimum %d\n", GetLastError());
		goto Exit;
	}

	SetThreadpoolCallbackPool(&processesingPoolEnv, processesingPool);

	cleanupGroup = CreateThreadpoolCleanupGroup();
	if (cleanupGroup == NULL)
	{
		wprintf(L"Error setting up cleanupGroup: %d\n", GetLastError());
		goto Exit;
	}

	SetThreadpoolCallbackCleanupGroup(&processesingPoolEnv, cleanupGroup, NULL);

	for (const auto& workstationName : config->WorkstationName)
	{
		std::wstring* etlFilePath = new std::wstring(config->ETLFilePath + workstationName + L"_\\JonMon-Lite.etl");

		wprintf(L"XMLFilePath: %s\n", config->XMLFilePath.c_str());
		wprintf(L"TraceName: %s\n", config->TraceName.c_str());
		wprintf(L"ETLFilePath %s\n", config->ETLFilePath.c_str());
		wprintf(L"RootPath: %s\n", config->RootFilePath.c_str());
		wprintf(L"WorkstationName: %s\n", workstationName.c_str());
		wprintf(L"User: %s\n", config->User.c_str());
		wprintf(L"Password: %s\n\n", config->Password.c_str());


		Create_Collector_Set* tempConfig = new Create_Collector_Set
		{
			config->TraceName,
			config->XMLFilePath,
			config->RootFilePath,
			workstationName,
			config->User,
			config->Password
		};


		collectionWork = CreateThreadpoolWork(CollectionCreationCallback, (PVOID)tempConfig, &processesingPoolEnv);
		if (collectionWork == NULL) {
			wprintf(L"CreateThreadpoolWork failed %d\n", GetLastError());
			delete tempConfig;
			delete etlFilePath;
			goto Exit;
		}

		SubmitThreadpoolWork(collectionWork);

		Etw_Processing* tempProcessing = new Etw_Processing
		{
			etlFilePath->c_str(),
			workstationName,
		};
		
		processessingWork = CreateThreadpoolWork(ProcessingThreadCallback, (PVOID)tempProcessing, &processesingPoolEnv);
		if (processessingWork == NULL) {
			wprintf(L"CreateThreadpoolWork failed %d\n", GetLastError());
			delete etlFilePath;
			delete tempProcessing;
			goto Exit;
		}

		SubmitThreadpoolWork(processessingWork);
	}

	processessingWork = CreateThreadpoolWork(InputConoleCallback, NULL, &processesingPoolEnv);
	if (processessingWork == NULL) {
		wprintf(L"CreateThreadpoolWork failed %d\n", GetLastError());
		goto Exit;
	}

	SubmitThreadpoolWork(processessingWork);

	waitResult = WaitForSingleObject(programExit, INFINITE);
	if (waitResult == WAIT_OBJECT_0) {
		goto Exit;
	}
	else {
		wprintf(L"WaitForSingleObject failed %d\n", GetLastError());
		goto Exit;
	}

Exit:
	SetEvent(finishJobs);


	//
	// create secondary wait
	//
	wprintf(L"Moving to cleanup...\n");

	g_Process = FALSE;

	if (cleanupGroup)
	{
		CloseThreadpoolCleanupGroupMembers(cleanupGroup, TRUE, NULL);
		CloseThreadpoolCleanupGroup(cleanupGroup);
	}

	if (&processesingPoolEnv) {
		DestroyThreadpoolEnvironment(&processesingPoolEnv);
	}

	if (processesingPool)
	{
		CloseThreadpool(processesingPool);
	}
	if (config)
	{
		delete config;
	}
	if (finishJobs != NULL) {
		CloseHandle(finishJobs);
	}

	if (programExit != NULL) {
		CloseHandle(programExit);
	}

	manifestResult = UninstallManifest();
	if (manifestResult != 0)
	{
		wprintf(L"Manifest did not uninstall\n");
	}

	wprintf(L"Cleanup complete\n");

    return 0;
}

VOID CALLBACK InputConoleCallback
(
	_In_ PTP_CALLBACK_INSTANCE Instance,
	_In_ PVOID Callback,
	_In_ PTP_WORK Work
) {
	BOOL exit_program = FALSE;
	while (!exit_program) {
		std::wstring input;
		std::wcin >> input;
		if (input == L"exit" || input == L"stop")
		{
			exit_program = TRUE;
			SetEvent(programExit);
			return;
		}
	}
	return;
}