#pragma once
#include "JonMon-Lite-Global.h"


struct JonMon_Lite_Config
{
	std::wstring TraceName;
	std::wstring XMLFilePath;
	std::wstring ETLFilePath;
	std::wstring RootFilePath;
	std::vector<std::wstring> WorkstationName;
	std::wstring User;
	std::wstring Password;
};

struct Create_Collector_Set
{
	std::wstring TraceName;
	std::wstring XMLFilePath;
	std::wstring RootFilePath;
	std::wstring WorkstationName;
	std::wstring User;
	std::wstring Password;
};




VOID CALLBACK InputConoleCallback
(
	_In_ PTP_CALLBACK_INSTANCE Instance,
	_In_ PVOID Callback,
	_In_ PTP_WORK Work
);


VOID CALLBACK ProcessingThreadCallback
(
	_In_ PTP_CALLBACK_INSTANCE Instance,
	_In_ PVOID Context,
	_In_ PTP_WORK Work
);

VOID ParseConfig(
	_In_ std::wstring ConfigFile,
	_Out_ JonMon_Lite_Config* Config
);
