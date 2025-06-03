#pragma once
#include "JonMon-Lite-Global.h"

VOID CreateCollectorSet(
	_In_ LPCWSTR workstationName,
	_In_ LPCWSTR collectorSetName,
	_In_ LPCWSTR xmlFilePath,
	_In_ LPCWSTR rootPath,
	_In_ LPCWSTR userName,
	_In_ LPCWSTR userPassword
);


std::wstring ReadXmlFile(
	const wchar_t* filePath
);