#pragma once
#include <Windows.h>
#include <pla.h>
#include <string>
#include <stdio.h>
#include <vector>
#include ".\ETWProvider\JonMon-Lite-Provider.h"

struct Etw_Processing
{
	std::wstring ETLFilePath;
	std::wstring WorkstationName;
};

extern BOOL g_Process;

extern HANDLE programExit;

extern HANDLE finishJobs;