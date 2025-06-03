#pragma once
#include "JonMon-Lite-Global.h"
#include <tdh.h>
#pragma comment(lib, "tdh.lib")



static GUID RPC_Provider = { 0x6ad52b32, 0xd609, 0x4be9, { 0xae, 0x07, 0xce, 0x8d, 0xae, 0x93, 0x7e, 0x39 } };
static GUID Network_Provider = { 0x7DD42A49,0x5329,0x4832,{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88} };
static GUID DotNet_Provider = { 0xe13c0d23, 0xccbc, 0x4e12, { 0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4 } };
static GUID AMSI_Provider = { 0x2a576b87, 0x09a7, 0x520e, { 0xc2, 0x1a, 0x49, 0x42, 0xf0, 0x27, 0x1d, 0x67 } };
static GUID WMIActivty_Provider = { 0x1418ef04, 0xb0b4, 0x4623, { 0xbf, 0x7e, 0xd7, 0x4a, 0xb4, 0x7b, 0xbd, 0xaa } };
static GUID DPAPI_Provider = { 0x89fe8f40, 0xcdce, 0x464e, { 0x82, 0x17, 0x15, 0xef, 0x97, 0xd4, 0xc7, 0xc3 } };
static GUID Registry_Provider = { 0x70eb4f03, 0xc1de, 0x4f73, { 0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd } };
static GUID Process_Provider = { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };
static GUID File_Provider = { 0xedd08927, 0x9cc4, 0x4e65, { 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89 } };
static GUID Service_Control_Manager_Provider = { 0x555908d1, 0xa6d7, 0x4695, { 0x8e, 0x1e, 0x26, 0x93, 0x1d, 0x20, 0x12, 0xf4 } };

VOID StartCollector(
	_In_ Etw_Processing* processingInfo
);

VOID TrimToMaxSize();

ULONGLONG CreateEventHash(
    _In_ PEVENT_RECORD pEvent
);

VOID WINAPI ProcessEvents(
	_In_ PEVENT_RECORD pEvent
);

NTSTATUS EtwEventProcessing(
    _In_ PEVENT_RECORD EventRecord,
    _Out_ PTRACE_EVENT_INFO* ppInfo,
    _Out_ BYTE*** ppPropertyDataVector
);

NTSTATUS ProcessEtwProperties(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PTRACE_EVENT_INFO PropertyInfo,
    _In_ BYTE** EventData
);

NTSTATUS WriteDotNetEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);

BOOL WriteAMSIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);

NTSTATUS WriteWMIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);

NTSTATUS WriteNetworkEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);

NTSTATUS WriteRpcEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName,
    _In_ INT32 EventType
);

NTSTATUS WriteDpapiEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);

NTSTATUS WriteFileEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);

NTSTATUS WriteRegistryEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);

NTSTATUS WriteProcessCreationEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);

NTSTATUS WriteServiceEvent(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
);