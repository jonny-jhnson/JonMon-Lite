#include <ws2tcpip.h>
#include "JonMon-Lite-Global.h"
#include "JonMon-Lite.h"
#include "JonMon-Lite-Collector.h"
#include <evntrace.h> 
#include <evntcons.h>
#include <thread>
#include <unordered_set>
#include <deque>
#include <regex>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

//
// Using thread_local so that each thread gets its own instance of the global variable
//
thread_local std::deque<ULONGLONG> g_EventOrder;
thread_local std::unordered_set<ULONGLONG> g_EventHashes;

const size_t MAX_CONTAINER_SIZE = 2000000;

//
// Main Processing Functions
//
VOID StartCollector(
    _In_ Etw_Processing* processingInfo
)
{
    DWORD waitResult;
    TRACEHANDLE hTrace = NULL;
    printf("Processing events...\n");


    ULONG status;
    EVENT_TRACE_LOGFILEW logfile = { 0 };
    DWORD fileAttrib;

    fileAttrib = GetFileAttributesW(processingInfo->ETLFilePath.c_str());
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"ETL file not found: %ls, waiting 4 seconds...\n", processingInfo->ETLFilePath.c_str());

        waitResult = WaitForSingleObject(finishJobs, 4000);
        if (waitResult == WAIT_OBJECT_0) {
            wprintf(L"Shutdown signaled while waiting for file: %ls\n", processingInfo->ETLFilePath.c_str());
            goto Exit;
        }
    }
    while (g_Process) {
        logfile.LogFileName = (LPWSTR)processingInfo->ETLFilePath.c_str();
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | EVENT_TRACE_FILE_MODE_CIRCULAR;
        logfile.EventRecordCallback = ProcessEvents;
        logfile.Context = processingInfo;

        hTrace = OpenTraceW(&logfile);
        if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
            printf("Failed to open trace file. Error: %lu\n", GetLastError());
            goto Exit;
        }

        status = ProcessTrace(&hTrace, 1, NULL, NULL);
        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
            printf("Failed to process trace. Error: %lu\n", status);
            goto Exit;
        }

        CloseTrace(hTrace);
        hTrace = NULL;

        waitResult = WaitForSingleObject(finishJobs, 1000);
        if (waitResult == WAIT_TIMEOUT) {

        }
        else if (waitResult == WAIT_OBJECT_0) {
            printf("Shutdown signaled, exiting wait...\n");
            goto Exit;
        }
    }

Exit:
    if (hTrace != NULL && hTrace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(hTrace);
    }
    return;
}


//
// Processes events in ETL
//
VOID WINAPI ProcessEvents(
    _In_ PEVENT_RECORD pEvent
) {
    PEVENT_HEADER eventHeader = &pEvent->EventHeader;
    PEVENT_DESCRIPTOR eventDescriptor = &eventHeader->EventDescriptor;
    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = NULL;
    DWORD bufferSize = 0;

    //
    // Creating unique event hash for tracking
    //
    ULONGLONG hash = CreateEventHash(pEvent);

    //
    // If hash has been seen - return
    //
    if (g_EventHashes.count(hash) > 0) {
        return;
    }

    //
    // Add to unordered set and double-ended queue
    //
    g_EventOrder.push_back(hash);
    g_EventHashes.insert(hash);

    //
    // Adjusting so that size doesn't exceed max
    //
    TrimToMaxSize();

    Etw_Processing* processingInfo = (Etw_Processing*)pEvent->UserContext;
    if (!processingInfo)
    {
        wprintf(L"Error getting UserContext\n");
        return;
    }

    if (eventHeader->ProviderId == DotNet_Provider) {
        switch (eventDescriptor->Id) {
        case 154: {
            status = WriteDotNetEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing DotNet Events\n");
            }
            break;
        }
        default: {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == Network_Provider)
    {
        switch (eventDescriptor->Id) {
        case 10:
        case 11:
        {
            status = WriteNetworkEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing Network Events\n");
            }
            break;
        }
        default:
        {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == Registry_Provider)
    {
        switch (eventDescriptor->Id) {
        case 1:
        {
            // removing due to noise
            status = WriteRegistryEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing Service Control Manager Provider Events\n");
            }
            break;
        }
        default:
        {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == Service_Control_Manager_Provider)
    {
        switch (eventDescriptor->Id) {
        case 7045:
        {
            status = WriteServiceEvent(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing Service Control Manager Provider Events\n");
            }
            break;
        }
        default:
        {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == File_Provider)
    {
        switch (eventDescriptor->Id) {
        case 30:
        {
            status = WriteFileEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing File Events\n");
            }
            break;
        }
        default:
        {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == Process_Provider)
    {
        switch (eventDescriptor->Id) {
        case 1:
        {
            status = WriteProcessCreationEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing Process Creation Events\n");
            }
            break;
        }
        default:
        {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == DPAPI_Provider)
    {
        switch (eventDescriptor->Id) {
        case 16385: {
            status = WriteDpapiEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing DPAPI Events\n");
            }
            break;
        }
        default: {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == WMIActivty_Provider) {
        switch (eventDescriptor->Id) {
        case 5861:
        {
            status = WriteWMIEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing WMI Events\n");
            }
            break;
        }
        default:
        {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == RPC_Provider) {
        switch (eventDescriptor->Id) {
        case 5:
        {
            status = WriteRpcEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str(), 0); // 0 == CLIENT
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing RPC Events\n");
            }

            break;
        }
        case 6:
        {
            status = WriteRpcEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str(), 1); // 1 == SERVER
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing RPC Events\n");
            }
            break;
        }
        default: {
            break;
        }

        }
    }
    if (eventHeader->ProviderId == AMSI_Provider) {
        switch (eventDescriptor->Id) {
        case 1101:
        {
            status = WriteAMSIEvents(pEvent, eventHeader, (LPWSTR)processingInfo->WorkstationName.c_str());
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing AMSI Events\n");
            }
            break;
        }
        default:
        {
            break;
        }


        }
    }
}

//
// Helper Functions
//

//
// Creating unique event hash using Provider GUID, ThreadId, ProcessId, and Timestamp
//
ULONGLONG CreateEventHash(
    _In_ PEVENT_RECORD pEvent
) {
    ULONGLONG hash = pEvent->EventHeader.TimeStamp.QuadPart;
    hash ^= ((ULONGLONG)pEvent->EventHeader.EventDescriptor.Id << 32);
    hash ^= ((ULONGLONG)pEvent->EventHeader.ThreadId << 16);
    hash ^= pEvent->EventHeader.ProcessId;

    ULONGLONG* guid = (ULONGLONG*)&pEvent->EventHeader.ProviderId;
    hash ^= guid[0] ^ guid[1];

    return hash;
}

//
// Triming container to proper size
//
VOID TrimToMaxSize() {
    while (g_EventOrder.size() > MAX_CONTAINER_SIZE) {
        ULONGLONG oldestHash = g_EventOrder.front();
        g_EventOrder.pop_front();
        g_EventHashes.erase(oldestHash);
    }
}

//
// ETW Event Processing Helper Functions
//
NTSTATUS EtwEventProcessing(
    _In_ PEVENT_RECORD EventRecord,
    _Out_ PTRACE_EVENT_INFO* ppInfo,
    _Out_ BYTE*** ppPropertyDataVector
) {
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;

    //
    // Get event information
    //
    status = TdhGetEventInformation(EventRecord, 0, nullptr, nullptr, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (!pInfo) {
            OutputDebugString(L"Error allocating memory for event info\n");
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        status = TdhGetEventInformation(EventRecord, 0, nullptr, pInfo, &bufferSize);
    }
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error fetching event info\n");
        if (pInfo) free(pInfo);
        return status;
    }

    //
    // Allocate property data vector
    //
    propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
    if (!propertyDataVector) {
        OutputDebugString(L"Error allocating memory for propertyDataVector\n");
        free(pInfo);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    //
    // Process the event
    //
    status = ProcessEtwProperties(EventRecord, pInfo, propertyDataVector);
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error processing ETW event\n");
        free(pInfo);
        free(propertyDataVector);
        return status;
    }

    *ppInfo = pInfo;
    *ppPropertyDataVector = propertyDataVector;
    return ERROR_SUCCESS;
}

NTSTATUS ProcessEtwProperties(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PTRACE_EVENT_INFO PropertyInfo,
    _In_ BYTE** EventData
) {
    NTSTATUS status = ERROR_SUCCESS;
    int vectorSize = 0;

    //
    // Process each property in the event
    //
    for (ULONG i = 0; i < PropertyInfo->TopLevelPropertyCount; i++) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        DWORD propertySize = 0;
        WCHAR* propertyName = (WCHAR*)((BYTE*)PropertyInfo + PropertyInfo->EventPropertyInfoArray[i].NameOffset);
        dataDescriptor.PropertyName = (ULONGLONG)propertyName;
        dataDescriptor.ArrayIndex = ULONG_MAX;

        //
        // Determine the size of the property
        //
        status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error getting size for property\n");
            goto Exit;
        }

        BYTE* propertyData = (BYTE*)malloc(propertySize);
        if (!propertyData) {
            OutputDebugString(L" Error allocating memory for propertyData\n");
            goto Exit;
        }

        //
        // Get the actual property data
        //
        status = TdhGetProperty(EventRecord, 0, NULL, 1, &dataDescriptor, propertySize, propertyData);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error getting data for property\n");
            goto Exit;
        }

        //
        // Add the data to the vector
        //
        EventData[vectorSize++] = propertyData;

        if (vectorSize > PropertyInfo->TopLevelPropertyCount) {
            OutputDebugString(L"Error: vectorSize exceeded allocated EventData size\n");
            status = ERROR_BUFFER_OVERFLOW;
            goto Exit;
        }
    }

Exit:
    if (status != ERROR_SUCCESS) {
        for (int i = 0; i < vectorSize; i++) {
            if (EventData[i] != nullptr) {
                free(EventData[i]);
            }
        }
    }
    return status;

}

//
// Specific Event Processing Function
//
BOOL WriteAMSIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {

    UINT_PTR Session;
    UINT8 ScanStatus;
    UINT32 ScanResult, ContentSize, OriginalSize;
    std::wstring AppName, ContentName, decodedString;
    BYTE* Content;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    SYSTEMTIME systemTime;
    BYTE** propertyDataVector = nullptr;
    FILETIME fileTime;

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    Session = *(ULONG64*)propertyDataVector[0];
    ScanStatus = *(UINT8*)propertyDataVector[1];
    ScanResult = *(UINT32*)propertyDataVector[2];
    AppName = (WCHAR*)propertyDataVector[3];

    if (AppName != L"VBScript" && AppName != L"JScript" && AppName != L"OFFICE_VBA" && AppName != L"Excel" && AppName != L"Excel.exe")
    {
        goto Exit;
    }

    ContentName = (WCHAR*)propertyDataVector[4];
    ContentSize = *(UINT32*)propertyDataVector[5];
    OriginalSize = *(UINT32*)propertyDataVector[6];
    Content = (BYTE*)propertyDataVector[7];

    if (ScanResult != (UINT32)1 && ScanResult != (UINT32)32768) {
        goto Exit;
    }

    decodedString = std::wstring(reinterpret_cast<const wchar_t*>(Content), ContentSize / sizeof(wchar_t));

    EventWriteAMSI(
        &systemTime,
        WorkstationName,
        EventHeader->ProcessId,
        AppName.c_str(),
        ContentName.c_str(),
        ScanStatus,
        ScanResult,
        ContentSize,
        Content,
        decodedString.c_str()
    );

Exit:
    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }
    return TRUE;
}

NTSTATUS WriteRpcEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName,
    _In_ INT32 EventType
) {
    PEVENT_HEADER_EXTENDED_DATA_ITEM extendedData = EventRecord->ExtendedData;
    wchar_t szInterfaceUUID[64] = { 0 };
    GUID interfaceUUID;
    UINT32 procNum, protocol, authenticationLevel, authenticationService, impersonationLevel;
    std::wstring networkAddress, endpoint, options, methodString, interfaceString;
    int result;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    SYSTEMTIME systemTime;
    FILETIME fileTime;
    BYTE** propertyDataVector = nullptr;

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    interfaceUUID = *(GUID*)propertyDataVector[0];
    procNum = *(UINT32*)propertyDataVector[1];
    protocol = *(UINT32*)propertyDataVector[2];
    networkAddress = (WCHAR*)propertyDataVector[3];
    endpoint = (WCHAR*)propertyDataVector[4];
    options = (WCHAR*)propertyDataVector[5];
    authenticationLevel = *(UINT32*)propertyDataVector[6];
    authenticationService = *(UINT32*)propertyDataVector[7];
    impersonationLevel = *(UINT32*)propertyDataVector[8];

    //
    // convert GUID to string
    //
    result = StringFromGUID2(interfaceUUID, szInterfaceUUID, 64);
    if (result == 0) {
        OutputDebugString(L"Error converting GUID to string\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //MS-SCMR {367ABB81-9844-35F1-AD32-98F038001003}
    if (wcscmp(szInterfaceUUID, L"{367ABB81-9844-35F1-AD32-98F038001003}") == 0) {
        interfaceString = L"MS-SCMR";
        switch (procNum)
        {
        case 12:
        {
            methodString = L"RCreateServiceW";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }

    //MS-DRSR {E3514235-4B06-11D1-AB04-00C04FC2DCD2}
    if (wcscmp(szInterfaceUUID, L"{E3514235-4B06-11D1-AB04-00C04FC2DCD2}") == 0) {
        interfaceString = L"MS-DRSR";
        switch (procNum) {
        case 3:
        {
            methodString = L"GetNCChanges";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        default: {
            goto Exit;
        }
        }
        goto Exit;
    }

    //MS-RRP {338CD001-2244-31F1-AAAA-900038001003}
    if (wcscmp(szInterfaceUUID, L"{338CD001-2244-31F1-AAAA-900038001003}") == 0) {
        interfaceString = L"MS-RRP";
        switch (procNum) {
        case 6:
        {
            methodString = L"BaseRegCreateKey";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        case 22:
        {
            methodString = L"BaseRegSetValue";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }

    //MS-SRVS {4B324FC8-1670-01D3-1278-5A47BF6EE188}
    if (wcscmp(szInterfaceUUID, L"{4B324FC8-1670-01D3-1278-5A47BF6EE188}") == 0) {
        interfaceString = L"MS-SRVS";
        switch (procNum) {
        case 12:
        {
            methodString = L"NetrSessionEnum";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }

    //MS-RPRN {12345678-1234-ABCD-EF00-0123456789AB}
    if (wcscmp(szInterfaceUUID, L"{12345678-1234-ABCD-EF00-0123456789AB}") == 0) {
        interfaceString = L"MS-RPRN";
        switch (procNum) {
        case 89:
        {
            methodString = L"RpcAddPrinterDriverEx";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            break;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }

    //MS-PAR 76F03F96-CDFD-44FC-A22C-64950A001209
    if (wcscmp(szInterfaceUUID, L"{76F03F96-CDFD-44FC-A22C-64950A001209}") == 0) {
        interfaceString = L"MS-PAR";
        switch (procNum) {
        case 39:
        {
            methodString = L"RpcAsyncAddPrinterDriver";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }

    // MS-EFSR {D9A0A0C0-150F-11D1-8C7A-00C04FC297EB} || {C681D488-D850-11D0-8C52-00C04FD90F7E}"
    if ((wcscmp(szInterfaceUUID, L"{C681D488-D850-11D0-8C52-00C04FD90F7E}") == 0) ||
        (wcscmp(szInterfaceUUID, L"{DF1941C5-FE89-4E79-BF10-463657ACF44D}") == 0)) {
        interfaceString = L"MS-EFSR";
        switch (procNum) {
        case 0:
        {
            methodString = L"EfsRpcOpenFileRaw";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        case 4:
        {
            methodString = L"EfsRpcEncryptFileSrv";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                wprintf(L"RPC Server Event\n");
                wprintf(L"SystemTime: %02d:%02d\n", systemTime.wHour, systemTime.wMinute);
                wprintf(L"InterfaceUUID: %s\n", szInterfaceUUID);
                wprintf(L"Interface String: %s\n", interfaceString.c_str());
                wprintf(L"Method String: %s\n", methodString.c_str());
                wprintf(L"procNum: %lu\n", procNum);
                wprintf(L"protocol: %lu\n", protocol);
                wprintf(L"networkAddress: %s\n", networkAddress.c_str());
                wprintf(L"endpoint: %s\n", endpoint.c_str());
                wprintf(L"options: %s\n", options.c_str());
                wprintf(L"authenticationLevel: %lu\n", authenticationLevel);
                wprintf(L"authenticationService: %lu\n", authenticationService);
                wprintf(L"impersonationLevel: %lu\n", impersonationLevel);

                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        case 5:
        {
            methodString = L"EfsRpcDecryptFileSrv";
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    WorkstationName,
                    EventHeader->ProcessId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str()
                );
                break;
            }
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }

Exit:
    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

NTSTATUS WriteNetworkEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;
    SYSTEMTIME systemTime;
    UINT32 processId, size, sourceAddress, destinationAddress;
    UINT16 sourcePort, destinationPort;
    WCHAR wide_deststring_ip[INET_ADDRSTRLEN];
    WCHAR wide_sourcestring_ip[INET_ADDRSTRLEN];
    struct in_addr srceaddr = {};
    struct in_addr destaddr = {};
    BOOL isInitiated = false;
    FILETIME fileTime;

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    processId = *(UINT32*)propertyDataVector[0];

    if (processId == 4)
    {
        goto Exit;
    }

    size = *(UINT32*)propertyDataVector[1];
    destinationAddress = *(UINT32*)propertyDataVector[2];
    sourceAddress = *(UINT32*)propertyDataVector[3];
    sourcePort = *(UINT16*)propertyDataVector[4];
    destinationPort = *(UINT16*)propertyDataVector[5];


    if (EventHeader->EventDescriptor.Id == 10)
    {
        isInitiated = true;
        destaddr.s_addr = destinationAddress;
        srceaddr.s_addr = sourceAddress;
    }
    else if (EventHeader->EventDescriptor.Id == 11)
    {
        isInitiated = false;
        destaddr.s_addr = sourceAddress;
        srceaddr.s_addr = destinationAddress;

    }

    if (InetNtop(AF_INET, &srceaddr, wide_sourcestring_ip, INET_ADDRSTRLEN) == nullptr) {
        OutputDebugString(L"Error converting source IP address\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    if (InetNtop(AF_INET, &destaddr, wide_deststring_ip, INET_ADDRSTRLEN) == nullptr) {
        OutputDebugString(L"Error converting destination IP address\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    EventWriteNetworkConnection(
        &systemTime,
        WorkstationName,
        processId,
        wide_sourcestring_ip,
        wide_deststring_ip,
        sourcePort,
        destinationPort,
        isInitiated
    );


Exit:
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

NTSTATUS WriteProcessCreationEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {
    UINT64 ProcessSequenceNumber, ParentProcessSequenceNumber;
    UINT32 ProcessId, ParentProcessID, SessionID, Flags, ProcessTokenElevationType, ProcessTokenIsElevated, ImageCheckSum, TimeDataStamp, SecurityMitigations;
    UINT16 ClrInstanceID;
    std::wstring ImageName, PackageFullName, PackageRelativeAppId;
    SID MandatoryLabel;
    FILETIME CreateTime;
    SYSTEMTIME systemTime;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    ProcessId = *(UINT32*)propertyDataVector[0];
    ProcessSequenceNumber = *(UINT64*)propertyDataVector[1];
    CreateTime = *(FILETIME*)propertyDataVector[2];
    ParentProcessID = *(UINT32*)propertyDataVector[3];
    ParentProcessSequenceNumber = *(UINT64*)propertyDataVector[4];
    SessionID = *(UINT32*)propertyDataVector[5];
    Flags = *(UINT32*)propertyDataVector[6];
    ProcessTokenElevationType = *(UINT32*)propertyDataVector[7];
    ProcessTokenIsElevated = *(UINT32*)propertyDataVector[8];
    MandatoryLabel = *(SID*)propertyDataVector[9];
    ImageName = (WCHAR*)propertyDataVector[10];
    ImageCheckSum = *(UINT32*)propertyDataVector[11];
    TimeDataStamp = *(UINT32*)propertyDataVector[12];
    PackageFullName = (WCHAR*)propertyDataVector[13];
    PackageRelativeAppId = (WCHAR*)propertyDataVector[14];

    if (pInfo->TopLevelPropertyCount >= 16)
    {
        SecurityMitigations = *(UINT32*)propertyDataVector[15];
    }
    else
    {
        SecurityMitigations = 0;
    }

    if (!FileTimeToSystemTime(&CreateTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }


    EventWriteProcessCreation(
        &systemTime,
        WorkstationName,
        ProcessId,
        ParentProcessID,
        SessionID,
        Flags,
        ProcessTokenIsElevated,
        &MandatoryLabel,
        ImageName.c_str(),
        PackageFullName.c_str(),
        SecurityMitigations
    );


Exit:
    //
    // Free each element in propertyDataVector and the vector itself
    //
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

NTSTATUS WriteDotNetEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {
    UINT64 AssemblyID, AppDomainID, BindingID;
    UINT32 AssemblyFlags;
    UINT16 ClrInstanceID;
    std::wstring FQAN;
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    AssemblyID = *(UINT64*)propertyDataVector[0];
    AppDomainID = *(UINT64*)propertyDataVector[1];
    BindingID = *(UINT64*)propertyDataVector[2];
    AssemblyFlags = *(UINT32*)propertyDataVector[3];
    FQAN = (WCHAR*)propertyDataVector[4];
    ClrInstanceID = *(UINT16*)propertyDataVector[5];


    EventWriteDotNetLoad(
        &systemTime,
        WorkstationName,
        EventHeader->ProcessId,
        AssemblyID,
        AppDomainID,
        FQAN.c_str(),
        ClrInstanceID
    );


Exit:
    //
    // Free each element in propertyDataVector and the vector itself
    //
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

NTSTATUS WriteRegistryEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    switch (EventHeader->EventDescriptor.Id) {
        // Registry Key Creation
    case 1:
    {
        UINT_PTR BaseObject, KeyObject;
        UINT32 Status, Disposition;
        std::wstring BaseName, RelativeName;

        BaseObject = *(UINT_PTR*)propertyDataVector[0];
        KeyObject = *(UINT_PTR*)propertyDataVector[1];
        Status = *(UINT32*)propertyDataVector[2];
        Disposition = *(UINT32*)propertyDataVector[3];
        BaseName = (WCHAR*)propertyDataVector[4];
        RelativeName = (WCHAR*)propertyDataVector[5];

        EventWriteRegistryCreateKey(
            &systemTime,
            WorkstationName,
            BaseName.c_str(),
            RelativeName.c_str(),
            Disposition,
            Status
        );

        break;
    }
    // Registry Set Value
    case 5:
    {
        UINT_PTR KeyObject;
        UINT32 Status, Type, DataSize, PreviousDataType, PreviousDataSize;
        UINT16 CapturedDataSize, PreviousDataCapturedSize;
        std::wstring KeyName, ValueName, capturedDataString;
        BYTE* CapturedData;
        BYTE* PreviousData;

        KeyObject = *(UINT_PTR*)propertyDataVector[0];
        Status = *(UINT32*)propertyDataVector[1];
        Type = *(UINT32*)propertyDataVector[2];
        DataSize = *(UINT32*)propertyDataVector[3];
        KeyName = (WCHAR*)propertyDataVector[4];
        ValueName = (WCHAR*)propertyDataVector[5];
        CapturedDataSize = *(UINT16*)propertyDataVector[6];
        CapturedData = (BYTE*)propertyDataVector[7];
        PreviousDataType = *(UINT32*)propertyDataVector[8];
        PreviousDataSize = *(UINT32*)propertyDataVector[9];
        PreviousDataCapturedSize = *(UINT16*)propertyDataVector[10];
        PreviousData = (BYTE*)propertyDataVector[11];

        capturedDataString = std::wstring(reinterpret_cast<const wchar_t*>(CapturedData), CapturedDataSize / sizeof(wchar_t));

        //EventWriteRegistrySetValueKey(
        //    &systemTime,
        //    WorkstationName,
        //    KeyName.c_str(),
        //    ValueName.c_str(),
        //    capturedDataString.c_str(),
        //    Type
        //);

        break;
    }

    default:
    {
        break;
    }
    }

Exit:
    //
    // Free each element in propertyDataVector and the vector itself
    //
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

NTSTATUS WriteFileEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {
    UINT_PTR Irp, FileObject;
    UINT32 IssuingThreadId, CreateOptions, CreateAttributes, ShareAccess;
    std::wstring FileName;
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;
    bool hasValidExtension;
    static const std::wregex validExtensions(LR"((\.exe|\.sys|\.dll|\.js|\.vbs|\.ps1|\.bat|\.cmd|\.hta|\.msi)$)", std::regex_constants::icase);

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    Irp = *(UINT_PTR*)propertyDataVector[0];
    FileObject = *(UINT_PTR*)propertyDataVector[1];
    IssuingThreadId = *(UINT32*)propertyDataVector[2];
    CreateOptions = *(UINT32*)propertyDataVector[3];
    CreateAttributes = *(UINT32*)propertyDataVector[4];
    ShareAccess = *(UINT32*)propertyDataVector[5];
    FileName = (WCHAR*)propertyDataVector[6];

    //
    // Reducing noise by looking for certian extensions
    //
    hasValidExtension = std::regex_search(FileName, validExtensions);

    if (!hasValidExtension)
    {
        goto Exit;
    }

    EventWriteFileCreation(
        &systemTime,
        WorkstationName,
        FileName.c_str(),
        IssuingThreadId,
        ShareAccess,
        CreateOptions
    );

Exit:
    //
    // Free each element in propertyDataVector and the vector itself
    //
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

NTSTATUS WriteServiceEvent(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {
    std::wstring ServiceName, ImagePath, ServiceType, StartType, AccountName;
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    ServiceName = (WCHAR*)propertyDataVector[0];
    ImagePath = (WCHAR*)propertyDataVector[1];
    ServiceType = (WCHAR*)propertyDataVector[2];
    StartType = (WCHAR*)propertyDataVector[3];
    AccountName = (WCHAR*)propertyDataVector[4];

    EventWriteServiceCreation(
        &systemTime,
        WorkstationName,
        ServiceName.c_str(),
        ImagePath.c_str(),
        ServiceType.c_str(),
        StartType.c_str(),
        AccountName.c_str()
    );

Exit:
    //
    // Free each element in propertyDataVector and the vector itself
    //
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

NTSTATUS WriteDpapiEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {

    UINT32 Flags, ProtectionFlags, ReturnValue, CallerProcessID, PlainTextDataSize;
    std::wstring OperationType, DataDescription;
    GUID MasterKeyGUID;
    UINT64 CallerProcessStartKey, CallerProcessCreationTime;
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    OperationType = (WCHAR*)propertyDataVector[0];
    DataDescription = (WCHAR*)propertyDataVector[1];
    MasterKeyGUID = *(GUID*)propertyDataVector[2];
    Flags = *(UINT32*)propertyDataVector[3];
    ProtectionFlags = *(UINT32*)propertyDataVector[4];
    ReturnValue = *(UINT32*)propertyDataVector[5];
    CallerProcessStartKey = *(UINT64*)propertyDataVector[6];
    CallerProcessID = *(UINT32*)propertyDataVector[7];
    CallerProcessCreationTime = *(UINT64*)propertyDataVector[8];
    PlainTextDataSize = *(UINT32*)propertyDataVector[9];

    if (OperationType == L"SPCryptUnprotect")
    {
        EventWriteDPAPIUnprotect(
            &systemTime,
            WorkstationName,
            CallerProcessID,
            OperationType.c_str(),
            DataDescription.c_str(),
            Flags,
            ProtectionFlags
        );

    }


Exit:
    //
    // Free each element in propertyDataVector and the vector itself
    //
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

NTSTATUS WriteWMIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ LPWSTR WorkstationName
) {

    std::wstring Namespace, ESS, Consumer, PossibleCause;
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;

    fileTime.dwLowDateTime = EventHeader->TimeStamp.LowPart;
    fileTime.dwHighDateTime = EventHeader->TimeStamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        OutputDebugString(L"Error converting timestamp\n");
        status = ERROR_INVALID_DATA;
        goto Exit;
    }

    //
    // Processing ETW
    //
    status = EtwEventProcessing(EventRecord, &pInfo, &propertyDataVector);
    if (status != ERROR_SUCCESS) {
        goto Exit;
    }

    Namespace = (WCHAR*)propertyDataVector[0];
    ESS = (WCHAR*)propertyDataVector[1];
    Consumer = (WCHAR*)propertyDataVector[2];
    PossibleCause = (WCHAR*)propertyDataVector[3];

    EventWriteWMIEventFilter(
        &systemTime,
        WorkstationName,
        EventHeader->ProcessId,
        Namespace.c_str(),
        ESS.c_str(),
        Consumer.c_str(),
        PossibleCause.c_str()
    );



Exit:
    //
    // Free each element in propertyDataVector and the vector itself
    //
    if (propertyDataVector != nullptr) {
        if (pInfo != nullptr) {
            for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                if (propertyDataVector[i] != nullptr) {
                    free(propertyDataVector[i]);
                }
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}
