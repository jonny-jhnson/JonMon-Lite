#include "JonMon-Lite-Creation.h"


VOID CreateCollectorSet(
	_In_ LPCWSTR workstationName,
	_In_ LPCWSTR collectorSetName,
	_In_ LPCWSTR xmlFilePath,
    _In_ LPCWSTR rootPath,
    _In_ LPCWSTR userName,
    _In_ LPCWSTR userPassword
)
{
	HRESULT hr;
	IDataCollectorSet* pDataCollectorSet = NULL;
	BSTR bstrWorkstationName = NULL;
	BSTR bstrXml = NULL;
	BSTR bstrUserName = NULL;
	BSTR bstrPassword = NULL;
	BSTR bstrCollectorSetName = NULL;
    BSTR bstrRootPath = NULL;
    IValueMap* pCommitValidation = NULL;
    DWORD waitResult;


    wprintf(L"Creating JonMon-Lite Trace...\n");

	if (wcscmp(workstationName, L"Local") == 0)
	{
		bstrWorkstationName = NULL;
	}
	else
	{
		bstrWorkstationName = SysAllocString(workstationName);
	}



    std::wstring xmlContent = ReadXmlFile(xmlFilePath);
    if (xmlContent.empty()) {
        wprintf(L"Failed to read XML file or file is empty.\n");
        goto Exit;
    }

    //
    // Convert XML to BSTR
    //
    bstrXml = SysAllocString(xmlContent.c_str());

    //
    // Initializing COM 
    //
	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		wprintf(L"Failed to initialize COM library. Error: %x\n", hr);
        goto Exit;
	}

    //
	// Create the DataCollectorSet Instance
    //
    hr = CoCreateInstance(__uuidof(DataCollectorSet),
        NULL,
        CLSCTX_SERVER,
        __uuidof(IDataCollectorSet),
        (void**)&pDataCollectorSet);

    if (FAILED(hr)) {
        wprintf(L"CoCreateInstance(__uuidof(DataCollectorSet) failed with 0x%x.\n", hr);
        goto Exit;
    }

    //
    // Setting CollectorSetDisplayName
    //
    bstrCollectorSetName = SysAllocString(collectorSetName);

    hr = pDataCollectorSet->put_DisplayName(
        bstrCollectorSetName
    );
    if (FAILED(hr)) {
        wprintf(L"pDataCollectorSet->put_DisplayName failed with 0x%x.\n", hr);
        goto Exit;
    }

    //
    // Setting user that the trace will run under
    //
    if (userName != L"")
    {
        bstrUserName = SysAllocString(userName);
        bstrPassword = SysAllocString(userPassword);

        hr = pDataCollectorSet->SetCredentials(
            bstrUserName, 
            bstrPassword
        );
        if (FAILED(hr)) {
            wprintf(L"pDataCollectorSet->SetCredentials failed with 0x%x.\n", hr);
            goto Exit;
        }
        else {
            wprintf(L"Credentials set successfully.\n");
        }
    }

    //
    // Applying RootPath
    //
    bstrRootPath = SysAllocString(rootPath);

    hr = pDataCollectorSet->put_RootPath(bstrRootPath);
    if (FAILED(hr)) {
        wprintf(L"pDataCollectorSet->put_RootPath failed with 0x%x.\n", hr);
        goto Exit;
    }
    else {
        wprintf(L"pDataCollectorSet->put_RootPath was set successfully\n");
    }

    //
    // Apply the XML file to the collector set
    //
    hr = pDataCollectorSet->SetXml(
        bstrXml, 
        &pCommitValidation
    );
    if (FAILED(hr)) {
        wprintf(L"pDataCollectorSet->SetXml failed with 0x%x.\n", hr);
        goto Exit;
    }
    else {
        wprintf(L"pDataCollectorSet->SetXml was set successfully\n");
    }

    //
    // Setting the CollectorSet
    //
    hr = pDataCollectorSet->Commit(
        bstrCollectorSetName,
        bstrWorkstationName,
        plaCreateNew,
        &pCommitValidation
    );
    if (FAILED(hr)) {
        wprintf(L"pDataCollectorSet->Commit failed with 0x%x.\n", hr);
        goto Exit;
    }

    wprintf(L"Collector set '%s' has been created/updated successfully.\n", collectorSetName);

    hr = pDataCollectorSet->Start(VARIANT_TRUE);
    if (FAILED(hr)) {
        wprintf(L"pDataCollectorSet->Start failed with 0x%x.\n", hr);
        goto Exit;
    }
    
    wprintf(L"Collector set '%s' started successfully.\n", collectorSetName);

    waitResult = WaitForSingleObject(finishJobs, INFINITE);
    if (waitResult == WAIT_OBJECT_0) {
        hr = pDataCollectorSet->Stop(VARIANT_TRUE);
        if (FAILED(hr)) {
            wprintf(L"pDataCollectorSet->Stop failed with 0x%x.\n", hr);
            goto Exit;
        }

        hr = pDataCollectorSet->Delete();
        if (FAILED(hr)) {
            wprintf(L"pDataCollectorSet->Delete failed with 0x%x.\n", hr);
            goto Exit;
        }

        goto Exit;
    }
    else {
        wprintf(L"WaitForSingleObject failed %d\n", GetLastError());
        goto Exit;
    }

Exit:
    if (bstrCollectorSetName)
    {
        SysFreeString(bstrCollectorSetName);
    }
	if (bstrUserName)
	{
		SysFreeString(bstrUserName);
	}
    if (bstrPassword)
    {
		SysFreeString(bstrPassword);
    }
	if (bstrXml)
	{
		SysFreeString(bstrXml);
	}
    if (bstrWorkstationName)
    {
		SysFreeString(bstrWorkstationName);
    }
    if (pDataCollectorSet)
    {
        pDataCollectorSet->Release();
    }
    CoUninitialize();

    return;

}


std::wstring ReadXmlFile(
    const wchar_t* filePath
) {
    FILE* file = nullptr;
    char* buffer = nullptr;
    errno_t err; 
    long fileSize;
    std::wstring result;
    size_t bytesRead;
    const unsigned char* pBuffer;
    int wideLength;
    wchar_t* wideBuffer = nullptr;

    err = _wfopen_s(&file, filePath, L"rb");
    if (err != 0 || !file) {
        wprintf(L"Failed to open file: %s (Error: %d)\n", filePath, err);
        result = L"";
        goto Exit;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize <= 0) {
        fclose(file);
        result = L"";
        goto Exit;
    }

    // Allocate buffer for file content
    buffer = new char[fileSize + 2];
    bytesRead = fread(buffer, 1, fileSize, file);
    fclose(file);

    buffer[bytesRead] = '\0';
    buffer[bytesRead + 1] = '\0';

    pBuffer = (unsigned char*)buffer;
    if (bytesRead >= 3 && pBuffer[0] == 0xEF && pBuffer[1] == 0xBB && pBuffer[2] == 0xBF) {
        pBuffer += 3;
    }

    wideLength = MultiByteToWideChar(CP_UTF8, 0, (char*)pBuffer, -1, NULL, 0);
    wideBuffer = new wchar_t[wideLength];
    MultiByteToWideChar(CP_UTF8, 0, (char*)pBuffer, -1, wideBuffer, wideLength);

    result = wideBuffer;


Exit:
    if (buffer)
    {
        delete[] buffer;
    }
    if (wideBuffer)
    {
        delete[] wideBuffer;
    }
    
    return result;
}