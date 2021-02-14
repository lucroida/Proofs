/*
    fp.c
                                          
    According to MSDN, since Windows 10 1803, UEFI firmware variables
    may be wrriten from usermode using provided system interfaces. Add-
    itionally, credible sources have documented UEFI firmware variables
    as a means for persistent storage for offensive tradecreaft and to-
    oling. The following code demonstrates such capabilities

    References:
        MSDN. GetFirmwareEnvironmentVariab... https://bit.ly/2NmR7Dd
        MSDN. Access UEFI Firmware Variabl... https://bit.ly/2N2kLh7
        Process Hacker. Ntexpi.h... https://bit.ly/3ajezKq
        ...
*/
#include <windows.h>
#include <immintrin.h>
#include "fp.h"

/* Function Prototypes */
BOOL ReadPersistentStore(LPCSTR lpName, LPCSTR lpGuid, LPVOID pBuffer, DWORD dwSize);
BOOL WritePersistentStore(LPCSTR lpName, LPCSTR lpGuid, PVOID pValue, DWORD dwSize);
BOOL GetBootOptions(PBOOT_OPTIONS pBootOptions);
BOOL AdjustToken(HANDLE hToken, LPCWSTR szPrivilege);
BOOL GetAdjustableToken(PHANDLE phToken);
VOID GenerateKey(PBYTE pKeybuffer, DWORD dwSize);
VOID XorEncode(PBYTE pData, PBYTE pKey, DWORD dwLength);

/* Entry Point */
DWORD main()
{
    BOOL    bStatus;
    DWORD   dwError;
    HANDLE  hCurrentToken;
    LPCSTR  szStoreName = "demo_store";
    LPCSTR  szGuid = "{bdcb4412-7060-11ea-bc33-add1f107aa40}";

    // Get the current process token with adjust access
    bStatus = GetAdjustableToken(&hCurrentToken);
    if (!bStatus)
        goto _error;

    // Set the privilege needed to interact with firmware
    LPCWSTR szSystemEnvPrivilege = SE_SYSTEM_ENVIRONMENT_NAME;
    bStatus = AdjustToken(hCurrentToken, szSystemEnvPrivilege);
    if (!bStatus)
        goto _error;

    // Check that the system is even using UEFI
    FIRMWARE_TYPE FirmwareType = { 0 };
    bStatus = GetFirmwareType(&FirmwareType);
    if (!bStatus)
        goto _error;
    if (FirmwareType != FirmwareTypeUefi) 
        goto _error;
    
    // Setup data to persist
    PERSISTENT_DATA_CHUNK PersistentData = { 0xDEADBEEF };
    DWORD dwPersistDataSize = sizeof(PERSISTENT_DATA_CHUNK);
    
    // Encode it using a simple xor cipher
    BYTE pKey[sizeof(PersistentData)];
    GenerateKey(&pKey, dwPersistDataSize);
    XorEncode(&PersistentData, &pKey, dwPersistDataSize);
    
    // Demonstrates persistent storage using UEFI firmware variable
    bStatus = WritePersistentStore(
        szStoreName, szGuid, &PersistentData, dwPersistDataSize);
    if (!bStatus)
        goto _error;

    // Demonstrates read of UEFI firmware variable.        
    ZeroMemory(&PersistentData, dwPersistDataSize);
    bStatus = ReadPersistentStore(szStoreName, szGuid, &PersistentData, dwPersistDataSize);
    if (!bStatus)
        goto _delete;

    // Decode the data using the original key
    XorEncode(&PersistentData, &pKey, dwPersistDataSize);

    // Demonstrate deletion of UEFI firmware variable
    bStatus = DeletePersistentStore(szStoreName, szGuid);
    if (!bStatus)
        goto _error;

_error:
    CloseHandle(hCurrentToken);
    dwError = GetLastError();
    return dwError;
}

// Read an NVRAM environment variable
BOOL ReadPersistentStore(LPCSTR lpName, LPCSTR lpGuid, LPVOID pBuffer, DWORD dwSize) {
    DWORD dwBytesRead = 0;
    DWORD dwAttributes = 0;

    if (!pBuffer) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    dwBytesRead = GetFirmwareEnvironmentVariableExA(
        lpName,
        lpGuid,
        pBuffer,
        dwSize,
        &dwAttributes);
    if (dwBytesRead == 0)
        return FALSE;

    return TRUE;
}

// Write an NVRAM environment variable
BOOL WritePersistentStore(LPCSTR lpName, LPCSTR lpGuid, PVOID pValue, DWORD dwSize) {
    DWORD dwRet = 0;
    DWORD dwAttributes = VARIABLE_ATTRIBUTE_NON_VOLATILE
        | VARIABLE_ATTRIBUTE_BOOTSERVICE_ACCESS
        | VARIABLE_ATTRIBUTE_RUNTIME_ACCESS;

    dwRet = SetFirmwareEnvironmentVariableExA(
        lpName,
        lpGuid,
        pValue,
        dwSize,
        dwAttributes);
    
    if (dwRet == 0)
        return FALSE;

    return TRUE;
}

// Delete an item from the persistent store
BOOL DeletePersistentStore(LPCSTR lpName, LPCSTR lpGuid) {
    DWORD dwRet = 0;
    DWORD dwAttributes = VARIABLE_ATTRIBUTE_NON_VOLATILE
        | VARIABLE_ATTRIBUTE_BOOTSERVICE_ACCESS
        | VARIABLE_ATTRIBUTE_RUNTIME_ACCESS;

    // nSize parameter signals to delete
    dwRet = SetFirmwareEnvironmentVariableExA(
        lpName,
        lpGuid,
        0,
        0,                  
        dwAttributes);

    if (dwRet == 0)
        return FALSE;

    return TRUE;
}

// Get the system's global boot options
BOOL GetBootOptions(PBOOT_OPTIONS pBootOptions) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == 0)
        return FALSE;

    _NtQueryBootOptions* lfNtQueryBootOptions =
        GetProcAddress(hNtdll, "NtQueryBootOptions");

    DWORD dwOptionsLength = sizeof(BOOT_OPTIONS);
    status = lfNtQueryBootOptions(pBootOptions, &dwOptionsLength);
    if (!NT_SUCCESS(status))
        return FALSE;

    return TRUE;
}

// Get the current process token
BOOL GetAdjustableToken(PHANDLE phToken) {
    *phToken = INVALID_HANDLE_VALUE;

    OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        phToken);
    if (*phToken == INVALID_HANDLE_VALUE)
        return FALSE;

    return TRUE;
}

// Request adjustment of the given token to enable the given privilege
BOOL AdjustToken(HANDLE hToken, LPCWSTR szPrivilege) {
    DWORD               dwError;
    BOOL                bStatus;
    TOKEN_PRIVILEGES    NewState;
    TOKEN_PRIVILEGES    OldState;
    LUID                luid;

    // Get the LUID for the target privilege
    bStatus = LookupPrivilegeValue(
        NULL,
        szPrivilege,
        &luid);
    if (!bStatus)
        return FALSE;

    // Set new privilege state
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = luid;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Request the privileges be adjusted
    bStatus = AdjustTokenPrivileges(
        hToken,
        FALSE,
        &NewState,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL);

    if (GetLastError == ERROR_NOT_ALL_ASSIGNED)
        return FALSE;

    return bStatus;
}

// Generate key for xor cipher operations
VOID GenerateKey(PBYTE pKeybuffer, DWORD dwSize) {
    DWORD dwRand = 0;

    for (DWORD i = 0; i < dwSize; i++) {
        _rdrand32_step(&dwRand);
        pKeybuffer[i] = (BYTE)dwRand;
    }
}

// Sliding xor cipher (obfuscate) the given data
VOID XorEncode(PBYTE pData, PBYTE pKey, DWORD dwLength) {
    for (int i = 0; i < dwLength; i++) {
        pData[i] = pData[i] ^ pKey[i];
    }
}