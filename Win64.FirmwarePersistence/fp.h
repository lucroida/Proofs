/*
    fp.h

    Expose items for interacting with UEFI/NVRAM
*/
#pragma once
#include <windows.h>
#include <winternl.h>

/* Macros and Preprocessor Definitions */

#define STATUS_UNSUCCESSFUL 0xC0000001;

#define VARIABLE_ATTRIBUTE_NON_VOLATILE                             0x00000001
#define VARIABLE_ATTRIBUTE_BOOTSERVICE_ACCESS                       0x00000002
#define VARIABLE_ATTRIBUTE_RUNTIME_ACCESS                           0x00000004
#define VARIABLE_ATTRIBUTE_HARDWARE_ERROR_RECORD                    0x00000008
#define VARIABLE_ATTRIBUTE_AUTHENTICATED_WRITE_ACCESS               0x00000010
#define VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS    0x00000020
#define VARIABLE_ATTRIBUTE_APPEND_WRITE                             0x00000040

/* Structures */

typedef struct _BOOT_OPTIONS
{
    ULONG Version;
    ULONG Length;
    ULONG Timeout;
    ULONG CurrentBootEntryId;
    ULONG NextBootEntryId;
    WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, * PBOOT_OPTIONS;

typedef struct _PERSISTENT_DATA_CHUNK {
    DWORD Data[0xFF];
} PERSISTENT_DATA_CHUNK, * PPERSISTENT_DATA_CHUNK;

/* Function Prototypes */

typedef NTSTATUS NTAPI _RtlGetLastNtStatus();
typedef NTSTATUS NTAPI _RtlGUIDFromString(PCUNICODE_STRING GuidString, GUID* Guid);
typedef NTSTATUS NTAPI _RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS NTAPI _NtQueryBootOptions(PBOOT_OPTIONS BootOptions, PULONG BootOptionsLength);
