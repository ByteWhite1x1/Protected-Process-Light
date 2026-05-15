#pragma once

#include <Nt.h>

/*
TokenProtectionNone(0)

Type = 0  (None)
Signer = 0  (None)

TokenProtectionLsaLight(1)

Type = 1  (ProtectedLight)
Signer = 4  (Lsa)

TokenProtectionLsa(2)

Type = 2  (Protected)
Signer = 4  (Lsa)

TokenProtectionAntimalwareLight(3)

Type = 1  (ProtectedLight)
Signer = 3  (Antimalware)

TokenProtectionAntimalware(4)

Type = 2  (Protected)
Signer = 3  (Antimalware)

TokenProtectionApp(5)

Type = 1  (ProtectedLight)
Signer = 5  (Windows)

TokenProtectionMax(6)

Type = 2  (Protected)
Signer = 6  (WinTcb)
*/

typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

static const WCHAR* ProtectedSignerNames[] =
{
    L"None",
    L"Authenticode",
    L"Anti-Malware",
    L"CodeGen",
    L"LSA",
    L"Windows",
    L"WinTcb",
    L"WinSystem",
    L"StoreApplication"
};

// https://www.alex-ionescu.com/the-evolution-of-protected-processes-pass-the-hash-mitigations-in-windows-8-1/
typedef enum _PS_PROTECTED_SIGNER : UCHAR
{
    PsProtectedSignerNone = 0,
    // No protected signer. The process is not a PPL.

    PsProtectedSignerAuthenticode = 1,
    // Legacy. Used for processes protected by standard Authenticode signatures.
    // Rarely used in modern Windows.

    PsProtectedSignerCodeGen = 2,
    // Used for JIT/code-generation components (e.g., .NET NGEN, JIT compiler).
    // Provides limited protection against tampering.

    PsProtectedSignerAntimalware = 3,
    // Used by antimalware vendors and Microsoft Defender.
    // Required for PPL-Antimalware processes (e.g., MsMpEng.exe).
    // Allows access to certain protected resources.

    PsProtectedSignerLsa = 4,
    // Used by Local Security Authority (lsass.exe).
    // Required for PPL-Lsa, which protects credentials and authentication secrets.

    PsProtectedSignerWindows = 5,
    // Used by core Windows components that need PPL-Windows protection.
    // Examples: Winlogon, certain service hosts.

    PsProtectedSignerWinTcb = 6,
    // Windows Trusted Computing Base.
    // Highest non-kernel PPL level. Used by critical OS components.
    // Required for processes that need SeTcbPrivilege-like trust.

    PsProtectedSignerWinSystem = 7,
    // Used by system-level Windows components that require strong protection
    // but do not need full WinTcb trust.
    // Often used by system services running as PPL-WinSystem.

    PsProtectedSignerApp = 8,
    // Used by Windows Store (UWP) applications that run as PPL-App.
    // Provides isolation from non-protected processes.

    PsProtectedSignerMax = 9
    // Upper bound marker. Not a real signer.
} PS_PROTECTED_SIGNER;


PS_PROTECTED_SIGNER GetSignerFromProtectionLevel(PS_PROTECTION lpProtection)
{
    return (PS_PROTECTED_SIGNER)(lpProtection.Signer);
}

UCHAR GetProcessProtection(PEPROCESS lpProcess)
{

    BYTE retValue = 0;

    NTSTATUS status;

    HANDLE lpProcessId = PsGetProcessId(lpProcess);

    OBJECT_ATTRIBUTES objAttribs;
    InitializeObjectAttributes(&objAttribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    CLIENT_ID cId = { 0 };
    cId.UniqueProcess = lpProcessId;

    HANDLE hTmp = NULL;
    status = ZwOpenProcess(&hTmp, PROCESS_ALL_ACCESS, &objAttribs, &cId);

    if (!NT_SUCCESS(status))
    {

        DbgPrintEx(0, 0, "[-] ZwOpenProcess (0x%08X) \n", status);
        return retValue;

    }

    PS_PROTECTION protectionInfo;

    ULONG bytesReturned;
    status = ZwQueryInformationProcess(hTmp,
        ProcessProtectionInformation,
        &protectionInfo,
        sizeof(PS_PROTECTION),
        &bytesReturned);

    if (NT_SUCCESS(status))
    {

        PS_PROTECTED_SIGNER signer = GetSignerFromProtectionLevel(protectionInfo);

        // DbgPrintEx(0, 0, "[+] ZwQueryInformationProcess (0x%08X) protectionInfo.Level: %u 0x%02X signer: %d -> %ls\n", status, protectionInfo.Level, protectionInfo.Level, signer, ProtectedSignerNames[signer]);

        retValue = (UCHAR)signer;

    }

    if (hTmp)
    {
        ZwClose(hTmp);
    }

    return retValue;

}

/*
UCHAR GetPplLevelFromToken(PTOKEN pToken) // PTOKEN == dt nt!_TOKEN
{

    if (!pToken)
        return 0;

    // The PPL level is stored directly in Token->Protection.Level
    return pToken->Protection.Level;
}
*/
