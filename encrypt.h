#include <windows.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")


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


void ROT_encrypt(unsigned char* str, size_t data_len, int rot){
    for(int i = 0; i < data_len; i++){
        str[i] = str[i] + rot;
    }
}
void ROT_decrypt(unsigned char* str, size_t data_len, int rot){
    for(int i = 0; i < data_len; i++){
        str[i] = str[i] - rot;
    }
}


void XOR(unsigned char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}