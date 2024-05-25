#include <iostream>
#include <Windows.h>
#include <string>
#include <Psapi.h>

std::string GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return "Unknown Process";
    }

    char processName[MAX_PATH] = { 0 };
    if (GetModuleFileNameExA(hProcess, NULL, processName, MAX_PATH) == 0) {
        CloseHandle(hProcess);
        return "Unknown Process";
    }

    CloseHandle(hProcess);
    return std::string(processName);
}

void printTitle(const char* title) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    COORD pos;
    pos.X = (csbi.srWindow.Right - csbi.srWindow.Left - strlen(title)) / 2;
    pos.Y = csbi.dwCursorPosition.Y;
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
    std::cout << title << std::endl;
}

void printHeader() {
    std::cout << "\x1b[31m" << R"(
 /$$$$$$                                     /$$                         /$$$$$$$ 
|_  $$_/                                    | $$                        | $$__  $$
  | $$   /$$$$$$$  /$$  /$$$$$$   /$$$$$$$ /$$$$$$    /$$$$$$   /$$$$$$ | $$  \ $$
  | $$  | $$__  $$|__/ /$$__  $$ /$$_____/|_  $$_/   /$$__  $$ /$$__  $$| $$$$$$$/
  | $$  | $$  \ $$ /$$| $$$$$$$$| $$        | $$    | $$  \ $$| $$  \__/| $$__  $$
  | $$  | $$  | $$| $$| $$_____/| $$        | $$ /$$| $$  | $$| $$      | $$  \ $$
 /$$$$$$| $$  | $$| $$|  $$$$$$$|  $$$$$$$  |  $$$$/|  $$$$$$/| $$      | $$  | $$
|______/|__/  |__/| $$ \_______/ \_______/   \___/   \______/ |__/      |__/  |__/
             /$$  | $$                                                            
            |  $$$$$$/                                                            
             \______/                                                             
)" << "\x1b[0m" << std::endl;
}

void clearScreen() {
    system("cls");
}

void printFooter(const char* process, const char* dll) {
    std::cout << "" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "\x1b[90m" << "                              Process: " << (process ? process : "Not Selected") << std::endl;
    std::cout << "                              DLL: " << (dll ? dll : "Not Selected") << "\x1b[0m" << std::endl;
}

std::string chooseProcess() {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return "";
    }

    cProcesses = cbNeeded / sizeof(DWORD);
    std::cout << "Select a process:" << std::endl;
    for (DWORD i = 0; i < cProcesses; i++) {
        DWORD processId = aProcesses[i];
        if (processId != 0) {
            std::cout << i + 1 << ". " << GetProcessName(processId) << " (PID: " << processId << ")" << std::endl;
        }
    }

    std::cout << "Enter the index of the process: ";
    DWORD index;
    std::cin >> index;
    if (index >= 1 && index <= cProcesses) {
        DWORD processId = aProcesses[index - 1];
        return GetProcessName(processId);
    }

    return "";
}

std::string chooseFile(const char* fileType) {
    OPENFILENAMEA ofn; // Use ANSI version of OPENFILENAME
    char szFile[MAX_PATH] = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = fileType;
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn) == TRUE) { // Use ANSI version of GetOpenFileName
        return std::string(ofn.lpstrFile);
    }
    else {
        return "";
    }
}

bool injectDll(const char* process, const char* dll) {
    // Example injection using CreateRemoteThread method
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (hProcess == NULL) {
        std::cerr << "Failed to open process." << std::endl;
        return false;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pDllPath == NULL) {
        std::cerr << "Failed to allocate memory in the remote process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dll, strlen(dll) + 1, NULL)) {
        std::cerr << "Failed to write DLL path into the remote process." << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"); // Use ANSI versions
    if (pLoadLibrary == NULL) {
        std::cerr << "Failed to get address of LoadLibraryA function." << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pDllPath, 0, NULL);
    if (hRemoteThread == NULL) {
        std::cerr << "Failed to create remote thread." << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);

    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    return true;
}

int main() {
    SetConsoleTitle(TEXT("InjectorR"));
    const char* title = "InjectorR";
    printTitle(title);
    printHeader();
    const char* process = nullptr;
    const char* dll = nullptr;
    bool processSelected = false;
    bool dllSelected = false;

    int option = 0;
    while (true) {
        if (!processSelected) {
            clearScreen();
            printHeader();
            printFooter(process, dll);
            std::cout << "" << std::endl;
            std::cout << "\x1b[90mOptions:" << std::endl << "\x1b[0m";
            std::cout << "" << std::endl;
            std::cout << "\x1b[90m1. Choose Process" << std::endl;
            std::cout << "2. Close Program" << std::endl << "\x1b[0m";
            std::cout << "" << std::endl;
            std::cout << "Enter option: ";
            std::cin >> option;

            switch (option) {
            case 1:
                process = chooseProcess().c_str();
                processSelected = true;
                break;
            case 2:
                return 0;
            default:
                std::cout << "Invalid option. Please try again." << std::endl;
            }
        }
        else if (!dllSelected) {
            clearScreen();
            printHeader();
            printFooter(process, dll);
            std::cout << "\x1b[90mOptions:" << std::endl;
            std::cout << "1. Choose DLL" << std::endl;
            std::cout << "2. Inject DLL to Process" << std::endl << "\x1b[0m";
            std::cout << "Enter option: ";
            std::cin >> option;

            switch (option) {
            case 1:
                dll = chooseFile("Dynamic Link Libraries\0*.dll\0All Files\0*.*\0").c_str();
                dllSelected = true;
                break;
            case 2:
                if (dllSelected) {
                    if (injectDll(process, dll)) {
                        std::cout << "Injection successful!" << std::endl;
                    }
                    else {
                        std::cout << "Injection failed." << std::endl;
                    }
                }
                else {
                    std::cout << "DLL not selected. Please choose a DLL first." << std::endl;
                }
                return 0;
            default:
                std::cout << "Invalid option. Please try again." << std::endl;
            }
        }
    }

    return 0;
}
