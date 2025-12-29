#include <windows.h>
#include <stdio.h>

typedef BOOL (WINAPI *LOAD_FUNC)(LPCWSTR);

int main() {
    HMODULE dll = LoadLibraryW(L"VEHoverloading.dll");
    if (!dll) { printf("Load DLL failed\n"); return 1; }

    LOAD_FUNC func = (LOAD_FUNC)GetProcAddress(dll, "load_vectoredoverload");
    if (!func) { printf("Get proc failed\n"); return 1; }

    printf("Calling...\n");
    BOOL ok = func(NULL); // 使用默认 calc.exe
    printf("Result: %s\n", ok ? "SUCCESS" : "FAILED");

    FreeLibrary(dll);
    return 0;
}