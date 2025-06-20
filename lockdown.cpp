#include <windows.h>

#pragma comment(linker, "/NODEFAULTLIB:LIBCMT") // No standard C/C++ library needed
#pragma comment(linker, "/SUBSYSTEM:WINDOWS") // Microsoft Windows application
#pragma comment(lib, "KERNEL32")
#pragma comment(lib, "USER32")
#pragma comment(lib, "GDI32")
#pragma comment(lib, "ADVAPI32")
#pragma comment(lib, "BUFFEROVERFLOWU") // For 64bit compiler

UCHAR AddressLength = sizeof(PVOID);  // Size of address

UCHAR VerMaj = 1,
      VerMin = 0,
      VerBit = sizeof(PVOID) * 8;
PCHAR VerDat = __TIMESTAMP__;

enum { SVCSTR_BOOT, SVCSTR_SYS, SVCSTR_AUTO, SVCSTR_MAN, SVCSTR_OFF, SVCSTR_MAX };

PCHAR SvcStrings[SVCSTR_MAX] = { "Boot", "System", "Automatic", "Manual", "Disabled" };

typedef struct { HWND WH, EH; } CTHANDLE, *PCTHANDLE;

typedef struct { PCHAR Name; ULONG Def, Rec, Set, Cur; } SERVICE, *PSERVICE;

CTHANDLE Handles;
HANDLE   TH;

PCHAR WinName = "LockDown";
HANDLE ProcessHeap;                   // Handle to process memory heap
HANDLE ProcessMutex;                  // Mutex to handle multiple instances

UCHAR DCOMEnabled      = 0;
PCHAR RegDCOMPath      = "SOFTWARE\\Microsoft\\Ole";
PCHAR RegDCOMProtoPath = "SOFTWARE\\Microsoft\\Rpc";
PCHAR RegDCOMVal       = "EnableDCOM";
PCHAR RegDCOMBindPath  = "SYSTEM\\CurrentControlSet\\Services\\RpcSs\\Linkage";
PCHAR RegDCOMBindVal   = "Bind";
PCHAR RegDCOMProtoVal  = "DCOM Protocols";

SERVICE Services[]=
{
  "AeLookupSvc",       0, 4, 0, 0,  "ALG",               0, 4, 0, 0,
  "AppMgmt",           0, 4, 0, 0,  "ATI HotKey Poller", 0, 4, 0, 0,
  "wuauserv",          0, 4, 0, 0,  "BITS",              0, 4, 0, 0,
  "BthServ",           0, 3, 0, 0,  "ClipSrv",           0, 4, 0, 0,
  "EventSystem",       0, 4, 0, 0,  "COMSysApp",         0, 4, 0, 0,
  "CryptSvc",          0, 3, 0, 0,  "DcomLaunch",        0, 2, 0, 0,
  "Dhcp",              0, 2, 0, 0,  "TrkWks",            0, 4, 0, 0,
  "MSDTC",             0, 4, 0, 0,  "Dnscache",          0, 4, 0, 0,
  "ERSvc",             0, 4, 0, 0,  "Eventlog",          0, 2, 0, 0,
  "helpsvc",           0, 4, 0, 0,  "HTTPFilter",        0, 4, 0, 0,
  "HidServ",           0, 4, 0, 0,  "IASJet",            0, 4, 0, 0,
  "ImapiService",      0, 4, 0, 0,  "CiSvc",             0, 4, 0, 0,
  "PolicyAgent",       0, 4, 0, 0,  "dmserver",          0, 4, 0, 0,
  "dmadmin",           0, 4, 0, 0,  "swprv",             0, 4, 0, 0,
  "mnmsrvc",           0, 4, 0, 0,  "Netman",            0, 4, 0, 0,
  "NetDDE",            0, 4, 0, 0,  "NetDDEdsdm",        0, 4, 0, 0,
  "Nla",               0, 4, 0, 0,  "xmlprov",           0, 4, 0, 0,
  "NVSvc",             0, 4, 0, 0,  "Sysmonlog",         0, 4, 0, 0,
  "PlugPlay",          0, 2, 0, 0,  "WmdmPmSN",          0, 4, 0, 0,
  "Spooler",           0, 3, 0, 0,  "mnmsrvc",           0, 4, 0, 0,
  "NetBT",             0, 0, 0, 0,  "ProtectedStorage",  0, 3, 0, 0,
  "RasAuto",           0, 4, 0, 0,  "RasMan",            0, 4, 0, 0,
  "RDSessMgr",         0, 4, 0, 0,  "RpcSs",             0, 0, 0, 0,
  "RemoteRegistry",    0, 4, 0, 0,  "NtmsSvc",           0, 4, 0, 0,
  "RemoteAccess",      0, 4, 0, 0,  "seclogon",          0, 4, 0, 0,
  "SamSs",             0, 4, 0, 0,  "wscsvc",            0, 4, 0, 0,
  "ShellHWDetection",  0, 4, 0, 0,  "SCardSvr",          0, 4, 0, 0,
  "SSDPSRV",           0, 4, 0, 0,  "SENS",              0, 4, 0, 0,
  "srservice",         0, 4, 0, 0,  "Schedule",          0, 4, 0, 0,
  "LmHosts",           0, 4, 0, 0,  "TapiSrv",           0, 4, 0, 0,
  "TlntSvr",           0, 4, 0, 0,  "TermService",       0, 4, 0, 0,
  "Themes",            0, 4, 0, 0,  "UPS",               0, 4, 0, 0,
  "upnphost",          0, 4, 0, 0,  "vds",               0, 4, 0, 0,
  "VSS",               0, 4, 0, 0,  "WebClient",         0, 4, 0, 0,
  "AudioSrv",          0, 2, 0, 0,  "SharedAccess",      0, 4, 0, 0,
  "stisvc",            0, 4, 0, 0,  "MSIServer",         0, 3, 0, 0,
  "winmgmt",           0, 4, 0, 0,  "Wmi",               0, 4, 0, 0,
  "W32Time",           0, 4, 0, 0,  "UMWdf",             0, 4, 0, 0,
  "WinHttpAutoProxySvc", 0, 4, 0, 0,"WZCSVC",            0, 4, 0, 0,
  "WmiApSrv",          0, 4, 0, 0,
  0
};

PVOID _cdecl operator new(size_t Size)
{
  return HeapAlloc(ProcessHeap, 0xC, Size);
}

VOID _cdecl operator delete(PVOID Address)
{
  HeapFree(ProcessHeap, 0x4, Address);
}

VOID PrintF(HWND H, PCHAR Format, ...)
{
  CHAR Buffer[1024];

  if(wvsprintf(Buffer, Format, (PCHAR)(&Format + 1)))
  {
    SendMessage(H, EM_SETSEL, 0, 0xffffffff);
    SendMessage(H, EM_SETSEL, 0xffffffff, 0xffffffff);
    SendMessage(H, EM_REPLACESEL, 0, (LPARAM)Buffer);
  }
}

INT WINAPI ThreadMain(PCTHANDLE H)
{
  SYSTEMTIME      T;

  GetLocalTime(&T);

  PrintF(H->EH, "System Lockdown, Version %u.%u for %u-Bit Windows.\r\nCompiled %s.\r\nBy Mhatxotic Design.\r\n\r\nLog start time: %02u/%02u/%04u %02u:%02u:%02u.%03u.\r\n\r\nChecking Windows version... ", VerMaj, VerMin, VerBit, VerDat, T.wDay, T.wMonth, T.wYear, T.wHour, T.wMinute, T.wSecond, T.wMilliseconds);

  OSVERSIONINFOEX OSI;

  SecureZeroMemory(&OSI, sizeof(OSI));
  OSI.dwOSVersionInfoSize = sizeof(OSI);

  if(!GetVersionEx((LPOSVERSIONINFO)&OSI))
  {
    OSI.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if(!GetVersionEx((LPOSVERSIONINFO)&OSI))
      return 1;
  }

  PrintF(H->EH, "%u.%u.%u.%u.%u.%u... ", OSI.dwMajorVersion, OSI.dwMinorVersion, OSI.dwBuildNumber, OSI.dwPlatformId, OSI.wSuiteMask, OSI.wProductType);

  if((VerBit == 32 && OSI.dwPlatformId == VER_PLATFORM_WIN32_NT && OSI.wProductType == VER_NT_WORKSTATION && OSI.dwMajorVersion == 5 && OSI.dwMinorVersion == 1 && OSI.dwBuildNumber && 2600) ||
     (VerBit == 64 && OSI.dwPlatformId == VER_PLATFORM_WIN32_NT && OSI.wProductType == VER_NT_WORKSTATION && OSI.dwMajorVersion == 5 && OSI.dwMinorVersion == 2 && OSI.dwBuildNumber && 3790))
    PrintF(H->EH, "[PASSED].");
  else
  {
    PrintF(H->EH, "[UNSUPPORTED].\r\n\r\nWaiting for user response... ");

    if(MessageBox(H->WH, "WARNING! This program has not been tested on your operating system. You may of course continue if you are absolutely sure you know what you are doing. Do you wish to continue?\n\nPlease press the YES button to continue with the lockdown or NO button to cancel the lockdown.", WinName, MB_ICONQUESTION|MB_YESNO) == IDNO)
    {
      GetLocalTime(&T);

      PrintF(H->EH, "[ABORTED].\r\n\r\nLog finish time: %02u/%02u/%04u %02u:%02u:%02u.%03u.\r\n\r\nThread terminated. Please review the log if you wish and then press the X button, ALT + F4 or click close in the system menu to terminate the application.", T.wDay, T.wMonth, T.wYear, T.wHour, T.wMinute, T.wSecond, T.wMilliseconds);

      return 1;
    }

    PrintF(H->EH, "[OVERIDDEN].");
  }

  PrintF(H->EH, "\r\n\r\nScanning services database...\r\n");


  HKEY HK;
  ULONG HKT, HKS;
  CHAR KEYBUF[1024];
  PSERVICE SVC = Services;
  ULONG NS = 0, CH = 0, NC = 0;

  while(SVC->Name)
  {
    PrintF(H->EH, "SVC: %s, ", SVC->Name);

    wsprintf(KEYBUF, "SYSTEM\\CurrentControlSet\\Services\\%s", SVC->Name);

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, KEYBUF, 0, KEY_QUERY_VALUE, &HK) == ERROR_SUCCESS)
    {
      HKS = sizeof(ULONG);
      if(RegQueryValueEx(HK, "Start", 0, &HKT, (LPBYTE)&SVC->Cur, &HKS) == ERROR_SUCCESS)
      {
        if(SVC->Cur > SVCSTR_MAX)
          PrintF(H->EH, "Startup: INVALID VALUE (%u) ", SVC->Cur);
        else
          PrintF(H->EH, "Startup: %s (%u) ", SvcStrings[SVC->Cur], SVC->Cur);

        if(SVC->Cur != SVC->Rec)
        {
          SVC->Set = 1;
          PrintF(H->EH, "[Rec: %s (%u)]", SvcStrings[SVC->Rec], SVC->Rec);
          CH++;
        }
        else
        {
          SVC->Set = 0;
          PrintF(H->EH, "[OK]");
          NC++;
        }
      }
      else PrintF(H->EH, "RegQueryValueEx() failed code %u.", GetLastError());
      RegCloseKey(HK);
    }
    else PrintF(H->EH, "RegOpenKeyEx() failed code %u.", GetLastError());

    PrintF(H->EH, ".\r\n");

    SVC++;
    NS++;
  }

  PrintF(H->EH, "\r\nA total of %u services.\r\n%u services will not be changed.\r\n%u services will be changed.\r\n\r\nChecking Distributed COM status... ", NS, NC, CH);

  if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, RegDCOMPath, 0, KEY_QUERY_VALUE, &HK) == ERROR_SUCCESS)
  {
    BYTE Value[2];

    HKS = sizeof(Value);

    if(RegQueryValueEx(HK, RegDCOMVal, 0, &HKT, Value, &HKS) == ERROR_SUCCESS)
    {
      if(*Value == 'Y')
      {
        DCOMEnabled = 1;
        PrintF(H->EH, "Enabled and will be disabled.");
        ++CH;
      }
      else if(*Value == 'N')
        PrintF(H->EH, "Already disabled.");
      else
        PrintF(H->EH, "Unknown value returned. Cannot disable this feature.");
    }
    else PrintF(H->EH, "RegQueryValueEx() failed code %u.", GetLastError());
    RegCloseKey(HK);
  }
  else PrintF(H->EH, "RegOpenKeyEx() failed code %u.", GetLastError());

  PrintF(H->EH, "\r\n\r\n");

  if(CH)
  {
    PrintF(H->EH, "System changes are required. Waiting for user response... ");
    if(MessageBox(H->WH, "WARNING! This can be a destructive operation. Please make sure you have FULLY backed up your local machine registry just incase something bad happends.\nAre you absolutely sure you want to lockdown your system?\n\nPlease press the YES button to continue with the lockdown or NO button to cancel the lockdown and review the log.", WinName, MB_ICONQUESTION|MB_YESNO) == IDYES)
    {
      PrintF(H->EH, "[YES].\r\n\r\nCreating backup registry file... ");

      NC = CH = 0, SVC = Services;

      for(HANDLE REGFILE = INVALID_HANDLE_VALUE;;)
      {
        if((REGFILE = CreateFile("lockdown.reg", GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0)) != INVALID_HANDLE_VALUE)
        {
          PrintF(H->EH, "[SUCCESS].\r\n\r\nModifying system services...\r\n");
          WriteFile(REGFILE, "Windows Registry Editor Version 5.00\r\n", 40, &NS, 0);
          while(SVC->Name)
          {
            if(SVC->Set)
            {
              wsprintf(KEYBUF, "\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s]\r\n\"Start\"=dword:%08x\r\n", SVC->Name, SVC->Cur);
              WriteFile(REGFILE, KEYBUF, lstrlen(KEYBUF), &NS, 0);
              PrintF(H->EH, "SETSVC: %s to %s (%u), ", SVC->Name, SvcStrings[SVC->Rec], SVC->Rec);
              wsprintf(KEYBUF, "SYSTEM\\CurrentControlSet\\Services\\%s", SVC->Name);

              if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, KEYBUF, 0, KEY_SET_VALUE, &HK) == ERROR_SUCCESS)
              {
                if(RegSetValueEx(HK, "Start", 0, REG_DWORD, (LPBYTE)&SVC->Rec, 4) == ERROR_SUCCESS)
                  PrintF(H->EH, "[SUCCESS]", GetLastError());
                else
                  PrintF(H->EH, "RegSetValueEx() failed code %u.", GetLastError());
                RegCloseKey(HK);
                CH++;
              }
              else
              {
                PrintF(H->EH, "RegOpenKeyEx() failed code %u", GetLastError());
                NC++;
              }

              PrintF(H->EH, ".\r\n");
            }
            SVC++;
          }
          PrintF(H->EH, "\r\n%u services successfully modified.\r\n%u services could not be modified.", CH, NC);

          if(DCOMEnabled)
          {
            PrintF(H->EH, "\r\n\r\nDisabling Distributed COM... ");

            wsprintf(KEYBUF, "\r\n[HKEY_LOCAL_MACHINE\\%s]\r\n\"%s\"=\"Y\"\r\n"
                             "\r\n[HKEY_LOCAL_MACHINE\\%s]\r\n\"%s\"=\"NCACN_IP_TCP\"\r\n",
              RegDCOMPath, RegDCOMVal, RegDCOMProtoPath, RegDCOMProtoVal);

            WriteFile(REGFILE, KEYBUF, lstrlen(KEYBUF), &NS, 0);

            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, RegDCOMPath, 0, KEY_SET_VALUE, &HK) == ERROR_SUCCESS)
            {
              PCHAR Value = "N";

              if(RegSetValueEx(HK, RegDCOMVal, 0, REG_SZ, (LPBYTE)Value, 1) == ERROR_SUCCESS)
                PrintF(H->EH, "[SUCCESS]", GetLastError());
              else
                PrintF(H->EH, "RegSetValueEx() failed code %u.", GetLastError());
              RegCloseKey(HK);
            }

            PrintF(H->EH, "\r\nRemoving DCOM protocols... ");

            if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, RegDCOMProtoPath, 0, KEY_SET_VALUE, &HK) == ERROR_SUCCESS)
            {
              PCHAR Value = "";

              if(RegSetValueEx(HK, RegDCOMProtoVal, 0, REG_MULTI_SZ, (LPBYTE)Value, 1) == ERROR_SUCCESS)
                PrintF(H->EH, "[SUCCESS]", GetLastError());
              else
                PrintF(H->EH, "RegSetValueEx() failed code %u.", GetLastError());
              RegCloseKey(HK);
            }
          }

          CloseHandle(REGFILE);
          break;
        }
        else
        {
          PrintF(H->EH, "[FAILED %u].", GetLastError());
          if(MessageBox(H->WH, "Could not create the backup registry file to restore your original settings. Please check that the working directory this program is running from has access to create and write new files and that the file does not already exist which is for safety reasons.\r\n\r\nDo you wish to retry the operation?", WinName, MB_ICONEXCLAMATION|MB_YESNO) == IDYES)
          {
            PrintF(H->EH, "\r\nRetrying creation backup registry file... ");
            continue;
          }
          PrintF(H->EH, "\r\nUser cancelled the operation because the backup registry file cannot be created.");
          break;
        }
      }
    }
    else PrintF(H->EH, "[NO].");
  }
  else
  {
    PrintF(H->EH, "No changes to the system are to be made.");
    MessageBox(H->WH, "All the services are at their recommended values therefore no changes to the system will be made at this time.", WinName, MB_ICONINFORMATION);
  }

  GetLocalTime(&T);

  PrintF(H->EH, "\r\n\r\nLog finish time: %02u/%02u/%04u %02u:%02u:%02u.%03u.\r\n\r\nThread completed. Please review the log if you wish and then press the X button, ALT + F4 or click close in the system menu to terminate the application.", T.wDay, T.wMonth, T.wYear, T.wHour, T.wMinute, T.wSecond, T.wMilliseconds);

  return 0;
}

LRESULT CALLBACK WinProc(HWND H, UINT M, WPARAM W, LPARAM L)
{
  switch(M)
  {
    case WM_DESTROY:
      PostQuitMessage(0);
      break;
    default:
      return DefWindowProc(H, M, W, L);
  }

  return 0;
}

VOID Exception(INT Line, INT Code, PCHAR Format, ...)
{
  // Terminate thread
  TerminateThread(TH, 0);
  // Create format buffer for wvsprintf
  CHAR FormatBuffer[1024];
  // Format arguments to format buffer
  wvsprintf(FormatBuffer, Format, (PCHAR)(&Format + 1));
  // Create final buffer for wsprintf/messagebox
  CHAR FinalBuffer[1024];
  // Format final buffer
  if(Line)
    // Show error information if line specified
    wsprintf(FinalBuffer, "Error %u-%x-%u: %s.", Code, Code, Line, FormatBuffer);
  else
    // Treat as a PrintF version of MessageBox
    wsprintf(FinalBuffer, "%s.", FormatBuffer);
  // Show final buffer to user
  MessageBox(Handles.WH, FinalBuffer, WinName, (Line ? MB_ICONEXCLAMATION : MB_ICONINFORMATION) | MB_SYSTEMMODAL);
  // Terminate process
  ExitProcess(Line);
}

VOID SetAllServices(ULONG Value)
{
  PSERVICE SVC = Services;

  while(SVC->Name)
  {
    SVC->Rec = Value;
    SVC++;
  }
}

VOID ProcessCommandLineParameters(VOID)
{
  PCHAR *Arguments = 0;       // Arguments array (argv)
  PCHAR  Argument;            // Current argument being processed
  INT    ArgumentCount = 0;   // Number of arguments in Arguments array (argc)
  PCHAR  ArgumentPointer;     // Pointer to command line
  PCHAR *ArgumentsPointer;    // Pointer to arguments array
  BOOL   InQuotation = FALSE; // In quotations?

  // Retreive command line
  Argument = ArgumentPointer = GetCommandLine();
  if(Argument == NULL)
    Exception(__LINE__, GetLastError(), "Failed to retrieve command line");

  // Walk command line string
  for(;;)
  {
    // Character is a white-space
    if(*ArgumentPointer == 32)
    {
      // In quotation?
      if(InQuotation)
      {
        // Continue to next character
        ++ArgumentPointer;
        // Begin loop again
        continue;
      }
      // Out of quotation, make character null and move to next character
      *ArgumentPointer++ = 0;
      // Fall through and store argument
    }
    // Character is a quote?
    else if(*ArgumentPointer == 34)
    {
      // Make character null and move to next character
      *ArgumentPointer++ = 0;
      // Toggle 'In quotation' and if it is now 1?
      if((InQuotation ^= 1))
      {
        // Skip character
        ++Argument;
        // Begin loop again
        continue;
      }
      // Fall through and store argument
    }
    // Character is insignificant
    else if(*ArgumentPointer)
    {
      // Skip to next cahracter
      ++ArgumentPointer;
      // Begin loop again
      continue;
    }
    // Store argument
    if(ArgumentCount)
      // Not first argument
      Arguments = (PCHAR*)HeapReAlloc(ProcessHeap, 0x4, Arguments, (ArgumentCount + 1) * AddressLength);
    else
      // First argument
      Arguments = (PCHAR*)HeapAlloc(ProcessHeap, 0xC, AddressLength);
    // Store argument in array
    Arguments[ArgumentCount++] = Argument;
    // Walk through all the white-space characters
    while(*ArgumentPointer == 32)
      // Remove them and move to next character
      *ArgumentPointer++ = 0;
    // If there are no more characters to process?
    if(!*ArgumentPointer)
      // At end of command line so break loop
      break;
    // Update beginning of next argument
    Argument = ArgumentPointer;
  }
  // Create space for a new argument
  Arguments = (PCHAR*)HeapReAlloc(ProcessHeap, 0x4, Arguments, (ArgumentCount + 1) * AddressLength);
  // Make it null
  Arguments[ArgumentCount] = NULL;
  // Walk arguments array
  for(ArgumentsPointer = Arguments + 1; *ArgumentsPointer; ++ArgumentsPointer)
  {

    // Compare first character
    switch(**ArgumentsPointer)
    {
      case 45:
      case 47:
      {
        switch(*(++*ArgumentsPointer))
        {
          case 'A': SetAllServices(2);
                    break;
          case 'D': SetAllServices(4);
                    break;
          case 'M': SetAllServices(3);
                    break;
          case 'V': Exception(0, 0, "%s; Version %u.%02u; %u-bit; Created %s.",
                      WinName, VerMaj, VerMin, AddressLength << 3, VerDat);
          case '?': Exception(0, 0, "Usage: LOCKDOWN </[?|V][A|D|M]>\n\n"
                                    "/?\tShow this help message box.\n"
                                    "/A\tSet all services to automatic.\n"
                                    "/D\tSet all services to disabled (not recommended).\n"
                                    "/M\tSet all services to manual (not recommended).\n"
                                    "/V\tShow version information");
          case   0: Exception(0, 0, "Missing parameter after switch character");
          default : Exception(0, 0, "Invalid parameter '%c' specified. Please use '/?' or '-?' for help", **ArgumentsPointer);
        }
        break;
      }
      default: Exception(0, 0, "Invalid switch character '%c' specified. Please use '/?' or '-?' for help", **ArgumentsPointer);
    }
  }
  // Done with arguments array
  HeapFree(ProcessHeap, 0x4, Arguments);
}

INT WinMainCRTStartup(VOID)
{
  WNDCLASS WC;
  MSG      M;
  BOOL     GM;
  HFONT    WF;
  ULONG    TID;

  SecureZeroMemory(&WC, sizeof(WC));

  ProcessHeap = GetProcessHeap();

  ProcessCommandLineParameters();

  WC.style         = CS_HREDRAW | CS_VREDRAW;
  WC.lpfnWndProc   = (WNDPROC)WinProc;
  WC.hInstance     = GetModuleHandle(0);
  WC.hIcon         = LoadIcon(WC.hInstance, MAKEINTRESOURCE(1));
  WC.hCursor       = LoadCursor(0, IDC_ARROW);
  WC.hbrBackground = (HBRUSH)COLOR_WINDOW;
  WC.lpszClassName = WinName;

  RegisterClass(&WC);

  Handles.WH = CreateWindow(WC.lpszClassName, WC.lpszClassName, WS_DLGFRAME|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 384, 384, 0, 0, WC.hInstance, 0);
  Handles.EH = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VSCROLL|WS_VISIBLE|ES_LEFT|ES_MULTILINE|ES_READONLY,  0, 0, 378, 359, Handles.WH, 0, WC.hInstance, 0);
  WF = CreateFont(13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "MS Shell Dlg");

  SendMessage(Handles.EH, WM_SETFONT, (WPARAM)WF, 0);

  ShowWindow(Handles.WH, SW_SHOW);

  TH = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ThreadMain, &Handles, 0, &TID);

  for(;;)
  {
    GM = GetMessage(&M, 0, 0, 0);
    if(GM == 0 || GM == -1)
      break;
    TranslateMessage(&M);
    DispatchMessage(&M);
  }

  TerminateThread(TH, 0);

  UnregisterClass(WC.lpszClassName, WC.hInstance);

  return 0;
}
