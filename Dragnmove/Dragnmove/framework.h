#pragma once
#include <Windows.h>
#include <stdio.h>
#include <oleidl.h>
#include <ShObjIdl_core.h>
#include "detours.h"
#include "GetPayload.h"

WCHAR DragFileW[MAX_PATH] = { 0 };

BOOL DetachHooks();

HRESULT(*pOrigDragEnter)(
	LPVOID lpDropTarget,
	IDataObject*,
	DWORD,
	POINTL,
	DWORD*
	);

HRESULT(*pOrigDrop)(
	LPVOID lpDropTarget,
	IDataObject* pDataObj,
	DWORD       grfKeyState,
	POINTL      pt,
	DWORD* pdwEffect
	);

HANDLE(WINAPI* pCreateFileA)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

HANDLE(WINAPI* pCreateFileW)(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

HANDLE (WINAPI* pGetClipboardData)(
	UINT uFormat
);

HRESULT (WINAPI* pOleGetClipboard)(
	LPDATAOBJECT* ppDataObj
);

typedef struct _THREAD_PARAM {
	HANDLE hWritePipe;
	LPVOID lpBuffer;
} THREAD_PARAM, *PTHREAD_PARAM;

