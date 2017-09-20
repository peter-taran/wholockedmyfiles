#pragma once

class DllHandle
{
private:
	HMODULE	_h;

public:
	DllHandle() : _h(NULL) {}
	~DllHandle()
	{
		free();
	}

	void attach(HMODULE h)
	{
		if(_h) ::FreeLibrary(_h);
		_h = h;
	}

	HMODULE detach()
	{
		HMODULE h = _h;
		_h = NULL;
		return h;
	}

	void free()
	{
		attach(NULL);
	}

	operator HMODULE() const
	{
		return _h;
	}
};

inline CRect GetChildRect(CWindow* parent, CWindow& child)
{
	CRect rect;
	child.GetWindowRect(&rect);
	parent->ScreenToClient(&rect);
	return rect;
}

inline CRect GetChildRect(CWindow* parent, int idc)
{
	return GetChildRect(parent, parent->GetDlgItem(idc));
}

// функции либы rstrtmgr.dll
#include "restartmanager.h"
struct RmFuncs
{
	HMODULE _lib;
	HMODULE _kernel;
	
	DWORD (WINAPI *startSession)(
		DWORD *pSessionHandle,
		DWORD dwSessionFlags,
		WCHAR strSessionKey[ ]
	);
	
	DWORD (WINAPI *registerResources)(
		DWORD dwSessionHandle,
		UINT nFiles,
		LPCWSTR rgsFilenames[ ],
		UINT nApplications,
		RM_UNIQUE_PROCESS rgApplications[ ],
		UINT nServices,
		LPCWSTR rgsServiceNames[ ]
	);

	DWORD (WINAPI *getList)(
		DWORD dwSessionHandle,
		UINT *pnProcInfoNeeded,
		UINT *pnProcInfo,
		RM_PROCESS_INFO rgAffectedApps[ ],
		LPDWORD lpdwRebootReasons
	);

	DWORD (WINAPI *endSession)(
		DWORD dwSessionHandle
	);
	
	BOOL (WINAPI *queryFullProcessImageNameA)(
		HANDLE hProcess,
		DWORD dwFlags,
		LPTSTR lpExeName,
		PDWORD lpdwSize
	);
	
	RmFuncs();
	~RmFuncs();
};

// одна сессия работы с rstrtmgr.dll
struct RmSession
{
	RmFuncs& _rm;
	WCHAR _sessionKey[CCH_RM_SESSION_KEY+1];
	DWORD _handle;
	bool _readyToFight;
	
	RmSession(RmFuncs& rmFuncs);
	~RmSession();
	
	string whoLocked(LPCTSTR fileName);
};


// Для сбора системной информации об открытых хэндлах
struct NtHandleCollector
{
	HMODULE _ntdll;
	HMODULE _kernel;
	
	NTSTATUS (NTAPI *NtQuerySystemInformation)(
			ULONG SystemInformationClass,
			PVOID SystemInformation,
			ULONG SystemInformationLength,
			PULONG ReturnLength
			);
	NTSTATUS (NTAPI *NtDuplicateObject)(
			HANDLE SourceProcessHandle,
			HANDLE SourceHandle,
			HANDLE TargetProcessHandle,
			PHANDLE TargetHandle,
			ACCESS_MASK DesiredAccess,
			ULONG Attributes,
			ULONG Options
			);
	NTSTATUS (NTAPI *NtQueryObject)(
			HANDLE ObjectHandle,
			ULONG ObjectInformationClass,
			PVOID ObjectInformation,
			ULONG ObjectInformationLength,
			PULONG ReturnLength
			);
	
	BOOL (WINAPI* QueryFullProcessImageName)(
			HANDLE hProcess,
			DWORD dwFlags,
			LPTSTR lpExeName,
			PDWORD lpdwSize
			);

	NtHandleCollector();
	~NtHandleCollector();
	
	string whoLocked(LPCTSTR fileName);
	
	string whoLockedInThread(LPCTSTR fileName, DWORD maxTimeMs);
	
	void _putProcToResult(string& result, const struct SYSTEM_HANDLE& h,
			HANDLE sourceProcHandle);
	void _onFile(string& result, const string& fileName, const struct SYSTEM_HANDLE& h,
			HANDLE handle, HANDLE sourceProcHandle);
	void _onSection(string& result, const string& fileName, const struct SYSTEM_HANDLE& h,
			HANDLE handle, HANDLE sourceProcHandle);
};
