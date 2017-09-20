#include "stdafx.h"
#include "util.h"
#include "../../../include/instrument/ErrorCodes100.h"
#include "../../../include/instrument/SmartShells.h"
#include "../../../include/instrument/ESTypes100.h"
#include <psapi.h>


static LPCTSTR g_rmLibName = "rstrtmgr.dll";
static LPCTSTR g_kernelLibName = "kernel32.dll";
static LPCTSTR g_ntdllLibName = "ntdll.dll";

template<class FuncPtr>
static void iniProc(bool& fail, FuncPtr& var, LPCTSTR name, HMODULE lib)
{
	if( !lib )
	{
		fail = true;
	}
	else
	{
		var = lib ? reinterpret_cast<FuncPtr>(GetProcAddress(lib, name)) : 0;
		if( !var )
			fail = true;
	}
}

RmFuncs::RmFuncs():
	_lib   (LoadLibrary(g_rmLibName)),
	_kernel(LoadLibrary(g_kernelLibName))
{
	bool fail = false;
	
	iniProc(fail, startSession,      "RmStartSession", _lib);
	iniProc(fail, registerResources, "RmRegisterResources", _lib);
	iniProc(fail, getList,           "RmGetList", _lib);
	iniProc(fail, endSession,        "RmEndSession", _lib);
	
	iniProc(fail, queryFullProcessImageNameA, "QueryFullProcessImageNameA", _kernel);
	
	if( fail )
	{
		FreeLibrary(_lib);
		_lib = 0;
	}
}

RmFuncs::~RmFuncs()
{
	FreeLibrary(_lib);
	FreeLibrary(_kernel);
}

RmSession::RmSession(RmFuncs& rmFuncs):
	_rm(rmFuncs), _handle(0), _readyToFight(false)
{
	zeroVar(_sessionKey);
	
	if( !_rm._lib )
		return;
	
	DWORD error = (*_rm.startSession)(&_handle, 0, _sessionKey);
	if( 0 == error )
	{
		_readyToFight = true;
	}
	else
	{
		//CWin32Exception::Throw(1, error, "RmStartSession failed");
	}
}

RmSession::~RmSession()
{
	if( _handle )
		(*_rm.endSession)(_handle);
}

static string wtostr(LPCWSTR wideStr, int charCount = -1)
{
	DWORD len = (charCount < 0 ? lstrlenW(wideStr) : charCount) + 1;
	CHAR* result = new_stack_arr(CHAR, len);
	if( 0 == WideCharToMultiByte(
					CP_ACP, 0,
					wideStr, charCount < 0 ? -1 : charCount+1,
					result, len,
					"?", NULL) )
		result[0] = 0;
	return result;
}

static bool strequalnocase(const string& a, const string& b)
{
	return CSTR_EQUAL == CompareString(
			MAKELCID(MAKELANGID(LANG_RUSSIAN, SUBLANG_DEFAULT), SORT_DEFAULT),
			NORM_IGNORECASE,
			a.c_str(), a.size(),
			b.c_str(), b.size()
	);
}

#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

static string errText(LPCTSTR part1, LPCTSTR part2, DWORD code)
{
	TCHAR ret[256] = "";
	
	strcatbuf(ret, "{");
	
	if( part1 )
	{
		strcatbuf(ret, part1);
		if( part2 )
			strcatbuf(ret, ". ");
	}
	
	if( part2 )
	{
		strcatbuf(ret, part2);
		if( 0 != code )
			strcatbuf(ret, ". ");
	}
	
	if( 0 != code )
	{
		TCHAR codeStr[32];
		sprintf(codeStr, "%u", code);
		strcatbuf(ret, codeStr);
	}
	
	strcatbuf(ret, "}");
	
	return ret;
}

static string w32errText(DWORD error, LPCTSTR comment)
{
	TCHAR w32text[256];
	CWin32Exception::GetWin32ErrorText(w32text, sizeofa(w32text), error);
	
	return errText(comment, w32text, 0);
}

string RmSession::whoLocked(LPCTSTR fileName)
{
	if( !fileName || 0 == fileName[0] || !_readyToFight )
		return string();

	DWORD buffLen = lstrlen(fileName) + 1;
	LPWSTR fileNameW = new_stack_arr(WCHAR, buffLen);
	MultiByteToWideChar(CP_ACP, 0, fileName, -1, fileNameW, buffLen);
	LPCWSTR fileNameWConst = fileNameW;
	DWORD error = (*_rm.registerResources)(_handle, 1, &fileNameWConst, 0, 0, 0, 0);
	if( 0 != error )
		return w32errText(error, "RmRegisterResources failed");
	
	DWORD reason = 0;
	UINT processes = 0;
	UINT pisSize = 0;
	error = (*_rm.getList)(_handle, &pisSize, &processes, 0, &reason);
	if( 0 != error && ERROR_MORE_DATA != error )
		return w32errText(error, "RmGetList failed (get proc count)");
	if( 0 == pisSize )
		return string();

	RM_PROCESS_INFO* pis = new_stack_arr(RM_PROCESS_INFO, pisSize);
	processes = pisSize;
	error = (*_rm.getList)(_handle, &pisSize, &processes, pis, &reason);
	if( 0 != error )
		return w32errText(error, "RmGetList failed (get proc info)");
	
	string result;
	for(UINT procIndex = 0; procIndex < processes; ++procIndex)
	{
		const RM_PROCESS_INFO& procInfo = pis[procIndex];
		CHandleNull proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
				FALSE, procInfo.Process.dwProcessId);
		if( !!proc )
		{
			FILETIME ftCreate, ftExit, ftKernel, ftUser;
			if( GetProcessTimes(proc, &ftCreate, &ftExit, &ftKernel, &ftUser) &&
					0 == CompareFileTime(&procInfo.Process.ProcessStartTime, &ftCreate) )
			{
				TCHAR procImage[MAX_PATH + 1];
				DWORD procImageLen = MAX_PATH;
				bool procImageFilled = false;
				if( _rm.queryFullProcessImageNameA )
				{
					procImageFilled = 
							0 != (*_rm.queryFullProcessImageNameA)(proc, 0, procImage, &procImageLen);
				}
				
				string procDescr;
				
				TCHAR procIdStr[32] = "";
				sprintf(procIdStr, "[%u] ", procInfo.Process.dwProcessId);
				procDescr += procIdStr;
				
				bool appendImageName = true;
				switch(procInfo.ApplicationType)
				{
					case RmService:
						procDescr += "Служба ";
						procDescr += wtostr(procInfo.strServiceShortName);
						break;
					case RmExplorer:
						procDescr += "Проводник (Windows Explorer)";
						appendImageName = false;
						break;
					case RmConsole:
						procDescr += "Консоль ";
						procDescr += wtostr(procInfo.strAppName);
						break;
					default:
						procDescr += "Приложение ";
						procDescr += wtostr(procInfo.strAppName);
				}
				if( procImageFilled && appendImageName )
				{
					procDescr += " (";
					procDescr += procImage;
					procDescr += ")";
				}
				
				result += procDescr;
				result += "\n";
			}
		}
	}
	
	return result;
}

NtHandleCollector::NtHandleCollector():
	_ntdll(LoadLibrary(g_ntdllLibName)),
	_kernel(LoadLibrary(g_kernelLibName))
{
	bool fail = false;
	
	iniProc(fail, NtQuerySystemInformation,  "NtQuerySystemInformation", _ntdll);
	iniProc(fail, NtDuplicateObject,         "NtDuplicateObject", _ntdll);
	iniProc(fail, NtQueryObject,             "NtQueryObject", _ntdll);
	
	iniProc(fail, QueryFullProcessImageName, "QueryFullProcessImageNameA", _kernel);
	
	if( fail )
	{
		FreeLibrary(_ntdll);
		_ntdll = 0;
	}
}

NtHandleCollector::~NtHandleCollector()
{
	FreeLibrary(_ntdll);
}

#pragma pack(push, 1)

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020 
#define FILE_SEQUENTIAL_ONLY 0x00000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
#define ProcessBasicInformation 0
#define ProcessImageFileName 27

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

class CUnicodeString
{
	UNICODE_STRING* _data;
	bool _owns;
	
public:
	CUnicodeString():
		_data(0), _owns(false)
	{}
	
	~CUnicodeString()
	{
		if( _owns && _data )
			free(_data);
	}
	
	NTSTATUS loadObjectName(NtHandleCollector& funcs, HANDLE handle)
	{
		Assert(!_data);

		static const DWORD INITIAL_SIZE = 512;
		
		_data = static_cast<UNICODE_STRING*>(malloc(INITIAL_SIZE));
		_owns = true;
		DWORD needSize = 0;
		if( !NT_SUCCESS(funcs.NtQueryObject(
						handle, ObjectNameInformation, _data, INITIAL_SIZE, &needSize)) )
		{
			_data = static_cast<UNICODE_STRING*>(realloc(_data, needSize));
			return funcs.NtQueryObject(handle, ObjectNameInformation, _data,
					needSize, NULL);
		}
		else
			return 0;
	}
	
	CUnicodeString& wrap(UNICODE_STRING& object)
	{
		_data = &object;
		return *this;
	}
	
	string value()
	{
		if( !_data || 0 == _data->Length || !_data->Buffer || 0 == _data->Buffer[0] )
			return string();
		return wtostr(_data->Buffer, _data->Length/2);
	}
};

struct SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
};

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION;

class CSystemHandleInformation
{
	SYSTEM_HANDLE_INFORMATION* _data;
	DWORD _dataSize; // в байтах

public:
	CSystemHandleInformation():
		_data(0), _dataSize(1024*1024)
	{}
	
	~CSystemHandleInformation()
	{
		if( _data )
			free(_data);
	}
	
	void allocMore()
	{
		if( !_data )
		{
			_data = static_cast<SYSTEM_HANDLE_INFORMATION*>(malloc(_dataSize));
		}
		else
		{
			_dataSize *= 2;
			_data = static_cast<SYSTEM_HANDLE_INFORMATION*>(realloc(_data, _dataSize));
		}
	}
	
	void* bytesPointer()
	{
		return _data;
	}
	
	DWORD bytesLength()
	{
		return _data ? _dataSize : 0;
	}
	
	DWORD size()
	{
		return _data ? _data->HandleCount : 0;
	}
	
	const SYSTEM_HANDLE& at(DWORD index)
	{
		Assert(_data);
		return _data->Handles[index];
	}
};

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION;

class CObjectTypeInformation
{
	OBJECT_TYPE_INFORMATION* _data;
	static const DWORD LENGTH = 65536;

public:
	CObjectTypeInformation():
		_data(static_cast<OBJECT_TYPE_INFORMATION*>(malloc(LENGTH)))
	{}
	
	~CObjectTypeInformation()
	{
		if( _data )
			free(_data);
	}
	
	DWORD bytesLength()
	{
		return LENGTH;
	}
	
	OBJECT_TYPE_INFORMATION& value()
	{
		return *_data;
	}
};

#pragma pack(pop)

struct NtHandleCollector_whoLocked_Prm
{
	NtHandleCollector* _this;
	LPCTSTR _fileName;
	string _result;
};

static DWORD WINAPI NtHandleCollector_whoLocked(void* params)
{
	NtHandleCollector_whoLocked_Prm* prm =
			static_cast<NtHandleCollector_whoLocked_Prm*>(params);
	prm->_result = prm->_this->whoLocked(prm->_fileName);
	return 0;
}

string NtHandleCollector::whoLockedInThread(LPCTSTR fileName, DWORD maxTimeMs)
{
	NtHandleCollector_whoLocked_Prm prm;
	prm._this = this;
	prm._fileName = fileName;
	
	DWORD id = 0;
	CHandleInv thread = CreateThread(NULL, 0, &NtHandleCollector_whoLocked, &prm, 0, &id);
	if( WAIT_TIMEOUT == WaitForSingleObject(thread, maxTimeMs) )
	{
		TerminateThread(thread, 1);
	}
	
	return prm._result;
}

string NtHandleCollector::whoLocked(LPCTSTR fileNameInp)
{
	static const string FILE_TYPE_STRING = "File";
	static const string FILE_SECTION_STRING = "Section";

	if( !_ntdll || !fileNameInp || 0 == fileNameInp[0] )
		return string();
	
	string fileName;
	{
		const int fileNameInpLen = lstrlen(fileNameInp);
		fileName.reserve(fileNameInpLen+4);
		fileName.push_back('\\');
		LPCTSTR inp = fileNameInp;
		if( fileNameInpLen > 3 &&
				fileNameInp[1] == ':' && fileNameInp[2] == '\\' )
			inp = fileNameInp+3;
		else if( fileNameInpLen > 0 && fileNameInp[0] == '\\' )
			inp = fileNameInp+1;
		
		bool prevSlash = false;
		for(; *inp != 0; ++inp)
		{
			TCHAR ch = *inp;
			if( ch == '/' )
				ch = '\\';
			if( ch == '\\' )
			{
				if( prevSlash )
					continue;
				else
					prevSlash = true;
			}
			else
				prevSlash = false;
			fileName.push_back(ch);
		}
	}
	
	NTSTATUS status;
	const DWORD myPID = GetCurrentProcessId();
	
	// Вытащим из системы полный список хэндлов, инкрементально выделяя память,
	// пока не вытащится
	CSystemHandleInformation handleInfo;
	do
	{
		handleInfo.allocMore();
		status = NtQuerySystemInformation(
				SystemHandleInformation,
				handleInfo.bytesPointer(),
				handleInfo.bytesLength(),
				NULL);
	}
		while(status == STATUS_INFO_LENGTH_MISMATCH);
	if( !NT_SUCCESS(status) )
		return errText("NtQuerySystemInformation error", NULL, status);
	
	string result;
	
	CObjectTypeInformation objectType; // для оптимизации один объект
	for(DWORD hindex = handleInfo.size(); hindex > 0; --hindex)
	{
		const SYSTEM_HANDLE& h = handleInfo.at(hindex-1);
		
		// нас не интересуют хэндлы нашего процесса
		if( h.ProcessId == myPID )
			continue;
		
		CHandleNull sourceProcHandle = OpenProcess(
				PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
				FALSE, h.ProcessId);
		if( !sourceProcHandle )
			continue;

		CHandleNull handle;
		{
			HANDLE temp;
			if( !NT_SUCCESS(NtDuplicateObject(
							sourceProcHandle,
							(HANDLE)h.Handle,
							GetCurrentProcess(),
							&temp,
							0, 0, DUPLICATE_SAME_ACCESS)) )
			{
				continue;
			}
			handle = temp;
		}

		if( !NT_SUCCESS(NtQueryObject(
						handle,
						ObjectTypeInformation,
						&objectType.value(),
						objectType.bytesLength(),
						NULL)) )
		{
			continue;
		}
		const string objectTypeStr = CUnicodeString().wrap(objectType.value().Name).value();
		
		/*if( strequalnocase(FILE_TYPE_STRING, objectTypeStr) )
		{
			_onFile(result, fileName, h, handle, sourceProcHandle);
			continue;
		}*/
		if( strequalnocase(FILE_SECTION_STRING, objectTypeStr) )
		{
			_onSection(result, fileName, h, handle, sourceProcHandle);
			continue;
		}
	}
	
	return result;
}

void NtHandleCollector::_putProcToResult(string& result, const struct SYSTEM_HANDLE& h,
	HANDLE sourceProcHandle)
{
	TCHAR pidStr[32] = "";
	sprintf(pidStr, "[%u] ", h.ProcessId);
	result += pidStr;
	
	//NtQueryInformationProcess.ProcessImageFileName
	TCHAR exeName[MAX_PATH+1] = "";
	DWORD exeNameBufLen = sizeofa(exeName);
	if( QueryFullProcessImageName(sourceProcHandle, 0, exeName, &exeNameBufLen) )
	{
		result += exeName;
	}
	
	result += "\n";
}

void NtHandleCollector::_onSection(string& result, const string& fileName,
	const struct SYSTEM_HANDLE& h, HANDLE handle, HANDLE sourceProcHandle)
{
	void* mem = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, 1);
	if( mem )
	{
		// Удалось замэпить в наш процесс!
		TCHAR mapFileName[MAX_PATH+1] = "";
		if( 0 != GetMappedFileName(GetCurrentProcess(), mem, mapFileName,
						sizeofa(mapFileName)) )
		{
			DWORD mapFileNameLen = lstrlen(mapFileName);
			if( mapFileNameLen >= fileName.size() )
			{
				const string name = mapFileName + (mapFileNameLen - fileName.size());
				if( strequalnocase(fileName, name) )
					_putProcToResult(result, h, sourceProcHandle);
			}
		}
		
		UnmapViewOfFile(mem);
	}
	else
	{
		ATLTRACE2("Section %x @ %u; access %08x\n", h.Handle, h.ProcessId, h.GrantedAccess);
	}
}

void NtHandleCollector::_onFile(string& result, const string& fileName,
	const struct SYSTEM_HANDLE& h, HANDLE handle, HANDLE sourceProcHandle)
{
	// это именованный канал, он на получении имени может тупо повиснуть
	// тут про это подробнее: https://forum.sysinternals.com/topic14435_page1.html
	// Ну и главное - похоже, нам не нужны файлы!
	// ERROR_SHARING_VIOLATION должен найтись через RmFuncs, а для ошибки
	// ERROR_USER_MAPPED_FILE файл не числится среди хэндлов файлов, его держит хэндл
	// memory mapping, т.е. надо анализировать тип "Section", где именованных каналов
	// и не бывает. Попробовать можно через GetMappedFileName
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms683195(v=vs.85).aspx
	/* И это не работает, права 0x00120089 есть и у обычных файлов и у именованных каналов
	if( ((SYNCHRONIZE | READ_CONTROL | FILE_SEQUENTIAL_ONLY)) ==
			((SYNCHRONIZE | READ_CONTROL | FILE_SEQUENTIAL_ONLY) & h.GrantedAccess) )
		continue;*/
	/* Этот вариант получше, но увидел named pipe с правами 0012008d, это вообще без
		  FILE_SYNCHRONOUS_ флагов
	if( 0 != (h.GrantedAccess & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) &&
			(SYNCHRONIZE | READ_CONTROL) == (h.GrantedAccess & (SYNCHRONIZE | READ_CONTROL)) )
		continue;*/
	/* Этот вариант простой, но по факту встречаются и другие
	if( h.GrantedAccess == 0x0012019f )
		continue;*/

	ATLTRACE2("File %x @ %u; access %08x\n", h.Handle, h.ProcessId, h.GrantedAccess);
	CUnicodeString nameUnicode;
	if( !NT_SUCCESS(nameUnicode.loadObjectName(*this, handle)) )
		return;
	string name = nameUnicode.value();
	
	if( name.size() >= fileName.size() )
	{
		if( name.size() > fileName.size() )
			name.swap(name.substr(name.size() - fileName.size()));
		if( strequalnocase(fileName, name) )
			_putProcToResult(result, h, sourceProcHandle);
	}
}
