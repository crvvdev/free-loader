#pragma once

#include <BlackBone/Syscalls/Syscall.h>
#include <CryptoPP/sha.h>

static std::string trim(std::string& str)
{
	size_t first = str.find_first_not_of(' ');
	if (first == std::string::npos)
		return "";
	size_t last = str.find_last_not_of(' ');
	return str.substr(first, (last - first + 1));
}

static std::string random_string(size_t length)
{
	srand(GetTickCount());
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}

static bool GenerateHardDiskHash(std::string& szHWID)
{
	VM_REGION_START;
	/*
	std::string hardware_digest = "";

	if (dwSerialNumberOffset)
	{
		const char* serialNumber = reinterpret_cast<const char*>(pOutBuffer.get() + dwSerialNumberOffset);
		hardware_digest += serialNumber;
	}

	if (dwProductIdOffset)
	{
		const char* productId = reinterpret_cast<const char*>(pOutBuffer.get() + dwProductIdOffset);
		hardware_digest += productId;
	}

	if (dwVendorIdOffset)
	{
		const char* vendorId = reinterpret_cast<const char*>(pOutBuffer.get() + dwVendorIdOffset);
		hardware_digest += vendorId;
	}

	if (hardware_digest.empty())
	{
		utils::Error(XorStr("Failed to generate computer uniqueid!"), res);
		return false;
	}

	hardware_digest = trim(hardware_digest);

	CryptoPP::SHA256 hash;
	byte digest[CryptoPP::SHA256::DIGESTSIZE];

	hash.CalculateDigest(digest, (byte*)hardware_digest.c_str(), hardware_digest.length());

	CryptoPP::HexEncoder encoder;
	std::string output;
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	szHWID = output;

	hardware_digest.clear();
	output.clear();

	szHWID.clear();

	// Format physical drive path (may be '\\\\.\\PhysicalDrive0', '\\\\.\\PhysicalDrive1' and so on).
	// Note: backslash is used as escape in WQL, so we need to double each one.
	CStringW strDrivePath;
	strDrivePath.Format(XorStr(L"\\\\\\\\.\\\\PhysicalDrive0"));

	// 2. Set the default process security level
	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa393617(v=vs.85).aspx
	HRESULT hr = ::CoInitializeSecurity(
		NULL,                        // Security descriptor
		-1,                          // COM negotiates authentication service
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication level for proxies
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation level for proxies
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities of the client or server
		NULL);                       // Reserved

	if (FAILED(hr))
	{
		std::string message = std::system_category().message(hr);
		utils::Error("CoInitializeSecurity failed %s", message.c_str());
		return true;
	}

	// 3. Create a connection to WMI namespace
	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa389749(v=vs.85).aspx

	// 3.1. Initialize the IWbemLocator interface
	CComPtr<IWbemLocator> pIWbemLocator;
	hr = ::CoCreateInstance(CLSID_WbemLocator, 0,
		CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)& pIWbemLocator);

	if (FAILED(hr))
	{
		std::string message = std::system_category().message(hr);
		utils::Error("CoCreateInstance failed %s", message.c_str());
		return true;
	}

	// 3.2. Call IWbemLocator::ConnectServer for connecting to WMI
	CComPtr<IWbemServices> pIWbemServices;
	hr = pIWbemLocator->ConnectServer(L"ROOT\\CIMV2",
		NULL, NULL, 0, NULL, 0, 0, &pIWbemServices);

	if (FAILED(hr))
	{
		std::string message = std::system_category().message(hr);
		utils::Error("ConnectServer failed %s", message.c_str());
		return true;
	}

	// 4. Set the security levels on WMI connection
	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa393619(v=vs.85).aspx
	hr = ::CoSetProxyBlanket(
		pIWbemServices,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE);

	if (FAILED(hr))
	{
		std::string message = std::system_category().message(hr);
		utils::Error("CoSetProxyBlanket failed %s", message.c_str());
		return true;
	}

	// 5. Execute a WQL (WMI Query Language) query to get the wanted phisical drive serial number
	const BSTR szQueryLanguage = L"WQL";
	CStringW strQuery;
	strQuery.Format(VM_ENC_STR_W(L"SELECT SerialNumber FROM Win32_PhysicalMedia WHERE Tag=\"%s\""),
		strDrivePath);

	CComPtr<IEnumWbemClassObject> pIEnumWbemClassObject;
	hr = pIWbemServices->ExecQuery(
		szQueryLanguage,                                       // Query language
		(BSTR)strQuery.GetString(),                            // Query
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,   // Flags
		NULL,                                                  // Context
		&pIEnumWbemClassObject);                               // Enumerator

	if (FAILED(hr))
	{
		std::string message = std::system_category().message(hr);
		utils::Error("ExecQuery failed %s", message.c_str());
		return true;
	}

	// 6. Get first enumerator element. If exists, get the serial number.
	ULONG uReturn = 0;
	CComPtr<IWbemClassObject> pIWbemClassObject;
	hr = pIEnumWbemClassObject->Next(WBEM_INFINITE, 1, &pIWbemClassObject, &uReturn);

	if (WBEM_S_NO_ERROR != hr)
	{
		std::string message = std::system_category().message(hr);
		utils::Error("Next failed %s", message.c_str());
		return true;
	}

	variant_t vtSerialNumber;  // manufacturer-provided serial number
	hr = pIWbemClassObject->Get(XorStr(L"SerialNumber"), 0, &vtSerialNumber, NULL, NULL);

	if ( FAILED(hr) )
	{
		std::string message = std::system_category().message(hr);
		utils::Error("Get failed %s", message.c_str());
		return true;
	}*/

	HANDLE hPhysicalDriveIOCTL = CreateFileW(XorStr(L"\\\\.\\PhysicalDrive0"), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hPhysicalDriveIOCTL == INVALID_HANDLE_VALUE)
	{
		utils::Error("CreateFileW error code: %d", GetLastError());
		return false;
	}

	std::unique_ptr<std::remove_pointer<HANDLE>::type, void(*)(HANDLE)> hDevice{ hPhysicalDriveIOCTL, [](HANDLE handle) {CloseHandle(handle); } };

	STORAGE_PROPERTY_QUERY storagePropertyQuery{};
	storagePropertyQuery.PropertyId = StorageDeviceProperty;
	storagePropertyQuery.QueryType = PropertyStandardQuery;

	STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader{};

	IO_STATUS_BLOCK isb;
	auto res = blackbone::syscall::nt_syscall(
		blackbone::syscall::get_index(XorStr("NtDeviceIoControlFile")),
		hDevice.get(),
		NULL,
		NULL,
		NULL,
		&isb,
		IOCTL_STORAGE_QUERY_PROPERTY,
		&storagePropertyQuery,
		sizeof(STORAGE_PROPERTY_QUERY),
		&storageDescriptorHeader,
		sizeof(STORAGE_DESCRIPTOR_HEADER));

	if (!NT_SUCCESS(res))
	{
		utils::Error("Device[0] error code: %X", res);
		return false;
	}

	//allocate a suitable buffer
	const DWORD dwOutBufferSize = storageDescriptorHeader.Size;
	std::unique_ptr<BYTE[]> pOutBuffer{ new BYTE[dwOutBufferSize]{} };

	//call DeviceIoControl with the allocated buffer
	res = blackbone::syscall::nt_syscall(
		blackbone::syscall::get_index(XorStr("NtDeviceIoControlFile")),
		hDevice.get(),
		NULL,
		NULL,
		NULL,
		&isb,
		IOCTL_STORAGE_QUERY_PROPERTY,
		&storagePropertyQuery,
		sizeof(STORAGE_PROPERTY_QUERY),
		pOutBuffer.get(),
		dwOutBufferSize);

	if (!NT_SUCCESS(res))
	{
		utils::Error("Device[1] error code: %X", res);
		return false;
	}

	//read and return the serial number out of the output buffer
	STORAGE_DEVICE_DESCRIPTOR* pDeviceDescriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(pOutBuffer.get());

	const auto dwSerialNumberOffset = pDeviceDescriptor->SerialNumberOffset;
	const char* serialNumber = reinterpret_cast<const char*>(pOutBuffer.get() + dwSerialNumberOffset);

	char szUserName[256] = { 0 };
	DWORD max_len = 256;

	GetComputerNameA(szUserName, &max_len);

	std::stringstream wss;
	wss << szUserName << serialNumber;

	CryptoPP::SHA256 hash;
	byte digest[CryptoPP::SHA256::DIGESTSIZE];

	hash.CalculateDigest(digest, (byte*)wss.str().data(), wss.str().length());

	CryptoPP::HexEncoder encoder;
	std::string output;
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

	szHWID = output;
	output.clear();

	VM_REGION_END;
	return true;
}

static void NukeLoginusers()
{
	HKEY hKey = 0;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Valve\\Steam", 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey) != ERROR_SUCCESS)
	{
		utils::Error("RegOpenKeyW failed %d", GetLastError());
		return;
	}

	DWORD dwType = REG_SZ;
	wchar_t buf[255] = { 0 };
	DWORD dwBufSize = sizeof(buf);

	if (RegQueryValueExW(hKey, L"InstallPath", NULL, &dwType, reinterpret_cast<LPBYTE>(&buf), &dwBufSize) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		utils::Error("RegQueryValueExW failed %d", GetLastError());
		return;
	}

	RegCloseKey(hKey);

	//for (const auto & entry : fs::directory_iterator(path))
	//	std::cout << entry.path() << std::endl;

	wcscat_s(buf, VM_ENC_STR_W(L"\\config\\config.vdf"));
	DeleteFileW(buf);
	/*DWORD attrib = GetFileAttributesW(buf);

	if (attrib == INVALID_FILE_ATTRIBUTES)
	{
		utils::Error("Invalid steam file!");
		return;
	}

	const bool is_read_only = (attrib & FILE_ATTRIBUTE_READONLY);

	if (!is_read_only)
	{
		std::ofstream ofs(buf, std::ofstream::out | std::ofstream::trunc);
		ofs.close();

		SetFileAttributesW(buf, FILE_ATTRIBUTE_READONLY);
	}*/
}

static void GetPCInformation(IDirect3D9* dev)
{
	D3DADAPTER_IDENTIFIER9 adp;
	ZeroMemory(&adp, sizeof D3DADAPTER_IDENTIFIER9);

	HRESULT hr = 0;

	if (FAILED(hr = dev->GetAdapterIdentifier(D3DADAPTER_DEFAULT, 0, &adp)))
	{

	}

	//const int cch = sizeof(adp.Description);
	//TCHAR szDescription[cch];
	//DXUtil_ConvertAnsiStringToGenericCch(szDescription, AdapterIdentifier.Description, cch);
}

class Timer
{
public:
	void start()
	{
		m_StartTime = std::chrono::system_clock::now();
		m_bRunning = true;
	}

	void stop()
	{
		m_EndTime = std::chrono::system_clock::now();
		m_bRunning = false;
	}

	auto elapsedMilliseconds()
	{
		std::chrono::time_point<std::chrono::system_clock> endTime;

		if (m_bRunning)
		{
			endTime = std::chrono::system_clock::now();
		}
		else
		{
			endTime = m_EndTime;
		}

		return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - m_StartTime).count();
	}

	double elapsedSeconds()
	{
		return elapsedMilliseconds() / 1000.0;
	}

private:
	std::chrono::time_point<std::chrono::system_clock> m_StartTime;
	std::chrono::time_point<std::chrono::system_clock> m_EndTime;
	bool                                               m_bRunning = false;
};

struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}
	}
};

static std::uint32_t Proc_LdrLoadDll = 0;

#pragma pack( push, 1 )
struct SEND_RCV
{
	std::uint32_t addresses[10];
	std::uint8_t bytes[10][10];
	std::int32_t counter;
};
#pragma pack( pop )

#include <map>

static std::vector< std::pair< std::uint32_t, std::uint8_t* > > ntdll_map;

//static DWORD WINAPI CreatePipe(PVOID)
//{
//	constexpr std::wstring_view PipeName = L"\\\\.\\pipe\\PipeCom";
//
//	SEND_RCV buffer;
//	ZeroMemory(&buffer, sizeof buffer);
//
//	int i = 0;
//	DWORD NumofBytes = 0;
//
//	auto hpipe = std::unique_ptr<HANDLE, HandleDisposer>(
//		CreateNamedPipeW(
//			PipeName.data(),
//			PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
//			1,
//			sizeof SEND_RCV,
//			sizeof SEND_RCV,
//			0,
//			NULL));
//
//	if (hpipe.get() == INVALID_HANDLE_VALUE)
//		return 0;
//
//	if (ConnectNamedPipe(hpipe.get(), NULL != FALSE))
//	{
//		while (ReadFile(hpipe.get(), &buffer, sizeof(buffer), &NumofBytes, NULL) != FALSE)
//		{
//			ntdll_map.push_back({ buffer.addresses[buffer.counter], buffer.bytes[buffer.counter] });
//		}
//	}
//
//	DisconnectNamedPipe(hpipe.get());
//	return 0;
//}

namespace Modules
{
	//MODULEENTRY32 GetRemoteModule(std::uint32_t pid, wchar_t const* module_name);
	HMODULE GetRemoteModuleHandle(HANDLE hProcess, wchar_t const* module_name);
	bool GetRemoteModuleExportDirectory(HANDLE hProcess, HMODULE hRemote, PIMAGE_EXPORT_DIRECTORY ExportDirectory, IMAGE_DOS_HEADER DosHeader, IMAGE_NT_HEADERS NtHeaders);
	DWORD GetRemoteFuncAddress(HANDLE hProcess, wchar_t const* module, char* func);
}