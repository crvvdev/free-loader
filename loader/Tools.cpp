#include "Includes.hpp"
#include "WinStruct.hpp"

#pragma warning( push )
#pragma warning( disable : 4312)
#pragma warning( disable : 4311)
#pragma warning( disable : 4302)
#pragma warning( disable : 4018)
namespace Modules
{
	HMODULE GetRemoteModuleHandle(HANDLE m_hProcess, const wchar_t* Module)
	{
		PVOID dwModuleHandle = NULL;

		ULONG_PTR PebBaseAddress = 0;
		NTSTATUS status = STATUS_SUCCESS;
		status = NtQueryInformationProcess(m_hProcess, ProcessWow64Information, &PebBaseAddress, sizeof(ULONG_PTR), 0);
		if (!NT_SUCCESS(status))
			return NULL;

		_PEB32 peb;
		_PEB_LDR_DATA232 peb_ldr;
		using _LIST_ENTRY32 = _LIST_ENTRY_T< std::uint32_t >;

		SIZE_T dwBytesRead = 0;
		if (!ReadProcessMemory(m_hProcess, (LPCVOID)PebBaseAddress, &peb, sizeof(peb), &dwBytesRead))
		{
			return 0;
		}

		bool ldr_not_found = ReadProcessMemory(m_hProcess, (LPCVOID)peb.Ldr, &peb_ldr, sizeof(peb_ldr), &dwBytesRead);

		for (INT i = 0; !ldr_not_found && i < 10; i++)
		{
			ReadProcessMemory(m_hProcess, (LPCVOID)PebBaseAddress, &peb, sizeof(peb), &dwBytesRead);

			ldr_not_found = ReadProcessMemory(m_hProcess, (LPCVOID)peb.Ldr, &peb_ldr, sizeof(peb_ldr), &dwBytesRead);
		
			Sleep(750);
		}

		if (!ldr_not_found)
			return 0;

		_LIST_ENTRY32* pLdrListHead = (_LIST_ENTRY32*)peb_ldr.InLoadOrderModuleList.Flink;
		_LIST_ENTRY32* pLdrCurrentNode = (_LIST_ENTRY32*)peb_ldr.InLoadOrderModuleList.Flink;
		do
		{
			_LDR_DATA_TABLE_ENTRY_BASE32 lstEntry = { 0 };
			if (!ReadProcessMemory(m_hProcess, (void*)pLdrCurrentNode, &lstEntry, sizeof(_LDR_DATA_TABLE_ENTRY_BASE32), &dwBytesRead))
			{
				//DbgShout("[GetRemoteModuleHandleW] Could not read list entry from LDR list. Error = %s", Utils::GetLastErrorAsString().c_str());
				return NULL;
			}

			pLdrCurrentNode = (_LIST_ENTRY32*)lstEntry.InLoadOrderLinks.Flink;

			wchar_t wcsBaseDllName[MAX_PATH] = { 0 };
			if (lstEntry.BaseDllName.Length > 0)
			{
				if (!ReadProcessMemory(m_hProcess, (LPCVOID)lstEntry.BaseDllName.Buffer, &wcsBaseDllName, lstEntry.BaseDllName.Length, &dwBytesRead))
				{
					//DbgShout("[GetRemoteModuleHandleW] Could not read list entry DLL name. Error = %s", Utils::GetLastErrorAsString().c_str());
					return NULL;
				}
			}

			if (lstEntry.DllBase != NULL && lstEntry.SizeOfImage != 0)
			{
				if (_wcsicmp(wcsBaseDllName, Module) == 0)
				{
					dwModuleHandle = (PVOID)lstEntry.DllBase;
					//if (ModuleSize)
					//	*ModuleSize = lstEntry.SizeOfImage;
					break;
				}
			}

		} while (pLdrListHead != pLdrCurrentNode);

		return (HMODULE)dwModuleHandle;
	}

	DWORD GetRemoteFuncAddress(HANDLE m_hProcess, wchar_t const* module, char* func)
	{
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

		auto modb = GetRemoteModuleHandle(m_hProcess, module);

		if (!modb)
			return 0;

		IMAGE_DOS_HEADER hdrDos = { 0 };
		IMAGE_NT_HEADERS32 hdrNt32 = { 0 };
		IMAGE_EXPORT_DIRECTORY* expData = { 0 };
		void* pFunc = NULL;

		SIZE_T dwRead = 0;
		ReadProcessMemory(m_hProcess, (BYTE*)modb, &hdrDos, sizeof(IMAGE_DOS_HEADER), &dwRead);
		if (hdrDos.e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		ReadProcessMemory(m_hProcess, (BYTE*)modb + hdrDos.e_lfanew, &hdrNt32, sizeof(IMAGE_NT_HEADERS32), &dwRead);
		if (hdrNt32.Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		size_t expBase = hdrNt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		// Exports are present
		if (expBase)
		{
			DWORD expSize = hdrNt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			expData = (IMAGE_EXPORT_DIRECTORY*)malloc(expSize);
			ReadProcessMemory(m_hProcess, (BYTE*)modb + expBase, expData, expSize, &dwRead);

			WORD  *pAddressOfOrds = (WORD*)(expData->AddressOfNameOrdinals + (size_t)expData - expBase);
			DWORD *pAddressOfNames = (DWORD*)(expData->AddressOfNames + (size_t)expData - expBase);
			DWORD *pAddressOfFuncs = (DWORD*)(expData->AddressOfFunctions + (size_t)expData - expBase);

			for (DWORD i = 0; i < expData->NumberOfFunctions; ++i)
			{
				WORD OrdIndex = 0xFFFF;
				char *pName = NULL;

				// Find by index
				if ((size_t)func <= 0xFFFF)
					OrdIndex = (WORD)i;

				// Find by name
				else if ((size_t)func > 0xFFFF && i < expData->NumberOfNames)
				{
					pName = (char*)(pAddressOfNames[i] + (size_t)expData - expBase);
					OrdIndex = (WORD)pAddressOfOrds[i];
				}
				else
					return 0;

				if (((size_t)func <= 0xFFFF && (WORD)func == (OrdIndex + expData->Base)) || ((size_t)func > 0xFFFF && strcmp(pName, func) == 0))
				{
					pFunc = (void*)((size_t)modb + pAddressOfFuncs[OrdIndex]);
					break;
				}
			}
			// Free allocated data
			free(expData);
		}

		return ( DWORD )pFunc;
	}
}
#pragma warning( pop ) 