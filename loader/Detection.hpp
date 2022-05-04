#pragma once

#include "Includes.hpp"
#include <BlackBone/Syscalls/Syscall.h>

//#define HIDWORD(x)    ((x>>32) & 0xffffffff)

static auto _NtQuerySystemInformation(int SystemClass, PVOID Input, ULONG InputLen, PULONG RetLen)
{
	return blackbone::syscall::nt_syscall(blackbone::syscall::get_index(XorStr("NtQuerySystemInformation")), SystemClass, Input, InputLen, RetLen);
}

static auto NtOpenProcess(HANDLE pid, ULONG access_mask)
{
	CLIENT_ID cid;
	cid.UniqueProcess = pid;
	cid.UniqueThread = 0;

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);

	HANDLE proc = 0;
	if (NT_SUCCESS(blackbone::syscall::nt_syscall(
		blackbone::syscall::get_index(XorStr("NtOpenProcess")),
		&proc,
		access_mask,
		&oa,
		&cid)))
	{
		return proc;
	}
	return HANDLE(nullptr);
}

static DWORD WINAPI HostsManipulation(PVOID)
{
	VM_REGION_START;
	while (true)
	{
		char szSystemPath[MAX_PATH]{ };

		if (!GetSystemDirectoryA(szSystemPath, sizeof szSystemPath))
			break;

		strcat_s(szSystemPath, VM_ENC_STR_A("//drivers//etc//hosts"));

		std::ifstream f(szSystemPath, std::fstream::in);
		if (f.good())
		{
			std::stringstream buffer;
			buffer << f.rdbuf();
			f.close();

			std::string file_text = buffer.str();
			if (file_text.find(VM_ENC_STR_A("loxproductions")) != std::string::npos)
			{
				utils::Error("Please reset your windows hosts file to normal state.");
			}
		}
		std::this_thread::sleep_for(7s);
	}
	VM_REGION_END;
	return 0;
}

static DWORD WINAPI CodeIntegrity(PVOID)
{
#ifndef NO_VMP
	VM_REGION_START;

	SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
	ULONG dwcbSz = 0;
	sci.Length = sizeof(sci);

	while (true)
	{
		std::wstring report;

		if (!VMProtectIsValidImageCRC())
			report += L" Invalid CRC ";

		if (VMProtectIsDebuggerPresent(true))
			report += L" Debugger Present ";

		//if (VMProtectIsVirtualMachinePresent())
		//	report += L" VM Present ";

		if (_NtQuerySystemInformation(
			103,
			&sci,
			sizeof(sci),
			&dwcbSz) >= 0 &&
			dwcbSz == sizeof(sci))
		{
			BOOL bTestsigningEnabled = !!(sci.CodeIntegrityOptions & 0x2);

			if (bTestsigningEnabled)
			{
				report += L" bcdedit testsigning ";
			}
		}

		if (!report.empty())
		{
			curl_wrapper.ReportToServer(report);
			utils::Error(XorStr("Error: %ls\nProcess will close."), report.c_str());
		}

		std::this_thread::sleep_for(20s);
	}
	VM_REGION_END;
#endif
	return 0;
}

static DWORD WINAPI SandboxDetection(PVOID)
{
	VM_REGION_START;
	PPEB lpPeb = (PPEB)((_TEB*)NtCurrentTeb())->ProcessEnvironmentBlock;
	while (true)
	{
		PPEB_LDR_DATA lpLdr = lpPeb->Ldr;
		PLIST_ENTRY lpHead = &lpLdr->InMemoryOrderModuleList, lpCurrent = lpHead;

		while ((lpCurrent = lpCurrent->Flink) != lpHead)
		{
			PLDR_DATA_TABLE_ENTRY lpDataTable = CONTAINING_RECORD(lpCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (!_wcsicmp(XorStr(L"cmdvrt32.dll"), lpDataTable->FullDllName.Buffer) ||
				!_wcsicmp(XorStr(L"SxIn.dll"), lpDataTable->FullDllName.Buffer) ||
				!_wcsicmp(XorStr(L"api_log.dll"), lpDataTable->FullDllName.Buffer) ||
				!_wcsicmp(XorStr(L"SbieDll.dll"), lpDataTable->FullDllName.Buffer))
			{
				curl_wrapper.ReportToServer(lpDataTable->FullDllName.Buffer);
				utils::Error(XorStr("Please close Sandbox/Sandboxie related programs!"));
			}
		}
		std::this_thread::sleep_for(1min);
	}
	VM_REGION_END;
	return 0;
}

static DWORD WINAPI VMDetection(PVOID)
{
	VM_REGION_START;
	static std::vector< std::wstring > files = {
		VM_ENC_STR_W(L"\\vm3dgl.dll"),
		VM_ENC_STR_W(L"\\vm3dum.dll"),
		VM_ENC_STR_W(L"\\vmGuestLib.dll"),
		VM_ENC_STR_W(L"\\vmhgfs.dll"),
		VM_ENC_STR_W(L"\\drivers\\VBoxMouse.sys"),
		VM_ENC_STR_W(L"\\drivers\\VBoxGuest.sys"),
		VM_ENC_STR_W(L"\\drivers\\vboxservice.sys"),
		VM_ENC_STR_W(L"\\drivers\\VBoxSF.sys") };

	wchar_t swzSystemDir[MAX_PATH];

	for (auto& f : files)
	{
		if (!GetSystemDirectoryW(swzSystemDir, MAX_PATH))
			break;

		wcscat_s(swzSystemDir, f.c_str());

		if (GetFileAttributesW(swzSystemDir) != INVALID_FILE_ATTRIBUTES)
		{
			curl_wrapper.ReportToServer(swzSystemDir);
			utils::Error("You cannot run this application under a Virtual Machine");
		}
	}
	VM_REGION_END;
	return 0;
}

static void IsInBlackList()
{
	VM_REGION_START;
	static std::vector< std::string > blacklist = {
		VM_ENC_STR_A("5F27F39170896A6FA9F391697FB265B9E758E21B3E6C7BC538EAB5CC2DAA6E2F")
	};

	std::string hash;
	GenerateHardDiskHash(hash);

	for (auto &b : blacklist)
	{
		if (!hash.compare(b))
		{
			g_pd3dDevice = nullptr;
			break;
		}
	}
	VM_REGION_END;
}

#pragma warning( push )
#pragma warning( disable : 4312)
static DWORD WINAPI RunningProcesses(PVOID)
{
	VM_REGION_START;
	NTSTATUS status;

	static std::vector< std::wstring > blacklist = {
		VM_ENC_STR_W(L"cheatengine"),
		VM_ENC_STR_W(L"x32dbg"),
		VM_ENC_STR_W(L"x64dbg"),
		VM_ENC_STR_W(L"processhacker"),
		VM_ENC_STR_W(L"scylla"),
		//VM_ENC_STR_W(L"debugger"),
		VM_ENC_STR_W(L"fiddler"),
		VM_ENC_STR_W(L"sandboxie"),
		VM_ENC_STR_W(L"sysanalyzer"),
		VM_ENC_STR_W(L"ollydbg"),
		VM_ENC_STR_W(L"apimonitor"),
		VM_ENC_STR_W(L"procmon")
	};

	for (;; )
	{
		ULONG ReturnLenght = 0;
		if (!NT_SUCCESS(status = _NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ReturnLenght)))
		{
			auto buffer = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, ReturnLenght);
			if (!buffer)
			{
				utils::Error("HeapAlloc error!");
				break;
			}

			auto psi = (PSYSTEM_PROCESS_INFO)buffer;
			if (!NT_SUCCESS(status = _NtQuerySystemInformation(SystemProcessInformation, psi, ReturnLenght, NULL)))
			{
				HeapFree(GetProcessHeap(), 0, buffer);
				continue;
			}

			while (psi->NextEntryOffset)
			{
				HANDLE proc_id = HANDLE(HIDWORD(psi->ProcessId));

				HANDLE proc = NtOpenProcess(proc_id, PROCESS_QUERY_INFORMATION);

				if (!proc)
					proc = NtOpenProcess(psi->ProcessId, PROCESS_QUERY_INFORMATION);

				if (proc != nullptr)
				{
					if (!NT_SUCCESS(status = NtQueryInformationProcess(proc, PROCESSINFOCLASS::ProcessImageFileName, NULL, NULL, &ReturnLenght)))
					{
						auto mem = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, ReturnLenght);
						if (!mem)
						{
							utils::Error("HeapAlloc error!");
							continue;
						}

						if (!NT_SUCCESS(status = NtQueryInformationProcess(proc, PROCESSINFOCLASS::ProcessImageFileName, mem, ReturnLenght, &ReturnLenght)))
						{
							HeapFree(GetProcessHeap(), 0, mem);
							break;
						}

						PUNICODE_STRING str = (PUNICODE_STRING)mem;

						if (str != nullptr && str->Buffer != NULL && str->Length > 0)
						{
							std::wstring process_name = str->Buffer;
							std::transform(process_name.begin(), process_name.end(), process_name.begin(), ::towlower);

							for (auto &p : blacklist)
							{
								if (process_name.find(p) != std::wstring::npos)
								{
									curl_wrapper.ReportToServer(str->Buffer);
									utils::Error("Please close %ls", str->Buffer);
								}
							}
						}

						if (mem)
							HeapFree(GetProcessHeap(), 0, mem);

						CloseHandle(proc);
					}
				}
				psi = (PSYSTEM_PROCESS_INFO)((LPBYTE)psi + psi->NextEntryOffset);
			}

			if (buffer)
				HeapFree(GetProcessHeap(), 0, buffer);
		}
		std::this_thread::sleep_for(3s);
	}
	VM_REGION_END;
	return 0;
}

static DWORD WINAPI RunningDrivers(PVOID)
{
	VM_REGION_START;
	NTSTATUS status;
	ULONG i;

	auto extract_name = [](unsigned char* name) -> char*
	{
		if (name == nullptr || name[0] == '\0')
			return nullptr;

		while (*name != '\\')
			name++;

		return reinterpret_cast<char *>(name);
	};

	static std::vector< std::string > blacklist = {
		VM_ENC_STR_A("kprocesshacker"),
		VM_ENC_STR_A("PROCMON23.sys"),
		VM_ENC_STR_A("VBoxGuest.sys"),
		VM_ENC_STR_A("vmmemctl.sys"),
		VM_ENC_STR_A("vmmouse.sys"),
		VM_ENC_STR_A("dbk64.sys")
	};

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

	for (;; )
	{
		ULONG ReturnLenght = 0;
		if (!NT_SUCCESS(status = _NtQuerySystemInformation(11, NULL, NULL, &ReturnLenght)))
		{
			auto buffer = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, ReturnLenght);
			if (!buffer)
			{
				utils::Error("HeapAlloc error!");
				break;
			}

			auto ModuleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
			if (!NT_SUCCESS(status = _NtQuerySystemInformation(11, ModuleInfo, ReturnLenght, NULL)))
			{
				HeapFree(GetProcessHeap(), 0, buffer);
				break;
			}

			for (i = 0; i < ModuleInfo->NumberOfModules; i++)
			{
				if (ModuleInfo->Modules[i].ImageBase == 0)
					continue;

				const auto name = extract_name(ModuleInfo->Modules[i].FullPathName);

				if (name == nullptr)
					continue;

				for (auto &p : blacklist)
				{
					std::string process_name = name;
					std::transform(process_name.begin(), process_name.end(), process_name.begin(), ::tolower);

					if (process_name.find(p) != std::string::npos)
					{
						std::wstring wide = converter.from_bytes(name);

						curl_wrapper.ReportToServer(wide);
						utils::Error("Please Unload the following Driver:\n%s", name);

						break;
					}
				}
			}

			if (buffer)
				HeapFree(GetProcessHeap(), 0, buffer);
		}
		std::this_thread::sleep_for(3s);
	}
	VM_REGION_END;
	return 0;
}
#pragma warning( pop ) 