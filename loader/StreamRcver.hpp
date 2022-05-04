#pragma once

#include <cstdint>
#include <fstream>
#include <sstream>

#include <curl/curl.h>

using namespace CryptoPP;
using namespace rapidjson;

#define AES_BLOCK_SIZE 16
#define MD5_DIGEST_LENGTH 16

typedef struct _STREAMED_CHEAT_LIST
{
	std::string name;
	std::string description;
	std::string file_dir;
	std::uint64_t timestamp;
	std::int32_t group;
	bool online;
	std::string exe_name;
	std::int32_t inj_mode;
	std::uint8_t stream_key[32];

	auto operator < (const _STREAMED_CHEAT_LIST& other) const -> bool
	{
		return name < other.name;
	}

} STREAMED_CHEAT_LIST, * PSTREAMED_CHEAT_LIST;

class InjectionContext
{
private:
	STREAMED_CHEAT_LIST list;
	std::string status;

public:
	InjectionContext() = default;

	void ChangeStatus(const char* str)
	{
		status = str;
	}

	void SetCurrentList(STREAMED_CHEAT_LIST _list)
	{
		list = _list;
	}

	const STREAMED_CHEAT_LIST &GetCurrentList() const
	{
		return list;
	}

	const std::string &GetStatus() const
	{
		return status;
	}
};

extern std::vector< _STREAMED_CHEAT_LIST > v_cheats;

namespace StreamRcver
{
	extern HANDLE hEvent;

	bool DecryptAES(std::vector< std::uint8_t >& out_buffer, const std::uint8_t* stream_key, const std::uint8_t* stream_md5, const std::uint8_t* iv, std::vector< std::uint8_t >& cipherdata);
	void Base64Decode(std::string b64message, std::vector< std::uint8_t >& buffer);
	void ExtractCheats();
	bool DownloadAndInjectKDriver(const STREAMED_CHEAT_LIST& cheat);
	bool DownloadAndInject(const STREAMED_CHEAT_LIST& cheat, std::uint32_t pid);
	bool DownloadAndInject(const STREAMED_CHEAT_LIST& cheat, HANDLE proc_handle);
	bool DownloadAndRun(const STREAMED_CHEAT_LIST& cheat);
	
	DWORD WINAPI HandleInject(PVOID arg);
};