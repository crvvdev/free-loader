#pragma once

#include <curl/curl.h>
using namespace rapidjson;
using namespace CryptoPP;

class CurlWrapper
{
private:
	std::string _cookies;

	static std::size_t callback(
		const char* in,
		std::size_t size,
		std::size_t num,
		std::string* out)
	{
		const std::size_t totalBytes(size * num);
		out->append(in, totalBytes);
		return totalBytes;
	}

public:
	CurlWrapper()
	{
		char szPath[MAX_PATH];

		if (!SHGetSpecialFolderPathA(HWND_DESKTOP, szPath, CSIDL_COOKIES, TRUE))
			utils::Error("SHGetSpecialFolderPathA failed %d", GetLastError());

		strcat_s(szPath, "\\cookies.txt");

		_cookies = szPath;
	}

	~CurlWrapper()
	{
		_cookies.clear();
	}

	bool DownloadToString(const std::string& url, std::string& data);
	bool AuthenticateUser(const char* username, const char* password);
	bool DownloadFile(const std::string& url, std::vector< std::uint8_t >& file_bytes);
	inline std::string CalculateFileHash(const std::wstring& szFilePath);
	bool ReportToServer(const std::wstring& unicode_file_path);
};

extern CurlWrapper curl_wrapper;