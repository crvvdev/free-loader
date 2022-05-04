#include "Includes.hpp"

CurlWrapper curl_wrapper;

bool CurlWrapper::DownloadToString(const std::string& url, std::string& data)
{
	VM_REGION_START;
	data.clear();

	CURL* curl = curl_easy_init();

	// Set remote URL.
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

	curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, _cookies.c_str());
	curl_easy_setopt(curl, CURLOPT_COOKIEJAR, _cookies.c_str());
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "LoaderAgent2");

	// Response information.
	long httpCode(0);
	std::unique_ptr<std::string> httpData(new std::string());

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

	// Run our HTTP GET command, capture the HTTP response code, and clean up.
	const auto err_code = curl_easy_perform(curl);

	if (err_code != CURLE_OK)
		return false;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
	curl_easy_cleanup(curl);

	if (httpCode == 200)
		return true;
	VM_REGION_END;

	return false;
}

bool CurlWrapper::AuthenticateUser(const char* username, const char* password)
{
	VM_REGION_START;
	CURL* curl = curl_easy_init();

	const std::string url = base_url + "login.php";

	// Set remote URL.
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

	curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, _cookies.c_str());
	curl_easy_setopt(curl, CURLOPT_COOKIEJAR, _cookies.c_str());
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "LoaderAgent2");

	std::string encoded;

	CryptoPP::StringSource ss(password, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		)
	);

	std::string hwid;
	GenerateHardDiskHash(hwid);

	char post_field[500];
	sprintf_s(post_field, "username=%s&pass=%s&hwid=%s", username, encoded.c_str(), hwid.c_str());

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_field);

	// Response information.
	long httpCode(0);
	std::unique_ptr<std::string> httpData(new std::string());

	std::string response_data;

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

	// Run our HTTP GET command, capture the HTTP response code, and clean up.
	const auto err_code = curl_easy_perform(curl);

	if (err_code != CURLE_OK)
		return false;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
	curl_easy_cleanup(curl);

	if (httpCode == 200)
	{
		try
		{
			Document document;
			document.Parse(response_data.c_str());

			if (!strcmp(document[0]["login_result"].GetString(), "banned"))
			{
				MessageBoxA(GetActiveWindow(), "You're banned, not allowed to login or use.", 0, MB_ICONERROR);
				PostQuitMessage(-1);
			}

			if (!strcmp(document[0]["login_result"].GetString(), "hwid_in_use"))
			{
				MessageBoxA(GetActiveWindow(), "Every account is HWID locked, you can't use it in another computer.", 0, MB_ICONERROR);
				PostQuitMessage(-1);
			}

			return !strcmp(document[0]["login_result"].GetString(), "success");
		}
		catch (...)
		{
			MessageBoxA(GetActiveWindow(), "Failed to parse data", 0, MB_ICONERROR);
		}
	}
	VM_REGION_END;
	return false;
}

bool CurlWrapper::DownloadFile(const std::string& url, std::vector< std::uint8_t >& file_bytes)
{
	VM_REGION_START;
	IStream* pStream;

	HRESULT hr = URLOpenBlockingStreamA(nullptr, url.c_str(), &pStream, 0, nullptr);
	if (FAILED(hr))
	{
		MessageBoxA(GetActiveWindow(), "Failed to download file from the internet", 0, MB_ICONERROR);
		return false;
	}

	STATSTG statStream;
	if (FAILED(pStream->Stat(&statStream, STATFLAG_NONAME)))
	{
		pStream->Release();
		MessageBoxA(GetActiveWindow(), "pStream->Stat failed", 0, MB_ICONERROR);
		return false;
	}

	DWORD dwSize = statStream.cbSize.LowPart + 1;

	file_bytes.resize(dwSize);

	LARGE_INTEGER liPos;
	ZeroMemory(&liPos, sizeof(liPos));

	pStream->Seek(liPos, STREAM_SEEK_SET, NULL);
	pStream->Read(file_bytes.data(), dwSize - 1, NULL);

	if (pStream)
	{
		pStream->Release();
		pStream = nullptr;
	}

	file_bytes.pop_back();
	VM_REGION_END;
	return true;
}

inline std::string CurlWrapper::CalculateFileHash(const std::wstring& szFilePath)
{
	std::vector< char > myData;

	std::fstream ifs(szFilePath, std::ios::in | std::ios::binary | std::ios::ate);
	std::string result = "hash failed";

	if (ifs)
	{
		std::ifstream::pos_type pos = ifs.tellg();

		myData.resize(pos);

		ifs.seekg(0, std::ios::beg);
		ifs.read(myData.data(), pos);

		ifs.close();

		//MD5 from file.
		Weak::MD5 hash;
		CryptoPP::byte digest[Weak::MD5::DIGESTSIZE];

		hash.CalculateDigest(digest, (unsigned char*)myData.data(), myData.size());

		std::string output;

		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output), false);
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		result.clear();
		myData.clear();

		result = output;
	}
	return result;
}

bool CurlWrapper::ReportToServer(const std::wstring& unicode_file_path)
{
	VM_REGION_START;
	CURL* curl = curl_easy_init();
	if (curl)
	{
		const std::string url = base_url + "report.php";

		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

		curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15);
		curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

		curl_easy_setopt(curl, CURLOPT_COOKIEFILE, _cookies.c_str());
		curl_easy_setopt(curl, CURLOPT_COOKIEJAR, _cookies.c_str());
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "ReportAgent");

		///File Name Base64 Encoded
		std::string encoded;

		try
		{
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			auto to_64 = converter.to_bytes(unicode_file_path);

			CryptoPP::StringSource ss((byte*)to_64.data(), to_64.length(), true,
				new CryptoPP::Base64Encoder(
					new CryptoPP::StringSink(encoded)
				)
			);

			///User UniqueID
			std::string unique_id;
			GenerateHardDiskHash(unique_id);

			///File MD5 hash
			const auto file_hash = CalculateFileHash(unicode_file_path).c_str();

			char szPostData[1024];
			sprintf_s(szPostData, XorStr("hw=%s&filename=%s&filehash=%s"), unique_id.c_str(), encoded.c_str(), file_hash);
			//MessageBoxA(GetActiveWindow(), szPostData, 0, 0);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, szPostData);

			////////////////
			const auto err_code = curl_easy_perform(curl);
			curl_easy_cleanup(curl);

			return (err_code == CURLE_OK);
		}
		catch (std::exception& ex)
		{
			utils::Error("Fatal error: %s", ex.what());
		}
	}
	VM_REGION_END;
	return false;
}