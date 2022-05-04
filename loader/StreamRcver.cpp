#include "Includes.hpp"
#include <BlackBone/Symbols/SymbolData.h>

std::vector< _STREAMED_CHEAT_LIST > v_cheats;

namespace StreamRcver
{
	HANDLE hEvent = nullptr;

	bool DecryptAES( std::vector< std::uint8_t >& out_buffer, const std::uint8_t* stream_key, const std::uint8_t* stream_md5, const std::uint8_t* iv, std::vector< std::uint8_t >& cipherdata )
	{
		VM_REGION_START;
		CBC_Mode<AES>::Decryption dec;
		dec.SetKeyWithIV( stream_key, 32, iv, 16 );

		const auto cipherlen = cipherdata.size( );

		out_buffer.resize( cipherlen );
		ArraySink rs( out_buffer.data( ), out_buffer.size( ) );

		ArraySource( cipherdata.data( ), cipherlen, true, new StreamTransformationFilter( dec, new Redirector( rs ) ) );

		out_buffer.resize( rs.TotalPutLength( ) );

		Weak::MD5 hash;
		CryptoPP::byte digest[ Weak::MD5::DIGESTSIZE ];

		hash.CalculateDigest( digest, out_buffer.data( ), out_buffer.size( ) );

		std::string output;

		CryptoPP::HexEncoder encoder( new CryptoPP::StringSink( output ), false );
		encoder.Put( digest, sizeof( digest ) );
		encoder.MessageEnd( );

		//cipherdata.clear();
		VM_REGION_END;

		return !( std::memcmp( stream_md5, output.data( ), ( MD5_DIGEST_LENGTH * 2 ) ) );
	}

	void Base64Decode( std::string b64message, std::vector< std::uint8_t >& buffer )
	{
		Base64Decoder decoder;
		decoder.Put( ( byte* )b64message.data( ), b64message.size( ) );
		decoder.MessageEnd( );

		const auto size = decoder.MaxRetrievable( );
		if( size && size <= SIZE_MAX )
		{
			buffer.resize( size );
			decoder.Get( buffer.data( ), buffer.size( ) );
		}
	}

	void ExtractCheats( )
	{
		std::string json;
		if( !curl_wrapper.DownloadToString( base_url + "list.php", json ) )
		{
			MessageBoxA( GetActiveWindow( ), "Failed to download cheat list.", 0, MB_ICONERROR );
			return;
		}

		v_cheats.clear( );

		const auto web_server_ret = json.c_str( );

		try
		{
			Document document;
			document.Parse( json.c_str( ) );

			if( document.IsObject( ) )
			{
				const Value& attributes = document[ "attributes" ];

				if( !attributes.Empty( ) )
				{
					for( Value::ConstValueIterator itr = attributes.Begin( ); itr != attributes.End( ); ++itr )
					{
						const Value& attribute = *itr;

						STREAMED_CHEAT_LIST raw_list;
						RtlZeroMemory( &raw_list, sizeof STREAMED_CHEAT_LIST );

						for( Value::ConstMemberIterator itr2 = attribute.MemberBegin( ); itr2 != attribute.MemberEnd( ); ++itr2 )
						{
							if( !_stricmp( itr2->name.GetString( ), "name" ) )
								raw_list.name = std::string( itr2->value.GetString( ) );

							if( !_stricmp( itr2->name.GetString( ), "description" ) )
								raw_list.description = std::string( itr2->value.GetString( ) );

							if( !_stricmp( itr2->name.GetString( ), "file_name" ) )
								raw_list.file_dir = std::string( itr2->value.GetString( ) );

							if( !_stricmp( itr2->name.GetString( ), "date" ) )
								raw_list.timestamp = std::strtoull( itr2->value.GetString( ), 0, 10 );

							if( !_stricmp( itr2->name.GetString( ), "cgroup" ) )
								raw_list.group = std::atoi( itr2->value.GetString( ) );

							if( !_stricmp( itr2->name.GetString( ), "online" ) )
								raw_list.online = static_cast< bool >( std::atoi( itr2->value.GetString( ) ) );

							if( !_stricmp( itr2->name.GetString( ), "exe_name" ) )
								raw_list.exe_name = std::string( itr2->value.GetString( ) );

							if( !_stricmp( itr2->name.GetString( ), "inj_mode" ) )
								raw_list.inj_mode = std::atoi( itr2->value.GetString( ) );

							if( !_stricmp( itr2->name.GetString( ), "stream_key" ) )
								std::memcpy( raw_list.stream_key, itr2->value.GetString( ), sizeof raw_list.stream_key );
						}

						v_cheats.push_back( raw_list );
					}
				}
				else
				{
					MessageBoxA( GetActiveWindow( ), "Cheat list is empty, no cheats online at the moment!", 0, MB_ICONINFORMATION );
					PostQuitMessage( 0 );
					return;
				}
			}
			else
			{
				char szMsg[ 256 ];
				sprintf_s( szMsg, "Malformated JSON, output: %s", json.c_str( ) );

				MessageBoxA( GetActiveWindow( ), szMsg, 0, MB_ICONERROR );
				//MessageBoxA(GetActiveWindow(), "No cheats avaliable at the moment.", 0, MB_ICONERROR);
				return;
			}
		}
		catch( std::exception& ex )
		{
			MessageBoxA( GetActiveWindow( ), ex.what( ), "List Extraction", MB_ICONERROR );
		}
	}

	bool DecryptStream( const STREAMED_CHEAT_LIST& cheat, std::string& encoded_cheat, std::vector< std::uint8_t >& stream_bytes )
	{
		VM_REGION_START;
		std::uint8_t stream_iv[ AES_BLOCK_SIZE ];
		std::uint8_t stream_md5[ MD5_DIGEST_LENGTH * 2 ];

		try
		{
			Base64Decode( encoded_cheat, stream_bytes );
			encoded_cheat.clear( );

			///First 32 bytes is file MD5
			std::memcpy( stream_md5, stream_bytes.data( ), MD5_DIGEST_LENGTH * 2 );

			///Then the file IV
			std::memcpy( stream_iv, stream_bytes.data( ) + ( MD5_DIGEST_LENGTH * 2 ), AES_BLOCK_SIZE );

			///Erase First bytes, we dont need it anymore.
			stream_bytes.erase( stream_bytes.begin( ), stream_bytes.begin( ) + AES_BLOCK_SIZE + ( MD5_DIGEST_LENGTH * 2 ) );

			std::vector< std::uint8_t > to_inject;
			bool res = DecryptAES( to_inject, cheat.stream_key, stream_md5, stream_iv, stream_bytes );

			const auto file_mz = *( std::uint16_t* )to_inject.data( );

			if( res && file_mz == 0x5A4D )
			{
				stream_bytes = to_inject;
				return true;
			}
		}
		catch( std::exception& ex )
		{
			MessageBoxA( GetActiveWindow( ), ex.what( ), 0, MB_ICONERROR );
		}
		VM_REGION_END;
		return false;
	}

	bool DownloadAndRun( const STREAMED_CHEAT_LIST& cheat )
	{
		VM_REGION_START;
		const std::string download_url = base_url + cheat.file_dir;

		std::string encoded_cheat;
		if( !curl_wrapper.DownloadToString( download_url, encoded_cheat ) )
		{
			MessageBoxA( GetActiveWindow( ), "Failed to download cheat.", 0, MB_ICONERROR );
			return false;
		}

		std::vector< std::uint8_t > to_inject;

		if( !DecryptStream( cheat, encoded_cheat, to_inject ) )
			return false;

		std::string file_name = random_string( 10 ) + ".exe";

		HANDLE hFile = CreateFileA( file_name.c_str( ), GENERIC_WRITE,          // open for writing
			0,                      // do not share
			NULL,                   // default security
			CREATE_NEW,             // create new file only
			FILE_ATTRIBUTE_HIDDEN,  // normal file
			NULL );                  // no attr. template)

		if( hFile == INVALID_HANDLE_VALUE )
		{
			utils::Error( "Failed to create file, error %d", GetLastError( ) );
			return false;
		}
		DWORD dwWritten = 0;

		if( !WriteFile( hFile, to_inject.data( ), ( DWORD )to_inject.size( ), &dwWritten, nullptr ) )
		{
			utils::Error( "Failed to write to file, error %d", GetLastError( ) );
			return false;
		}
		CloseHandle( hFile );

		char szFormat[ MAX_PATH ];
		snprintf( szFormat, sizeof szFormat, "start %s", file_name.c_str( ) );
		system( szFormat );
		VM_REGION_END;

		return true;
	}

	bool DownloadAndInjectKDriver( const STREAMED_CHEAT_LIST& cheat )
	{
		//removed
		return true;
	}

	const char* FormatBytes( long long bytes, char* str )
	{
		const char* sizes[ 5 ] = { "B", "KB", "MB", "GB", "TB" };

		int i;
		double dblByte = static_cast< double >( bytes );
		for( i = 0; i < 5 && bytes >= 1024; i++, bytes /= 1024 )
			dblByte = bytes / 1024.0;

		sprintf( str, "%.2f", dblByte );
		return strcat( strcat( str, " " ), sizes[ i ] );
	}

#pragma warning( push )
#pragma warning( disable : 4311)
#pragma warning( disable : 4312)
#pragma warning( disable : 4302)
	DWORD WINAPI HandleInject( PVOID arg )
	{
		VM_REGION_START;
		InjectionContext* ctx = ( InjectionContext* )arg;

		DWORD dwWait = WaitForSingleObject( hEvent, INFINITE );

		if( dwWait == WAIT_OBJECT_0 )
		{
			DWORD pid = 0;
			HWND desk_hwnd = 0;

			ctx->ChangeStatus( "Procurando janela da Steam.." );

			while( !( desk_hwnd = FindWindowW( NULL, L"Steam" ) ) )
				std::this_thread::sleep_for( 150ms );

			auto ret = GetWindowThreadProcessId( desk_hwnd, &pid );

			auto exp_handle = OpenProcess( PROCESS_ALL_ACCESS, false, pid );

			if( !exp_handle )
			{
				MessageBoxW( GetActiveWindow( ), L"Falha ao obter handle da Steam!", nullptr, MB_ICONERROR );
				return 0;
			}

			auto io_port = CreateIoCompletionPort( INVALID_HANDLE_VALUE, 0, 0, 0 );

			auto job_object = CreateJobObjectW( 0, 0 );

			auto job_io_port = JOBOBJECT_ASSOCIATE_COMPLETION_PORT{ 0, io_port };

			auto result = SetInformationJobObject( job_object, JobObjectAssociateCompletionPortInformation, &job_io_port, sizeof( job_io_port ) );

			DWORD nOfBytes;
			ULONG_PTR cKey;
			LPOVERLAPPED proc_pid;

			result = AssignProcessToJobObject( job_object, exp_handle );

			ctx->ChangeStatus( "Aguardando pelo jogo.." );

			while( GetQueuedCompletionStatus( io_port, &nOfBytes, &cKey, &proc_pid, -1 ) )
			{
				if( nOfBytes == 6 )
				{
					auto race_handle = OpenProcess( PROCESS_ALL_ACCESS, false, DWORD( proc_pid ) );

					if( race_handle == INVALID_HANDLE_VALUE )
						continue;

					wchar_t buffer[ MAX_PATH ];
					DWORD len = MAX_PATH;

					QueryFullProcessImageNameW( race_handle, 0, buffer, &len );

					if( wcsstr( buffer, L"csgo.exe" ) )
					{
						const auto cur_item = ctx->GetCurrentList( );

						ctx->ChangeStatus( "Injetando o hack, não feche o Loader!" );
						DownloadAndInject( cur_item, race_handle );
					}

					CloseHandle( race_handle );
				}
			}

			CloseHandle( exp_handle );
			CloseHandle( job_object );
			CloseHandle( io_port );
		}
		PostQuitMessage( 0 );
		VM_REGION_END;
		return 0;
}
#pragma warning( pop ) 

	bool DownloadAndInject( const STREAMED_CHEAT_LIST& cheat, std::uint32_t pid )
	{
		VM_REGION_START;
		const std::string download_url = base_url + cheat.file_dir;

		std::string encoded_cheat;
		if( !curl_wrapper.DownloadToString( download_url, encoded_cheat ) )
		{
			MessageBoxA( GetActiveWindow( ), "Failed to download cheat.", 0, MB_ICONERROR );
			return false;
		}

		std::vector< std::uint8_t > to_inject;

		if( !DecryptStream( cheat, encoded_cheat, to_inject ) )
			return false;

		NTSTATUS err = ERROR_SUCCESS;

		auto modCallback = [ ] ( blackbone::CallbackType type, void*, blackbone::Process&, const blackbone::ModuleData& modInfo )
		{
			if( type == blackbone::PreCallback )
			{
				if( modInfo.name == L"user32.dll" )
					return blackbone::LoadData( blackbone::MT_Native, blackbone::Ldr_Ignore );
			}

			return blackbone::LoadData( blackbone::MT_Default, blackbone::Ldr_Ignore );
		};

		Process proc;
		if( !NT_SUCCESS( err = proc.Attach( pid ) ) )
		{
			MessageBoxW( GetActiveWindow( ), Utils::GetErrorDescription( err ).c_str( ), L"Injection", MB_ICONERROR );
			return false;
		}

		auto img = proc.mmap( ).MapImage( to_inject.size( ), to_inject.data( ), false, WipeHeader, modCallback );
		to_inject.clear( );

		if( !img )
		{
			MessageBoxW( GetActiveWindow( ), Utils::GetErrorDescription( img.status ).c_str( ), L"Injection", MB_ICONERROR );
			return false;
		}

		utils::TimeoutMsg( "Injetado com sucesso!\nO programa sera fechado em 3 segundos automaticamente.." );

		VM_REGION_END;
		return true;
	}

	bool DownloadAndInject( const STREAMED_CHEAT_LIST& cheat, HANDLE proc_handle )
	{
		VM_REGION_START;
		const std::string download_url = base_url + cheat.file_dir;

		std::string encoded_cheat;
		if( !curl_wrapper.DownloadToString( download_url, encoded_cheat ) )
		{
			MessageBoxA( GetActiveWindow( ), "Failed to download cheat.", 0, MB_ICONERROR );
			return false;
		}

		std::vector< std::uint8_t > to_inject;

		if( !DecryptStream( cheat, encoded_cheat, to_inject ) )
			return false;

		NTSTATUS err = ERROR_SUCCESS;

		auto modCallback = [ ] ( blackbone::CallbackType type, void*, blackbone::Process&, const blackbone::ModuleData& modInfo )
		{
			if( type == blackbone::PreCallback )
			{
				if( modInfo.name == L"user32.dll" )
					return blackbone::LoadData( blackbone::MT_Native, blackbone::Ldr_Ignore );
			}

			return blackbone::LoadData( blackbone::MT_Default, blackbone::Ldr_Ignore );
		};

		Process proc;
		if( !NT_SUCCESS( err = proc.Attach( proc_handle ) ) )
		{
			MessageBoxW( GetActiveWindow( ), Utils::GetErrorDescription( err ).c_str( ), L"Injection", MB_ICONERROR );
			return false;
		}

		auto img = proc.mmap( ).MapImage( to_inject.size( ), to_inject.data( ), false, WipeHeader, modCallback );
		to_inject.clear( );

		if( !img )
		{
			MessageBoxW( GetActiveWindow( ), Utils::GetErrorDescription( img.status ).c_str( ), L"Injection", MB_ICONERROR );
			return false;
		}

		utils::TimeoutMsg( "Injetado com sucesso!\nO programa sera fechado em 3 segundos automaticamente.." );

		VM_REGION_END;
		return true;
	}
};