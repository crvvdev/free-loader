#include "Includes.hpp"

// Forward declarations of helper functions
bool CreateDeviceD3D( HWND hWnd );
void CleanupDeviceD3D( );
void ResetDevice( );
LRESULT WINAPI WndProc( HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam );

inline bool set_privilege( HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege )
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if( !LookupPrivilegeValue( NULL, lpszPrivilege, &luid ) )
		return false;

	tp.PrivilegeCount = 1;
	tp.Privileges[ 0 ].Luid = luid;
	if( bEnablePrivilege )
		tp.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[ 0 ].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if( !AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof( TOKEN_PRIVILEGES ),
		( PTOKEN_PRIVILEGES )NULL, ( PDWORD )NULL ) )
		return false;

	return GetLastError( ) != ERROR_NOT_ALL_ASSIGNED;
}

void SetupPrivileges( )
{
	HANDLE token;
	if( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES, &token ) )
		return;

	bool done = ( set_privilege( token, TEXT( "SeLoadDriverPrivilege" ), TRUE ) && set_privilege( token, TEXT( "SeDebugPrivilege" ), TRUE ) );
	CloseHandle( token );
	if( !done )
	{
		MessageBoxA( GetActiveWindow( ), "Failed to set privileges", 0, MB_ICONERROR );
		PostQuitMessage( 0 );
	}
}

namespace ImGui
{
	void CheatsListBox( std::vector< _STREAMED_CHEAT_LIST >& list, int& cur_item )
	{
		auto cur_w = ImGui::GetWindowWidth( );

		if( ImGui::ListBoxHeader( "##CHEATS", ImVec2( -1, ImGui::GetWindowHeight( ) / 2 ) ) )
		{
			for( int i = 0; i < list.size( ); ++i )
			{
				const bool item_selected = ( cur_item == i );

				if( ImGui::Selectable( list.at( i ).name.c_str( ), item_selected ) )
					cur_item = i;
			}
			ImGui::ListBoxFooter( );
		}
	}

	void ButtonDisable( const char* text, bool disabled )
	{

	}
};


void DoCheckUpdate( HWND hwnd )
{
#ifndef NO_VMP
	VM_REGION_START;
	std::string json;
	if( !curl_wrapper.DownloadToString( base_url + "version.php", json ) )
	{
		MessageBoxA( hwnd, "Update check failed.", 0, MB_ICONERROR );
		PostQuitMessage( 0 );
		return;
	}

	if( GetFileAttributesA( "old_loader.bin" ) != INVALID_FILE_ATTRIBUTES )
		_unlink( "old_loader.bin" );

	try
	{
		Document document;
		document.Parse( json.c_str( ) );

		if( !document.Empty( ) )
		{
			const auto ver_build = document[ 0 ][ "version_build" ].GetString( );

			//if the version match, continue
			if( !std::strcmp( ver_build, ldr_cur_ver ) )
				return;

			MessageBoxA( hwnd, "A new update has been found, the loader will update itself.", 0, MB_ICONINFORMATION );

			//if not, update
			const auto file_url = document[ 0 ][ "version_url" ].GetString( );

			std::vector< std::uint8_t > file_stream;

			if( curl_wrapper.DownloadFile( base_url + file_url, file_stream ) )
			{
				//Calculate file md5, to make sure we downloaded it right.
				Weak::MD5 hash;
				CryptoPP::byte digest[ Weak::MD5::DIGESTSIZE ];

				hash.CalculateDigest( digest, file_stream.data( ), file_stream.size( ) );

				std::string output;

				CryptoPP::HexEncoder encoder( new CryptoPP::StringSink( output ), false );
				encoder.Put( digest, sizeof( digest ) );
				encoder.MessageEnd( );

				if( output.compare( document[ 0 ][ "version_crc32" ].GetString( ) ) )
				{
					MessageBoxA( hwnd, "File hash mismatch, closing.", "Update Error", MB_ICONERROR );
					PostQuitMessage( 0 );
					return;
				}

				//rename old file, start new file
				char szFormat[ MAX_PATH ];
				GetModuleFileNameA( GetModuleHandleW( 0 ), szFormat, sizeof szFormat );
				MoveFileA( szFormat, "old_loader.bin" );
				SetFileAttributesA( "old_loader.bin", FILE_ATTRIBUTE_HIDDEN );

				const auto new_file = random_string( 16 ) + ".exe";

				HANDLE hAvatar = CreateFileA( new_file.c_str( ), FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL );
				if( hAvatar != INVALID_HANDLE_VALUE )
				{
					DWORD dwWrite = 0;
					if( !WriteFile( hAvatar, file_stream.data( ), ( DWORD )file_stream.size( ), &dwWrite, NULL ) )
					{
						utils::Error( "WriteFile error %d", GetLastError( ) );
						PostQuitMessage( 0 );
						return;
					}

					file_stream.clear( );
					CloseHandle( hAvatar );

					//start the new process.
					snprintf( szFormat, sizeof szFormat, "start %s", new_file.c_str( ) );
					system( szFormat );

					PostQuitMessage( 0 );
				}
				else
				{
					utils::Error( "CreateFileA error %d", GetLastError( ) );
					return;
				}
			}
			else
			{
				MessageBoxA( hwnd, "Failed to update the loader.", "Update Error", MB_ICONERROR );
				PostQuitMessage( 0 );
				return;
			}
		}
		else
		{
			MessageBoxA( hwnd, "Missing informations, unknown error", "Update Error", MB_ICONERROR );
			PostQuitMessage( 0 );
			return;
		}
	}
	catch( std::exception& ex )
	{
		MessageBoxA( hwnd, ex.what( ), "Update Error", MB_ICONERROR );
		PostQuitMessage( 0 );
		return;
	}
	VM_REGION_END;
#endif
}

LONG CALLBACK ExceptionFilter( EXCEPTION_POINTERS* ep )
{
	BOOL bMiniDumpSuccessful;
	WCHAR szPath[ MAX_PATH ];
	WCHAR szFileName[ MAX_PATH ];
	DWORD dwBufferSize = MAX_PATH;
	HANDLE hDumpFile;
	SYSTEMTIME stLocalTime;
	GetLocalTime( &stLocalTime );

	MINIDUMP_EXCEPTION_INFORMATION ExpParam;

	swprintf_s( szFileName, MAX_PATH, L"Loader(%hs)-%04d%02d%02d-%02d%02d%02d-%ld-%ld.dmp",
		ldr_cur_ver,
		stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay,
		stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond,
		GetCurrentProcessId( ), GetCurrentThreadId( ) );

	hDumpFile = CreateFile( szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0 );

	ExpParam.ThreadId = GetCurrentThreadId( );
	ExpParam.ExceptionPointers = ep;
	ExpParam.ClientPointers = TRUE;

	bMiniDumpSuccessful = MiniDumpWriteDump( GetCurrentProcess( ), GetCurrentProcessId( ), hDumpFile, MiniDumpWithFullMemory, &ExpParam, NULL, NULL );

	swprintf_s( szPath, L"Application has crashed, minidump %s created", szFileName );
	MessageBoxW( GetActiveWindow( ), szPath, 0, MB_ICONERROR );

	PostQuitMessage( -1 );

	return EXCEPTION_EXECUTE_HANDLER;
}

HANDLE hEvent;

static DWORD WINAPI InjectionThread( LPVOID arg )
{
	InjectionContext* ctx = ( InjectionContext* )arg;

	DWORD dwWait = WaitForSingleObject( hEvent, INFINITE );

	std::vector<blackbone::ProcessInfo> procList;
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

	if( dwWait == WAIT_OBJECT_0 )
	{
		const auto cur_item = ctx->GetCurrentList( );

		// Wait for process
		for( ;; )
		{
			procList = blackbone::Process::EnumByNameOrPID( 0, converter.from_bytes( cur_item.exe_name ) ).result( std::vector<blackbone::ProcessInfo>( ) );

			if( !procList.empty( ) )
			{
				auto pid = procList.front( ).pid;

				//inject
				ctx->ChangeStatus( "Injetando o hack, não feche o Loader!" );
				StreamRcver::DownloadAndInject( cur_item, pid );
				break;
			}

			ctx->ChangeStatus( "Aguardando o processo do jogo.." );
			std::this_thread::sleep_for( 10ms );
		}
	}

	PostQuitMessage( 0 );
	return ERROR_SUCCESS;
}

#include <map>
#include <BlackBone/Symbols/SymbolData.h>
#include <BlackBone/Symbols/SymbolLoader.h>
#include "Iset.hpp"

//crash_rpt::CrashRpt g_crashRpt(
//	"{bd9c9385-dc4c-4d84-a1cd-4ec6e911badb}", // GUID assigned to this application.
//	L"Loader",                  // Application name that will be used in message box.
//	L"Lox Production"                        // Company name that will be used in message box.
//);

// Main code
INT WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow )
{
	VM_REGION_START;

	/*AllocConsole();
	AttachConsole(GetCurrentProcessId());
	freopen("CON", "w", stdout);*/

	if( !InstructionSet::AVX( ) )
	{
		MessageBoxA( GetActiveWindow( ), VM_ENC_STR_A( "Seu processador não contem instruções AVX presentes para o funcionamento da aplicação." ), 0, MB_ICONERROR );
		return 0;
	}

	srand( GetTickCount( ) );

	if( !IsDebuggerPresent( ) )
		SetUnhandledExceptionFilter( ExceptionFilter );

	HANDLE hMutexHandle = CreateMutex( NULL, TRUE, L"{bd9c9385-dc4c-4d84-a1cd-4ec6e911badb}" );
	if( GetLastError( ) == ERROR_ALREADY_EXISTS )
	{
		utils::Error( VM_ENC_STR_A( "Uma instância já esta rodando no sistema!" ) );
		return 0;
	}

	SetupPrivileges( );

	// crc32.Initialize();
	hEvent = CreateEventW( NULL, TRUE, FALSE, XorStr( L"ThrdInjct" ) );
	StreamRcver::hEvent = CreateEventW( NULL, TRUE, FALSE, XorStr( L"ThrdInjct2" ) );

	InjectionContext ctx;
	Timer timer;

	HANDLE hInjThread = CreateThread( 0, 0, InjectionThread, &ctx, 0, 0 );
	HANDLE hInjThread2 = CreateThread( 0, 0, StreamRcver::HandleInject, &ctx, 0, 0 );

	SetThreadPriority( hInjThread, THREAD_PRIORITY_TIME_CRITICAL );
	SetThreadPriority( hInjThread2, THREAD_PRIORITY_TIME_CRITICAL );

#ifndef NO_VMP
	//SECURED_THREAD(DetectDebugger);
	SECURED_THREAD( RunningDrivers );
	SECURED_THREAD( HostsManipulation );
	SECURED_THREAD( CodeIntegrity );
	SECURED_THREAD( RunningProcesses );
	SECURED_THREAD( SandboxDetection );
	SECURED_THREAD( VMDetection );
#endif

	LPDIRECT3DTEXTURE9 texture = NULL;
	D3DXIMAGE_INFO texture_info;
	HRESULT result;

	// get image info
	result = D3DXGetImageInfoFromFileInMemory( /*removed*/NULL, NULL, &texture_info );
	if( result != D3D_OK )
	{
		utils::Error( XorStr( "Error: %ls error description: %ls\n" ), DXGetErrorString( result ), DXGetErrorDescription( result ) );
		return NULL;
	}

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

	// create texture
	D3DCOLOR colorkey = 0xFFFF00FF;

	// Create application window
	const char charset[ ] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	std::default_random_engine rng( std::random_device{}( ) );
	std::uniform_int_distribution<> dist( 0, sizeof charset - 1 );

	std::string class_name;

	for( int i = 0; i < 7; ++i )
		class_name.push_back( charset[ dist( rng ) ] );

	auto str = converter.from_bytes( class_name );

	WNDCLASSEX wc = { sizeof( WNDCLASSEX ), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle( NULL ), NULL, NULL, NULL, NULL, str.c_str( ), NULL };
	::RegisterClassEx( &wc );

	const int Width = 528;
	const int Height = 465;

	const int ScreenX = ( GetSystemMetrics( SM_CXSCREEN ) - Width ) / 2;
	const int ScreenY = ( GetSystemMetrics( SM_CYSCREEN ) - Height ) / 2;

	HWND hwnd = ::CreateWindow( wc.lpszClassName, converter.from_bytes( random_string( 14 ) ).c_str( ), WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, ScreenX, ScreenY, Width, Height, NULL, NULL, wc.hInstance, NULL );

	// Initialize Direct3D
	if( !CreateDeviceD3D( hwnd ) )
	{
		CleanupDeviceD3D( );
		::UnregisterClass( wc.lpszClassName, wc.hInstance );
		return 1;
	}

	//IsInBlackList();
	DoCheckUpdate( hwnd );

	// Show the window
	::ShowWindow( hwnd, SW_SHOWDEFAULT );
	::UpdateWindow( hwnd );

	// Setup Dear ImGui context
	//IMGUI_CHECKVERSION();
	ImGui::CreateContext( );
	ImGuiIO& io = ImGui::GetIO( ); ( void )io;
	io.IniFilename = 0;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

	// Setup Dear ImGui style
	//ImGui::Spectrum::StyleColorsSpectrum( );

	ImGuiStyle* style = &ImGui::GetStyle( );

	style->WindowPadding = ImVec2( 15, 15 );
	style->WindowRounding = 0.0f;
	style->FramePadding = ImVec2( 5, 5 );
	style->FrameRounding = 4.0f;
	style->ItemSpacing = ImVec2( 12, 8 );
	style->ItemInnerSpacing = ImVec2( 8, 6 );
	style->IndentSpacing = 25.0f;
	style->ScrollbarSize = 15.0f;
	style->ScrollbarRounding = 9.0f;
	style->GrabMinSize = 5.0f;
	style->GrabRounding = 3.0f;

	// Setup Platform/Renderer bindings
	if( !ImGui_ImplWin32_Init( hwnd ) )
		utils::Error( XorStr( "ImGui_ImplWin32_Init failed" ) );

	if( !ImGui_ImplDX9_Init( g_pd3dDevice ) )
		utils::Error( XorStr( "ImGui_ImplDX9_Init failed" ) );

	ImFont* font = io.Fonts->AddFontFromFileTTF( XorStr( "C:\\Windows\\Fonts\\Tahoma.ttf" ), 15.0F );
	if( font )
		io.FontDefault = font;
	else
		ImGui::GetIO( ).Fonts->AddFontDefault( );

	result = D3DXCreateTextureFromFileInMemoryEx( g_pd3dDevice,
		0, //removed
		0,
		texture_info.Width,
		texture_info.Height,
		1,
		D3DPOOL_DEFAULT,
		D3DFMT_A8R8G8B8,
		D3DPOOL_MANAGED,
		D3DX_FILTER_NONE, D3DX_DEFAULT, colorkey, NULL, NULL, &texture );

	if( result != D3D_OK )
	{
		utils::Error( XorStr( "Error: %ls error description: %ls\n" ), DXGetErrorString( result ), DXGetErrorDescription( result ) );
		return NULL;
	}

	ImVec4 clear_color = ImVec4( 1.0f, 1.0f, 1.0f, 1.00f );

	bool show_another_window = true;

	// Main loop
	MSG msg;
	ZeroMemory( &msg, sizeof( msg ) );
	while( msg.message != WM_QUIT )
	{
		// Poll and handle messages (inputs, window resize, etc.)
		// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
		// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application.
		// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application.
		// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
		if( ::PeekMessage( &msg, NULL, 0U, 0U, PM_REMOVE ) )
		{
			::TranslateMessage( &msg );
			::DispatchMessage( &msg );
			continue;
		}

		for( auto& t : v_threads )
		{
			ULONG count = 0;
			const auto status = syscall::nt_syscall(
				syscall::get_index( VM_ENC_STR_A( "NtResumeThread" ) ),
				t,
				&count );

			if( !NT_SUCCESS( status ) || count > 0 )
			{
				g_pd3dDevice = nullptr;
				curl_wrapper.ReportToServer( VM_ENC_STR_W( L"NtResumeThread" ) );
				PostQuitMessage( -2 );
			}
		}

		// Start the Dear ImGui frame
		ImGui_ImplDX9_NewFrame( );
		ImGui_ImplWin32_NewFrame( );
		ImGui::NewFrame( );

		ImGui::SetNextWindowPos( ImVec2( 0, 0 ) );
		ImGui::SetNextWindowSize( ImVec2( 512, 435 ) );
		ImGui::Begin( XorStr( "##MAINWND" ), &show_another_window, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove );

		static bool bLogin = false;
		static int num_tries = 0;

		float flflWindowWidth = ImGui::GetWindowWidth( );
		auto cur_w = ImGui::GetWindowWidth( );
		static std::string username = "---";

		if( num_tries < 5 )
		{
			if( !bLogin )
			{
				ImGui::SameLine( 100 );
				ImGui::Image( ( void* )( intptr_t )texture, ImVec2( static_cast< float >( texture_info.Width ), static_cast< float >( texture_info.Height ) ) );

				ImGui::NewLine( );
				ImGui::NewLine( );
				ImGui::Text( XorStr( "Forum Username:" ) );
				static char szUsername[ 56 ];

				ImGui::PushItemWidth( -1 );

				ImGui::InputText( XorStr( "##USERNAME" ), szUsername, sizeof szUsername, ImGuiInputTextFlags_CharsNoBlank );

				ImGui::Text( XorStr( "Forum Password:" ) );
				static char szPassword[ 86 ];
				ImGui::InputText( XorStr( "##PASSWRD" ), szPassword, sizeof szPassword, ImGuiInputTextFlags_Password );

				//ImGui::SetNextItemWidth(cur_w - 25);
				if( ImGui::Button( XorStr( "Login" ), ImVec2( -1, 45 ) ) && strlen( szUsername ) > 0 && strlen( szPassword ) > 0 )
				{
					num_tries++;
					if( !( bLogin = curl_wrapper.AuthenticateUser( szUsername, szPassword ) ) )
						MessageBoxA( hwnd, XorStr( "Username/Password invalid!" ), "Error", MB_ICONERROR );

				}

				ImGui::PopItemWidth( );

				ImGui::NewLine( );
				ImGui::NewLine( );
				ImGui::Text( XorStr( "Loader Version %s" ), ldr_cur_ver );
				ImGui::SameLine( flflWindowWidth - 160 );
				ImGui::Text( XorStr( "forum.loxproductions.xyz" ) );
			}
			else if( bLogin )
			{
				static int cur_item = -1;
				static time_t user_timeleft = 0ull;

				for( static bool first = true; first; first = false )
				{
					curl_wrapper.DownloadToString( base_url + XorStr( "get_uname.php" ), username );

					std::stringstream _ss( username );
					std::string s;

					int i = 0;
					while( std::getline( _ss, s, '#' ) )
					{
						if( i == 0 )
							username = s;

						if( i > 0 )
							user_timeleft = std::strtoull( s.c_str( ), 0, 10 );

						++i;
					}

					StreamRcver::ExtractCheats( );
					std::sort( v_cheats.begin( ), v_cheats.end( ) );
				}

				std::stringstream ss;
				ss << "Bem vindo, " << username;

				auto vTextMetric = ImGui::CalcTextSize( ss.str( ).c_str( ) );

				ImGui::SameLine( ( flflWindowWidth / 2 ) - ( vTextMetric.x / 2 ) );
				ImGui::Text( ss.str( ).c_str( ) );
				ImGui::SameLine( );

				ImGui::PushID( 9801 );

				static bool in_delay = false;

				if( timer.elapsedSeconds( ) >= 6 )
				{
					in_delay = false;
					timer.stop( );
				}

				ImGui::PushItemFlag( ImGuiItemFlags_Disabled, in_delay );
				if( ImGui::Button( XorStr( "Recarregar Lista" ), ImVec2( -1, 25 ) ) )
				{
					timer.start( );
					in_delay = true;

					/* Extract new list */
					curl_wrapper.DownloadToString( base_url + XorStr( "get_uname.php" ), username );

					std::stringstream _ss( username );
					std::string s;

					int i = 0;
					while( std::getline( _ss, s, '#' ) )
					{
						if( i == 0 )
							username = s;

						if( i > 0 )
							user_timeleft = std::strtoull( s.c_str( ), 0, 10 );

						++i;
					}

					StreamRcver::ExtractCheats( );
					std::sort( v_cheats.begin( ), v_cheats.end( ) );
				}
				ImGui::PopItemFlag( );
				ImGui::PopID( );

				ImGui::CheatsListBox( v_cheats, cur_item );

				ImGui::Columns( 1 );
				ImGui::Separator( );

				if( cur_item != -1 )
				{
					const auto cur_item_sel = v_cheats.at( cur_item );
					const auto status_txt = ctx.GetStatus( );

					if( cur_item_sel.online )
					{
						ImGui::TextColored( ImVec4( 0.0f, 0.0f, 0.0f, 1.0f ), XorStr( "Descrição:" ) );
						ImGui::SameLine( );
						ImGui::TextColored( ImVec4( 0.2f, 0.2f, 0.2f, 1.0f ), XorStr( "%s" ), cur_item_sel.description.c_str( ) );

						std::time_t temp = cur_item_sel.timestamp;
						struct tm timeinfo;
						localtime_s( &timeinfo, &temp );

						char buffer[ 80 ];
						strftime( buffer, sizeof( buffer ), XorStr( "%d/%m/%Y %H:%M:%S" ), &timeinfo );

						ImGui::TextColored( ImVec4( 0.0f, 0.0f, 0.0f, 1.0f ), XorStr( "Ultima Update:" ) );
						ImGui::SameLine( );
						ImGui::TextColored( ImVec4( 0.2f, 0.2f, 0.2f, 1.0f ), XorStr( "%s" ), buffer );

						ImGui::TextColored( ImVec4( 0.0f, 0.0f, 0.0f, 1.0f ), XorStr( "Status:" ) );
						ImGui::SameLine( );

						auto cur_item_status = cur_item_sel.online ? XorStr( "Ativo" ) : XorStr( "Offline" );
						ImGui::TextColored( cur_item_sel.online ? ImVec4( 0.02f, 0.38f, 0.12f, 1.0f ) : ImVec4( 0.82f, 0.3f, 0.0f, 1.0f ), cur_item_status );

						bool expired = false;
						std::string button_text = XorStr( "Carregar Selecionado" );

						if( cur_item_sel.group == 2 )
						{
							//static constexpr time_t next_date = 1569791800;
							time_t now;
							time( &now );
							int n = static_cast< int >( user_timeleft - now );

							ImGui::TextColored( ImVec4( 0.0f, 0.0f, 0.0f, 1.0f ), XorStr( "Tempo Restante:" ) );
							ImGui::SameLine( );

							if( n <= 0 )
							{
								expired = true;
								ImGui::TextColored( ImVec4( 0.0f, 0.0f, 0.0f, 1.0f ), XorStr( "Seu tempo foi expirado, renove no forum!" ) );
								button_text = XorStr( "Seu tempo foi expirado, renove no forum!" );
							}
							else
							{
								int day = n / ( 24 * 3600 );

								n = n % ( 24 * 3600 );
								int hour = n / 3600;

								n %= 3600;
								int minutes = n / 60;

								n %= 60;
								int seconds = n;

								ImGui::TextColored( ImVec4( 0.0f, 0.0f, 0.0f, 1.0f ), XorStr( "%d hora(s) e %d minuto(s)" ), hour, minutes );
							}
						}
						//ImGui::NewLine();

						//ImGui::PushItemFlag(ImGuiItemFlags_Disabled, expired);
						if( expired )
						{
							if( ImGui::Button( button_text.c_str( ), ImVec2( -1, 25 ) ) )
							{
								ShellExecuteA( NULL, XorStr( "open" ), XorStr( "http://j.gs/DGNw" ), NULL, NULL, SW_SHOWNORMAL );
							}
						}
						else
						{
							if( ImGui::Button( button_text.c_str( ), ImVec2( -1, 25 ) ) )
							{
								if( cur_item_sel.inj_mode == 1 )
								{
									ctx.SetCurrentList( cur_item_sel );

									MessageBoxA( hwnd, XorStr( "Por favor, execute o jogo!" ), "Info", MB_ICONINFORMATION );

									SetEvent( hEvent );

								}
								else if( cur_item_sel.inj_mode == 2 )
								{
									StreamRcver::DownloadAndRun( cur_item_sel );
								}
								else if( cur_item_sel.inj_mode == 3 )
								{
									StreamRcver::DownloadAndInjectKDriver( cur_item_sel );
								}
								else if( cur_item_sel.inj_mode == 4 )
								{
									ctx.SetCurrentList( cur_item_sel );

									MessageBoxA( hwnd, XorStr( "Por favor, execute o jogo!" ), "Info", MB_ICONINFORMATION );

									SetEvent( StreamRcver::hEvent );
								}
							}
						}
						//ImGui::PopItemFlag();

						if( !status_txt.empty( ) )
						{
							ImGui::TextColored( ImVec4( 0.0f, 0.0f, 0.0f, 1.0f ), XorStr( "STATUS:" ) );
							ImGui::SameLine( );
							ImGui::TextColored( ImVec4( 0.2f, 0.2f, 0.2f, 1.0f ), status_txt.c_str( ) );
						}
					}
					else
					{
						ImGui::TextColored( ImVec4( 1.0f, 0.0f, 0.0f, 1.0f ), XorStr( "Este cheat está desabilitado no momento!" ) );
					}
				}
			}
		}
		else
		{
			ImGui::Text( XorStr( "Por favor, não floode o sistema!" ) );
		}

		ImGui::End( );
		// Rendering
		ImGui::EndFrame( );
		g_pd3dDevice->SetRenderState( D3DRS_ZENABLE, false );
		g_pd3dDevice->SetRenderState( D3DRS_ALPHABLENDENABLE, false );
		g_pd3dDevice->SetRenderState( D3DRS_SCISSORTESTENABLE, false );
		D3DCOLOR clear_col_dx = D3DCOLOR_RGBA( 0, 0, 0, 255 );
		g_pd3dDevice->Clear( 0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0 );
		if( g_pd3dDevice->BeginScene( ) >= 0 )
		{
			ImGui::Render( );
			ImGui_ImplDX9_RenderDrawData( ImGui::GetDrawData( ) );
			g_pd3dDevice->EndScene( );
		}
		HRESULT result = g_pd3dDevice->Present( NULL, NULL, NULL, NULL );

		// Handle loss of D3D9 device
		if( result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel( ) == D3DERR_DEVICENOTRESET )
			ResetDevice( );
	}

	ReleaseMutex( hMutexHandle );
	CloseHandle( hMutexHandle );

	ImGui_ImplDX9_Shutdown( );
	ImGui_ImplWin32_Shutdown( );
	ImGui::DestroyContext( );

	CleanupDeviceD3D( );
	::DestroyWindow( hwnd );
	::UnregisterClass( wc.lpszClassName, wc.hInstance );
	VM_REGION_END;

	return 0;
}

// Helper functions

bool CreateDeviceD3D( HWND hWnd )
{
	if( ( g_pD3D = Direct3DCreate9( D3D_SDK_VERSION ) ) == NULL )
	{
		utils::Error( "Direct3DCreate9 failed" );
		return false;
	}

	// Create the D3DDevice
	ZeroMemory( &g_d3dpp, sizeof( g_d3dpp ) );
	g_d3dpp.Windowed = TRUE;
	g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
	g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
	g_d3dpp.EnableAutoDepthStencil = TRUE;
	g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
	g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;           // Present with vsync
	//g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate

	HRESULT hr = g_pD3D->CreateDevice( D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice );
	if( FAILED( hr ) )
	{
		std::string message = std::system_category( ).message( hr );
		utils::Error( "g_pD3D->CreateDevice failed %s", message.c_str( ) );
		return false;
	}

	return true;
}

void CleanupDeviceD3D( )
{
	if( g_pd3dDevice )
	{
		g_pd3dDevice->Release( ); g_pd3dDevice = NULL;
	}
	if( g_pD3D )
	{
		g_pD3D->Release( ); g_pD3D = NULL;
	}
}

void ResetDevice( )
{
	ImGui_ImplDX9_InvalidateDeviceObjects( );

	HRESULT hr = g_pd3dDevice->Reset( &g_d3dpp );

	if( hr == D3DERR_INVALIDCALL )
	{
		utils::Error( "g_pd3dDevice->Reset failed" );
	}

	ImGui_ImplDX9_CreateDeviceObjects( );
}

// Win32 message handler
extern LRESULT ImGui_ImplWin32_WndProcHandler( HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam );
LRESULT WINAPI WndProc( HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam )
{
	if( ImGui_ImplWin32_WndProcHandler( hWnd, msg, wParam, lParam ) )
		return true;

	switch( msg )
	{
		case WM_SIZE:
		if( g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED )
		{
			g_d3dpp.BackBufferWidth = LOWORD( lParam );
			g_d3dpp.BackBufferHeight = HIWORD( lParam );
			ResetDevice( );
		}
		return 0;
		case WM_SYSCOMMAND:
		if( ( wParam & 0xfff0 ) == SC_KEYMENU ) // Disable ALT application menu
			return 0;
		break;
		case WM_DESTROY:
		//::CoUninitialize();
		::PostQuitMessage( 0 );
		return 0;
	}
	return ::DefWindowProc( hWnd, msg, wParam, lParam );
}
