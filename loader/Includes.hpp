#pragma once

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOCOMM

//Windows 7
#define WINVER			0x0601 
#define _WIN32_WINNT	0x0601 

#define NOMINMAX
#define DIRECTINPUT_VERSION 0x0800
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <imgui.h>
#include <imgui_internal.h>
#include <imgui_impl_dx9.h>
#include <imgui_impl_win32.h>

#include <ctime>
#include <d3d9.h>
#include <Psapi.h>

#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <locale>
#include <utility>
#include <codecvt>
#include <algorithm>
#include <string>
#include <fstream>
#include <shlobj_core.h>
#include <Shlwapi.h>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <atlbase.h>
#include <iomanip>
#include <urlmon.h>
#include <algorithm>
#include <DbgHelp.h>
#include <filesystem>
#include <d3dx9.h>
#include <random>
#include <shellapi.h>

#include <dinput.h>
#include <tchar.h>
#include <iomanip>
#include <iostream>
#include <exception>
#include <typeinfo>
#include <stdexcept>
#include <DxErr.h>
#include <wtypes.h>
#include <atlbase.h>
#include <atlstr.h>
#include <comutil.h>
#include <wbemidl.h>
#include <system_error>

#pragma comment(lib, "wbemuuid.lib")

#pragma comment(lib, "dxerr.lib")
#pragma comment( lib, "d3d9")
#pragma comment( lib, "d3dx9")
#pragma comment( lib, "psapi.lib")
#pragma comment( lib, "Shlwapi.lib")
#pragma comment( lib, "Dbghelp.lib")
#pragma comment( lib, "Urlmon.lib")

// Data
static LPDIRECT3D9              g_pD3D = NULL;
static LPDIRECT3DDEVICE9        g_pd3dDevice = NULL;
static D3DPRESENT_PARAMETERS    g_d3dpp = {};

#include <CryptoPP/cryptlib.h>
#include <CryptoPP/filters.h>
#include <CryptoPP/files.h>
#include <CryptoPP/modes.h>
#include <CryptoPP/hex.h>
#include <CryptoPP/aes.h>
#include <CryptoPP/base64.h>
#include <CryptoPP/md5.h>
#include <CryptoPP/ripemd.h>

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#pragma warning( push )
#pragma warning( disable : 4242)
#include <BlackBone/Process/Process.h>
#pragma warning( pop ) 

//#include "CrashRpt.h"

static std::vector< HANDLE > v_threads;

#define NO_VMP		1

#ifndef NO_VMP
#include <VMProtectSDK.h>

#define VM_REGION_START		VMProtectBeginVirtualization( __FUNCTION__ );
#define VM_REGION_END		VMProtectEnd( );
#define VM_INLINE_CHECK     VMProtectIsProtected( ); VMProtectIsValidImageCRC( ); 
#define VM_ENC_STR_W(x)		VMProtectDecryptStringW( x )
#define VM_ENC_STR_A(x)		VMProtectDecryptStringA( x )
#else
#define VM_REGION_START		 
#define VM_REGION_END		 
#define VM_INLINE_CHECK    
#define VM_ENC_STR_W(x)		UNREFERENCED_PARAMETER( x )
#define VM_ENC_STR_A(x)		UNREFERENCED_PARAMETER( x )
#endif

using namespace std::chrono_literals;
using namespace blackbone;

//#pragma section( ".text" )
static const std::string base_url = VM_ENC_STR_A( "removed" );
static const char* ldr_cur_ver = VM_ENC_STR_A( "removed" );

#include "utils.hpp"
#include "lazy_importer.hpp"
#include "Tools.hpp"
#include "CRC32.hpp"

#include "winstruct.hpp"
#include "CurlWrapper.hpp"
#include "StreamRcver.hpp"
#include "Detection.hpp"

//#undef XorStr
//#define XorStr( x ) UNREFERENCED_PARAMETER( x )

#define SECURED_THREAD(x) auto __##x = CreateThread( nullptr, NULL, ( LPTHREAD_START_ROUTINE)&x, nullptr, 0, nullptr ); \
		if( __##x == INVALID_HANDLE_VALUE || __##x == NULL ) utils::Error("CreateThread failed."); \
				v_threads.push_back(__##x);

