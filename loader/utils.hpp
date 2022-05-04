#pragma once

#define XorStr(x) (x)

namespace utils
{
	static inline void Error( const char* fmt, ... )
	{
		char szBuffer[ 1024 ] = { };

		va_list va;
		va_start( va, fmt );
		vsnprintf_s( szBuffer, sizeof( szBuffer ), fmt, va );
		va_end( va );

		MessageBoxA( GetForegroundWindow( ), szBuffer, NULL, MB_ICONERROR );
	}

	static inline void TimeoutMsg( const char* fmt, ... )
	{
		using MessageBoxTimeout_ = int( WINAPI* )( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId, DWORD dwMilliseconds );
		static MessageBoxTimeout_ MessageBoxTimeout = ( MessageBoxTimeout_ )::GetProcAddress( LoadLibraryA( "user32" ), "MessageBoxTimeoutA" );

		char szBuffer[ 1024 ] = { };

		va_list va;
		va_start( va, fmt );
		vsnprintf_s( szBuffer, sizeof( szBuffer ), fmt, va );
		va_end( va );

		MessageBoxTimeout( GetForegroundWindow( ), szBuffer, NULL, MB_ICONERROR, 0, 5000 );
	}
}