#include "Includes.hpp"

CheckSum crc32;

void CheckSum::Initialize( void )
{
	memset( &this->ulTable, 0, sizeof( this->ulTable ) );

	for( int iCodes = 0; iCodes <= 0xFF; iCodes++ )
	{
		this->ulTable[ iCodes ] = this->Reflect( iCodes, 8 ) << 24;

		for( int iPos = 0; iPos < 8; iPos++ )
		{
			this->ulTable[ iCodes ] = ( this->ulTable[ iCodes ] << 1 ) ^
				( this->ulTable[ iCodes ] & ( 1 << 31 ) ? CRC32_POLYNOMIAL : 0 );
		}
		this->ulTable[ iCodes ] = this->Reflect( this->ulTable[ iCodes ], 32 );
	}
}

unsigned long CheckSum::Reflect( unsigned long ulReflect, char cChar )
{
	unsigned long ulValue = 0;
	for( int iPos = 1; iPos < ( cChar + 1 ); iPos++ )
	{
		if( ulReflect & 1 ) ulValue |= 1 << ( cChar - iPos );
		ulReflect >>= 1;
	}
	return ulValue;
}

unsigned long CheckSum::FileCRC( const char* sFileName )
{
	unsigned long ulCRC = 0xffffffff;
	unsigned char sBuf[ CRC32BUFSZ ];

	size_t iBytesRead = 0;

	FILE* f = nullptr;
	fopen_s( &f, sFileName, "rb" );

	if( !f )
	{
		return 0xffffffff;
	}
	do
	{
		iBytesRead = fread( sBuf, sizeof( char ), sizeof sBuf, f );
		this->PartialCRC( &ulCRC, sBuf, iBytesRead );
	} while( iBytesRead == CRC32BUFSZ );

	fclose( f );
	return( ulCRC ^ 0xffffffff );
}

unsigned long CheckSum::FullCRC( unsigned char* sData, size_t ulLength )
{
	unsigned long ulCRC = 0xffffffff;
	this->PartialCRC( &ulCRC, sData, ulLength );
	return ulCRC ^ 0xffffffff;
}

void CheckSum::PartialCRC( unsigned long* ulInCRC, unsigned char* sData, size_t ulLength )
{
	while( ulLength-- )
	{
		*ulInCRC = ( *ulInCRC >> 8 ) ^ this->ulTable[ ( *ulInCRC & 0xFF ) ^ *sData++ ];
	}
}
