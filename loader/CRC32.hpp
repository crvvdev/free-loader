#pragma once

#ifndef CHECKSUM_H
#define CHECKSUM_H

#define CRC32_POLYNOMIAL 0x04c11db7
#define CRC32BUFSZ 1024

class CheckSum
{

public:

	void Initialize(void);
	unsigned long FileCRC(const char *sFileName);
	unsigned long FullCRC(unsigned char *sData, size_t ulLength);
	void PartialCRC(unsigned long *ulInCRC, unsigned char *sData, size_t ulLength);

private:

	unsigned long Reflect(unsigned long ulReflect, char cChar);
	unsigned long ulTable[256];
};

extern CheckSum crc32;

#endif