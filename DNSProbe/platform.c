/*
 *  Author: Peter Dennis Bartok (peter@venafi.com)
 *
 */

#include "platform.h"

void
XPLDebugOut(const char *Format, ...)
{
	unsigned char	DebugBuffer[10240];
	va_list	argptr;

	va_start(argptr, Format);	
	vsprintf_s(DebugBuffer, sizeof(DebugBuffer), Format, argptr);
	va_end(argptr);

	OutputDebugString(DebugBuffer);
}