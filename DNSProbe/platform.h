/*
 *  Author: Peter Dennis Bartok (peter@venafi.com)
 *
 */

#ifndef _PLATFORM_H
#define _PLATFORM_H

/* Auto-detect the OS */
#if !defined(LINUX) && !defined(WIN32)
#if defined(__VISUALC__)
#define WIN32
#elif defined(linux)
#define LINUX
#else
#error You must define one option: LINUX or WIN32
#endif
#endif /* !LINUX && !WIN32 */

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

#define CallingFunction(FirstArg)       (*((unsigned long *)(&FirstArg)-1))

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#if defined(WIN32)
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <process.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <direct.h>
#include <limits.h>

#define WIN_CDECL					__cdecl
#define WIN_STDCALL					__stdcall
#define EXPORT						__declspec(dllexport)

/**********************
  Packing/Byte order
 **********************/
#define PackStructures				#pragma pack (push, 1)
#define Align4Structures			#pragma pack (push, 4)
#define EndPackStructure			#pragma pack (pop)
#define EndAlignStructure			#pragma pack (pop)
#define PackedStructure
#define BIGtoLITTLE(LongWord)		(LongWord)

/**********************
  TCP/IP
 **********************/
#define  IPSOCKET								SOCKET                                                       
#define  IPInit()								{WSADATA data; WSAStartup(MAKEWORD(1,1), &data);}            
#define  IPCleanup()							WSACleanup();
#define  IPsocket(domain, type, protocol)		socket(domain, type, protocol)                       
#define  IPaccept(s, addr, addrlen)				accept(s, addr, addrlen)
#define  IPlisten(sock, backlog)				listen(sock, backlog)        
#define  IPbind(sock, addr, addrlen)			bind(sock, addr, addrlen)    
#define  IPconnect(sock, addr, addrlen)			connect(sock, addr, addrlen)
#define  IPrecv(sock, buf, len, flags)			recv(sock, buf, len, flags)
#define  IPsend(sock, buf, len, flags)			send(sock, buf, len, flags)
#define  IPclose(sock)							closesocket(sock)    
#define  IPshutdown(s, how)						shutdown(s, how)                             
#define  IPgetsockname(s, addr, addrlen)		getsockname(s, addr, addrlen)        
#define  IPgetpeername(s, addr, addrlen)		getpeername(s, addr, addrlen)
#define  IPselect(nfds, rfds, wfds, efds, t)	select(nfds, rfds, wfds, efds, t) 
#define  IPerrno								WSAGetLastError()

#define  SocketReadyTimeout(Socket, Timeout, Exiting)			\
	{															\
		int	ready, ret;											\
		fd_set               readfds;							\
		struct timeval       timeout;							\
		unsigned long        ConnTimeout=(Timeout);				\
																\
		ready = 0;												\
																\
		while (!ready) {										\
			FD_ZERO(&readfds);									\
			FD_SET((Socket), &readfds);							\
			timeout.tv_usec=0;									\
			timeout.tv_sec=(Timeout);							\
			ret = IPselect(FD_SETSIZE, &readfds, NULL, NULL, &timeout); \
			ConnTimeout--;										\
																\
			if ((ret<1) || (Exiting)) {							\
				if (Exiting) {									\
					return(0);									\
				} else {										\
					return(-1);									\
				}												\
			} else {											\
				ready=TRUE;										\
				if (Exiting) {									\
					return(0);									\
				}												\
			}													\
		}														\
	}

#define  ETIMEDOUT         WSAETIMEDOUT
#define  ECONNREFUSED      WSAECONNREFUSED
#define  ENETUNREACH       WSAENETUNREACH


#endif

#if defined(LINUX)
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pthread.h>
#include <semaphore.h>
#include <strings.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <syslog.h>

typedef int				BOOL;
typedef unsigned long	LONG;
typedef unsigned char	BYTE;
typedef unsigned short	WORD;

#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Prototypes go here */
#if defined(WIN32)
#if defined(_DEBUG) || defined(DEBUG)
void XPLDebugOut(const char *Format, ...);
#define ConsolePrintf		XPLDebugOut
#define EnterDebugger()		DebugBreak()
#else
#define ConsolePrintf		printf
#define EnterDebugger()
#endif	/* DEBUG */
#endif /* WIN32 */

#if defined(LINUX)
#define ConsolePrintf	printf
#define XPLDebugOut		printf
#endif /* LINUX */

#ifdef __cplusplus
}
#endif

#endif /* _PLATFORM_H */