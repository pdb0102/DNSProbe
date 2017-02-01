/*
 * (c) Copyright 1995 Peter Dennis Bartok.
 * All Rights Reserved!
 *
 */

#define MEMVERSION 	"MuxMem $Revision:   1.0  $"

#define _IN_TKSOURCE_

#include "platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/* Define, if you want faster (and more unsecure) code */
/* #undef MEM_PRODUCTION */

/* Uncomment if you want (slow) but secure checking for mem*() and str*() functions */
#define TOUGH_CHECKING

/* Define, if you want the dialog box at the end */
#define EXIT_CHECK

/* Define, if you want notification at runtime */
#define IMMEDIATE_WARNING

typedef int 			BOOL;
typedef unsigned long	ULONG;

#ifndef TRUE
#define	TRUE	1
#endif

#ifndef FALSE
#define	FALSE 0
#endif


typedef struct {
	int	Flag;
	unsigned long MemPtr;
	char	Source[64];
	long	Sourceline;
	unsigned long	Size;
	BOOL	Used;
	BOOL	FreeCalled;
} ControlElement;

#define	CONTROL_ALLOC	1000

#define	CFLAG_ILLEGAL_FREE		   1
#define	CFLAG_ILLEGAL_REALLOC	   2
#define	CFLAG_MEMCPY_OVERWRITE	 	3
#define	CFLAG_MEMCPY_UNKNOWN_DEST	4
#define	CFLAG_MEMSET_OVERWRITE		5
#define	CFLAG_MEMSET_UNKNOWN_DEST	6

static ControlElement *	Control;
static long				ControlUsed=0;
static long				ControlAlloc=0;
static long				ControlFree=0;

static long				PeakMem=0;
static long				CurrentMem=0;
static long				CountMalloc=0;
static long				CountRealloc=0;

void ShutMemDown(char *Name);
static BOOL FreeControlElements(void);


void
ShutMemDown(char *Name)
{
#ifdef EXIT_CHECK
#ifndef MEM_PRODUCTION
	FILE	*out;
	long	i;
	char	Filename[128];
	unsigned long 	Leak=0, IllFree=0, IllRealloc=0, Overwrite=0;

	sprintf_s(Filename, 128, "%s", Name);	// We could add a prefix path here...
	fopen_s(&out, Filename,"wb");
	for (i=0; i<ControlUsed; i++) {
		if (Control[i].Used) {
			switch(Control[i].Flag) {
				case 0:
					fprintf(out, "Leak in         : %12s, line %5d. Size: %d\n",Control[i].Source, Control[i].Sourceline, Control[i].Size);
					Leak++;
					break;

				case CFLAG_ILLEGAL_FREE:
					fprintf(out, "Illegal free    : %12s, line %5d. ptr: %p (Block never allocated)\n",Control[i].Source, Control[i].Sourceline, Control[i].MemPtr);
					IllFree++;
					break;

				case CFLAG_ILLEGAL_REALLOC:
					fprintf(out, "Illegal realloc : %12s, line %5d. ptr: %p , Size: %d (Block never allocated)\n",Control[i].Source, Control[i].Sourceline, Control[i].MemPtr, Control[i].Size);
					IllRealloc++;
					break;

				case CFLAG_MEMCPY_OVERWRITE:
					fprintf(out, "Overwrite       : %12s, line %5d. ptr: %p , Size: %d (memcpy writes over end)\n",Control[i].Source, Control[i].Sourceline, Control[i].MemPtr, Control[i].Size);
					Overwrite++;
					break;

				case CFLAG_MEMCPY_UNKNOWN_DEST:
					fprintf(out, "Dest. unknown   : %12s, line %5d. ptr: %p , Size: %d (memcpy)\n",Control[i].Source, Control[i].Sourceline, Control[i].MemPtr, Control[i].Size);
					Overwrite++;
					break;

				case CFLAG_MEMSET_OVERWRITE:
					fprintf(out, "Overwrite       : %12s, line %5d. ptr: %p , Size: %d (memset writes over end)\n",Control[i].Source, Control[i].Sourceline, Control[i].MemPtr, Control[i].Size);
					Overwrite++;
					break;

				case CFLAG_MEMSET_UNKNOWN_DEST:
					fprintf(out, "Dest. unknown   : %12s, line %5d. ptr: %p , Size: %d (memset)\n",Control[i].Source, Control[i].Sourceline, Control[i].MemPtr, Control[i].Size);
					Overwrite++;
					break;

				default:
					break;
			}
		}
	}
	fclose(out);
	ConsolePrintf("\nLeaks                :%10d\nIllegal Free's       :%10d\n"
		"Illegal Realloc's    :%10d\nMemory overwrites    :%10d\nPeak memory allocated:%10d\nMalloc's executed    :%10d\n"
		"Realloc's executed   :%10d\n",Leak,IllFree,IllRealloc,Overwrite,PeakMem,CountMalloc,CountRealloc);
	FreeControlElements();
#endif
#endif /* Exit check */
}

static long
FindControlElement(unsigned long ptr)
{
	long i;

	for (i=0; i<ControlUsed; i++) {
		if (Control[i].Used) {
			if (Control[i].MemPtr==ptr)
				return(i);
		}
	}
	return(-1);
}

static long
AddControlElements(char *Sourcefilename, long Sourceline)
{
	void	*Tmp;

	if (ControlFree) {
		long i;

		for(i=0;i<ControlUsed;i++) {
			if (!Control[i].Used) {
				Control[i].Used=TRUE;
				ControlFree--;
				strcpy_s(Control[i].Source, 64, Sourcefilename);
				Control[i].Sourceline=Sourceline;
				return(i);
			}
		}
		ControlFree=0;	/* Ooops; */
	}

	if ((ControlUsed+1) >= ControlAlloc) {
		Tmp=(Control != NULL)?realloc(Control, (ControlAlloc+CONTROL_ALLOC) * sizeof(ControlElement)):malloc((ControlAlloc+CONTROL_ALLOC) * sizeof(ControlElement));
		if (!Tmp) {
			ConsolePrintf("Out of memory!\n");
			return(-1);
		}
		Control=(ControlElement *)Tmp;
		Tmp=(void *)
				(
					(ULONG)(Control)+
						(
							(ULONG)(ControlAlloc)*
							(ULONG)(sizeof(ControlElement))
						)
				);
		memset(Tmp, 0, (CONTROL_ALLOC*sizeof(ControlElement)));
		ControlAlloc+=CONTROL_ALLOC;
	}
	strcpy_s(Control[ControlUsed].Source, 64, Sourcefilename);
	Control[ControlUsed].Sourceline=Sourceline;
	return(ControlUsed++);
}

static BOOL
FreeControlElements(void)
{
	if (!Control)
		return(FALSE);

	free(Control);
	Control=NULL;
	ControlUsed=0;
	ControlAlloc=0;
	ControlFree=0;
	return(TRUE);
}

void*
Calloc_Internal(size_t size, size_t Elsize, char *SourceFilename, int SourceCodeline)
{
#ifndef MEM_PRODUCTION
	void *retval;
	long	Next;

	retval = calloc(size, Elsize);
	if (!retval) {
#ifdef RUNTIME_LOG
		ConsolePrintf("MALLOC  : Size: %8d - FAILED\n", size);
#endif
		return(retval);
	}

	CurrentMem+=(size*Elsize);
	if (CurrentMem>PeakMem)
		PeakMem=CurrentMem;

	CountMalloc++;

	Next=AddControlElements(SourceFilename, SourceCodeline);
	Control[Next].MemPtr=(unsigned long)retval;
	Control[Next].FreeCalled=FALSE;
	Control[Next].Used=TRUE;
	Control[Next].Size=(size*Elsize);
	Control[Next].Flag=0;
#ifdef RUNTIME_LOG
	ConsolePrintf("CALLOC  : Size: %8d, - RESULT: %x\n",(size*Elsize),retval);
#endif
	return(retval);
#else
	return(malloc(size));
#endif
}

void*
Malloc_Internal(size_t size, char *SourceFilename, int SourceCodeline)
{
#ifndef MEM_PRODUCTION
	void *retval;
	long	Next;

	retval = malloc(size);
	if (!retval) {
#ifdef RUNTIME_LOG
		ConsolePrintf("MALLOC  : Size: %8d - FAILED\n", size);
#endif
		return(retval);
	}

	CurrentMem+=size;
	if (CurrentMem>PeakMem)
		PeakMem=CurrentMem;

	CountMalloc++;

	Next=AddControlElements(SourceFilename, SourceCodeline);
	Control[Next].MemPtr=(unsigned long)retval;
	Control[Next].FreeCalled=FALSE;
	Control[Next].Used=TRUE;
	Control[Next].Size=size;
	Control[Next].Flag=0;
#ifdef RUNTIME_LOG
	ConsolePrintf("MALLOC  : Size: %8d, - RESULT: %x\n",size,retval);
#endif
	return(retval);
#else
	return(malloc(size));
#endif
}

void
Free_Internal(void *block, char *SourceFilename, int SourceCodeline)
{
#ifndef MEM_PRODUCTION
	long i;
																			 
#ifdef RUNTIME_LOG
	ConsolePrintf("FREE    : ptr : %8x\n",block);
#endif
	if (!block)
		return;
	i=FindControlElement((unsigned long)block);
	if (i==-1) {		/* We are freeing a block never allocated by us! */
		long Next;		/* We will record this! */

		Next=AddControlElements(SourceFilename, SourceCodeline);
#ifdef IMMEDIATE_WARNING
		ConsolePrintf("Illegal free!\n");
#endif
		Control[Next].MemPtr=(unsigned long)block;
		Control[Next].Flag=CFLAG_ILLEGAL_FREE;
		Control[Next].Used=TRUE;
		Control[Next].FreeCalled=FALSE;
		Control[Next].Size=0;
      return;
	} else {
		if (Control[i].Flag!=0) {
			Control[i].FreeCalled=TRUE;
#ifdef IMMEDIATE_WARNING
			ConsolePrintf("Strange free!\n");
#endif
		} else {
			Control[i].Used=FALSE;
			Control[i].FreeCalled=TRUE;
			ControlFree++;
         CurrentMem-=Control[i].Size;
		}
	}
	free(block);
#else
	if (block)
		free(block);
#endif
}


void*
Realloc_Internal(void *block, size_t size, char *SourceFilename, int SourceCodeline)
{
#ifndef MEM_PRODUCTION	
	void *retval;
	long	i;

	if (!block) {
#ifdef RUNTIME_LOG
		ConsolePrintf("REALLOC : ptr : NULL     Size: %8d\n",size);
#endif
		return(Malloc_Internal(size, SourceFilename, SourceCodeline));
	}

   CountRealloc++;

	i=FindControlElement((unsigned long)block);
	if (i==-1) {			/* We are re-allocing a block never allocated! */
		long Next;			/* We will record this! */

#ifdef IMMEDIATE_WARNING
		ConsolePrintf("Realloc of unknown block!\n");
#endif
		Next=AddControlElements(SourceFilename, SourceCodeline);
		Control[Next].MemPtr=(unsigned long)block;
		Control[Next].Flag=CFLAG_ILLEGAL_REALLOC;
		Control[Next].Used=TRUE;
		Control[Next].FreeCalled=FALSE;
		Control[Next].Size=size;
		retval=realloc(block, size);
		Next=AddControlElements(SourceFilename, SourceCodeline);
		Control[Next].MemPtr=(unsigned long)retval;
		Control[Next].Flag=0;
		Control[Next].Used=TRUE;
		Control[Next].FreeCalled=FALSE;
		Control[Next].Size=size;
#ifdef RUNTIME_LOG
		ConsolePrintf("REALLOC : ptr : %p Size: %8d - Result: %x\n",block, size, retval);
#endif
		return(retval);
	} else {			/* This is a legal realloc */
		CurrentMem-=Control[i].Size;
      CountRealloc++;
		retval=realloc(block, size);
		if (!retval) {
#ifdef RUNTIME_LOG
			ConsolePrintf("REALLOC : ptr : %x Size: %8d - FAILED!\n",block, size);
#else
			;
#endif
		} else {
			Control[i].MemPtr=(unsigned long)retval;
			strcpy_s(Control[i].Source, 64, SourceFilename);
			Control[i].Sourceline=SourceCodeline;
			Control[i].Size=size;
			CurrentMem+=Control[i].Size;
			if (CurrentMem>PeakMem)
				PeakMem=CurrentMem;
		}
#ifdef RUNTIME_LOG
		ConsolePrintf("REALLOC : ptr : %x Size: %8d - Result: %x\n",block, size, retval);
#endif
		return(retval);
	}
#else
	return(realloc(block,size));
#endif
}

void*
Strdup_Internal(const char *s, char *SourceFilename, int SourceCodeline)
{
#ifndef MEM_PRODUCTION	
	void 	*retval;
	long	Next;

	if (!s) {
		ConsolePrintf("NULL Strdup!\n");
		return(NULL);
	}

	retval = _strdup(s);

	Next=AddControlElements(SourceFilename, SourceCodeline);
	Control[Next].MemPtr=(unsigned long)retval;
	Control[Next].Flag=0;
	Control[Next].Used=TRUE;
	Control[Next].FreeCalled=FALSE;
	Control[Next].Size=strlen(s);
#ifdef RUNTIME_LOG
	ConsolePrintf("STRDUP   : Size: %8d - Result: %x\n",strlen(s), retval);
#endif
	return(retval);
#else
	return(strdup(s));
#endif
}

void*
Memcpy_Internal(void *dest, const void *src, size_t n, char *SourceFilename, int SourceCodeline)
{
#ifndef MEM_PRODUCTION	
	long i, Next;


#ifdef TOUGH_CHECKING
	for (i=0; i<ControlUsed; i++) {
		if (Control[i].Used) {
			if ((Control[i].MemPtr<=(unsigned long)dest)
			&& ((Control[i].MemPtr+Control[i].Size)>(unsigned long)dest)) {			/* Startpoint is here */
				if (((unsigned long)dest+n)>(Control[i].MemPtr+Control[i].Size)) {	/* Shit is happening! */
					long Next;

					Next=AddControlElements(SourceFilename, SourceCodeline);
					Control[Next].MemPtr=(unsigned long)dest;
					Control[Next].Flag=CFLAG_MEMCPY_OVERWRITE;
					Control[Next].Used=TRUE;
					Control[Next].FreeCalled=FALSE;
					Control[Next].Size=n;
					goto done;
				} else {		/* Good copy */
					goto done;
				}
			}
		}
	}

	Next=AddControlElements(SourceFilename, SourceCodeline);
	Control[Next].MemPtr=(unsigned long)dest;
	Control[Next].Flag=CFLAG_MEMCPY_UNKNOWN_DEST;
	Control[Next].Used=TRUE;
	Control[Next].FreeCalled=FALSE;
	Control[Next].Size=n;
done:
#else
	i=FindControlElement((unsigned long)dest);
	if (i==-1) {
		Next=AddControlElements(SourceFilename, SourceCodeline);
		Control[Next].MemPtr=(unsigned long)dest;
		Control[Next].Flag=CFLAG_MEMCPY_UNKNOWN_DEST;
		Control[Next].Used=TRUE;
		Control[Next].FreeCalled=FALSE;
		Control[Next].Size=n;
	}
#endif
	return(memcpy(dest, src, n));
#else
	return(memcpy(dest, src, n));
#endif
}

void*
Memset_Internal(void *dest, int c, size_t n, char *SourceFilename, int SourceCodeline)
{
#ifndef MEM_PRODUCTION
	long i, Next;


#ifdef TOUGH_CHECKING
	for (i=0; i<ControlUsed; i++) {
		if (Control[i].Used) {
			if ((Control[i].MemPtr<=(unsigned long)dest)
			&& ((Control[i].MemPtr+Control[i].Size)>(unsigned long)dest)) {			/* Startpoint is here */
				if (((unsigned long)dest+n)>(Control[i].MemPtr+Control[i].Size)) {	/* Shit is happening! */
					long Next;

					Next=AddControlElements(SourceFilename, SourceCodeline);
					Control[Next].MemPtr=(unsigned long)dest;
					Control[Next].Flag=CFLAG_MEMSET_OVERWRITE;
					Control[Next].Used=TRUE;
					Control[Next].FreeCalled=FALSE;
					Control[Next].Size=n;
					goto done;
				} else {		/* Good copy */
					goto done;
				}
			}
		}
	}

	Next=AddControlElements(SourceFilename, SourceCodeline);
	Control[Next].MemPtr=(unsigned long)dest;
	Control[Next].Flag=CFLAG_MEMSET_UNKNOWN_DEST;
	Control[Next].Used=TRUE;
	Control[Next].FreeCalled=FALSE;
	Control[Next].Size=n;
done:
#else
	i=FindControlElement((unsigned long)dest);
	if (i==-1) {
		Next=AddControlElements(SourceFilename, SourceCodeline);
		Control[Next].MemPtr=(unsigned long)dest;
		Control[Next].Flag=CFLAG_MEMSET_UNKNOWN_DEST;
		Control[Next].Used=TRUE;
		Control[Next].FreeCalled=FALSE;
		Control[Next].Size=n;
	}
#endif
	return(memset(dest, c, n));
#else
	return(memset(dest, c, n));
#endif
}

long
MuxxerInternGetMemory(void)
{
#ifndef MEM_PRODUCTION
	long Used=0, i;

	for (i=0; i<ControlUsed; i++) {
		if ((Control[i].Used) && (!Control[i].Flag))
			Used+=Control[i].Size;
	}

	return(Used);
#else
	return(0);
#endif
}

#ifdef MEM_PRODUCTION
void*
Malloc(size_t size)
{
	return(malloc(size));
}

void
Free(void *block)
{
	free(block);
}

void*
Realloc(void *block, size_t size)
{
	return(realloc(block,size));
}

void*
Strdup(const char *s)
{
	return(strdup(s));
}

void*
Memset(void *dest, int c, size_t size)
{
	return(memset(dest,c,size));
}

void*
Memcpy(void *dest, void *src, size_t n)
{
	return(memcpy(dest,src,n));
}

#endif

#if defined(WINDOWS) && defined(PVCS)
char *
ReportMuxMemVersion(char *TargetBuffer)
{
	return(MakeVersionFromPVCSRevision(TargetBuffer, MEMVERSION));
}
#endif
