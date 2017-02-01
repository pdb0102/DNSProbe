/*
 * (c) Copyright 1995 Peter Dennis Bartok.
 * All Rights Reserved!
 *
 */

#ifndef TERRAN_MUXMEM_H
#define TERRAN_MUXMEM_H

#include <stdlib.h>						/* for size_t and the clib malloc def's*/

#define MEM_POS							__FILE__, __LINE__

#define	Malloc(size)					Malloc_Internal(size, MEM_POS)
#define	Calloc(size, ElSize)			Calloc_Internal(size, ElSize, MEM_POS)
#define	Free(block)						Free_Internal(block, MEM_POS)
#define 	Realloc(block, size)			Realloc_Internal(block, size, MEM_POS)
#define	Strdup(s)						Strdup_Internal(s, MEM_POS)
#define	Memcpy(d,s,size)				Memcpy_Internal(d,s,size, MEM_POS)
#define	Memset(d,c,size)				Memset_Internal(d,c,size, MEM_POS)

#define	malloc(size)					Malloc_Internal(size, MEM_POS)
#define	calloc(size, ElSize)			Calloc_Internal(size, ElSize, MEM_POS)
#define	free(block)						Free_Internal(block, MEM_POS)
#define 	realloc(block, size)			Realloc_Internal(block, size, MEM_POS)
#define	strdup(s)						Strdup_Internal(s, MEM_POS)
#define	memcpy(d,s,size)				Memcpy_Internal(d,s,size, MEM_POS)
#define	memset(d,c,size)				Memset_Internal(d,c,size, MEM_POS)


#define StrAllocCopy(dest, src) 		StrAllocCopy_Internal(&(dest), src)
#define StrAllocCat(dest, src)  		StrAllocCat_Internal(&(dest), src)

/* Functions in the string replacement code*/
void		*Malloc_Internal(size_t size, char *SourceFilename, int SourceCodeline);
void		*Calloc_Internal(size_t size, size_t ElSize, char *SourceFilename, int SourceCodeline);
void		Free_Internal(void *block, char *SourceFilename, int SourceCodeline);
void		*Realloc_Internal(void *block, size_t size, char *SourceFilename, int SourceCodeline);
void		*Strdup_Internal(const char *s, char *SourceFilename, int SourceCodeline);
void		*Memset_Internal(void *dest, int c, size_t n, char *SourceFilename, int SourceCodeline);
void		*Memcpy_Internal(void *dest, const void *src, size_t n, char *SourceFilename, int SourceCodeline);
char 		*StrAllocCopy_Internal(char **dest, char *src);
char 		*StrAllocCat_Internal(char **dest,  char *src);
void		ShutMemDown(char *Name);

#endif /* TERRAN_MUXMEM_H */
