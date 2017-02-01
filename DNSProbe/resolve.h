/*
 *  (c)1997 Peter Dennis Bartok
 *  All Rights Reserved.
 *
 */

#ifndef _RESOLVE_H
#define _RESOLVE_H

#define MAXDNSNAMELENGTH 256
#include "platform.h"

#ifdef UNICODE
#error This method is designed for one byte character sets only
#endif

/* DNSResolve() returns a linked list of these structures */
#ifdef __cplusplus
extern "C" {
#endif

#pragma pack (push, 1)
typedef struct MXRecord {
	unsigned int	type;
	char			name[MAXDNSNAMELENGTH + 1];		/* The name of the mail exchanger */
	struct in_addr	addr;
	int				preference;
} MXRecord;

typedef struct ARecord {
	unsigned int	type;
	char			name[MAXDNSNAMELENGTH + 1];		/* The hostname */
	struct in_addr	addr;							/* The address of hostname		 */	
} ARecord;

typedef struct NSRecord {
	unsigned int	type;
	char			nsdname[MAXDNSNAMELENGTH + 1];	/* The hostname */
} NSRecord;

typedef struct PTRRecord {
	unsigned int	type;
	char			name[MAXDNSNAMELENGTH + 1];		/* The hostname					 */
} PTRRecord;

typedef struct SOARecord {
	unsigned int	type;
	char			mname[MAXDNSNAMELENGTH + 1];	/* The domain name primary source */
	char			rname[MAXDNSNAMELENGTH + 1];	/* The email for the authority	  */
	unsigned long	serial;							/* The version number of the zone */
	unsigned long	refresh;						/* zone refresh interval (sec)    */
	unsigned long	retry;							/* time to wait after failed refrsh*/
	unsigned long	expire;							/* max Time to keep data (sec)    */
	unsigned long	minimum;						/* TTL for zone (sec)             */
} SOARecord;

typedef struct TXTRecord {
	unsigned int	type;
	unsigned char	len;
	char			data[257];						/* Any provided <character string>s */
} TXTRecord;

typedef struct TLSARecord {
	unsigned int	type;
	unsigned char	usage;
	unsigned char	selector;
	unsigned char	matching_type;
	char			cert_assoc_data[257];			/* Any provided <character string>s */
} TLSARecord;

typedef union DNSRecord {
	unsigned int	type;
	ARecord		A;
	NSRecord	NS;
	MXRecord	MX;
	PTRRecord	PTR;
	SOARecord	SOA;
	TXTRecord	TXT;
	TLSARecord	TLSA;
} DNSRecord;
#pragma pack (pop)

/* RR type constants */
#define RR_A		0x0001	/* Host address */
#define RR_NS		0x0002	/* Authoritative name server*/
#define RR_CNAME	0x0005	/* Canonical name (alias) */
#define RR_SOA		0x0006	/* Start of Zone Authority */
#define RR_PTR		0x000C	/* Domain Name Pointer */
#define RR_MX		0x000F	/* Mail exchanger */
#define RR_TXT		0x0010	/* Text */
#define RR_AAAA		0x001C	/* IPv6 Host address */
#define RR_SRV		0x0021	/* Service Location record */
#define RR_KX		0x0024	/* Key Exchange Delegation */
#define RR_DS		0x002B	/* DS */
#define RR_RRSIG	0x002E	/* Signature for DNSSec record set */
#define RR_NSEC		0x002F	/* Next Secure Record */
#define RR_DNSKEY	0x0030	/* DNSSec Key Record */
#define RR_CDNSKEY	0x003C	/* Child copy of DNSKey */
#define RR_TLSA		0x0034	/* Transport Layer Security Protocol */
#define RR_AXFR		0x00FC	/* Pseudo record - zone transfer */
#define RR_CAA		0x0101	/* Certificateion Authority Restriction */
#define RR_TA		0x8000	/* Proposed: Trust Authority */
#define RR_DLV		0x8001	/* Proposed: Lookaside Validation record */

/* Return codes for MX */
#define DNS_SUCCESS		 0
#define DNS_BADHOSTNAME	-1
#define DNS_FAIL		-2
#define DNS_TIMEOUT		-3
#define DNS_NORECORDS	-4

/* Prototypes */
EXPORT int DNSResolve(char *host, DNSRecord **list, int type, int *list_count, unsigned long ResolverAddress);
EXPORT BOOL InitResolver(char **resolvers, int count);
EXPORT BOOL ShutdownResolver(void);

#ifdef __cplusplus
}
#endif

#endif /* _RESOLVE_H */
