/*
 *  (c) Copyright 1997 Peter Dennis Bartok
 *  (c) Copyright 2017 Peter Dennis Bartok
 */

#define SYSLOG_STRUCT_DEFINED

#include "platform.h"
#include "resolve.h"

/* Useful types and constants */

typedef unsigned char	uint8;
typedef unsigned short	uint16;
typedef unsigned long	uint32;

#define MTU				1537
#define HEADERSIZE		sizeof(struct Header)
#define RECINFOSIZE		sizeof(struct RecordInfo)
#define MXDATASIZE		sizeof(struct MXData)
#define ADATASIZE		sizeof(struct AData)
#define MAXTRIES		10
#define MAXCNAMELOOPS	10
#define TIMEOUT			5	/* Seconds */

#define DEBUG_RESOLVER	0

extern	int		Exiting;
char			VER_RESOLVER[] = {"$Revision:   1.0  $"};
char			**Resolvers		= NULL;
int				ResolverCount	= 0;

/* Pieces of a DNS packet */
#pragma pack (push, 1)
struct Header {
	uint16	id;		/* Query ID -- hopefully unique							*/
	uint16	flags;	/* Bit 0: query or response
					 * Bit 1-4: opcode
					 * Bit 5: authoritative answer
					 * Bit 6: truncation
					 * Bit 7: recursion desired
					 * Bit 8: recursion available
					 * Bit 9-11: unused, must be 0
					 * Bit 12-15: response code
					 */
	uint16	qdcount; /* Number of questions								*/
	uint16	ancount; /* Number of answers								*/
	uint16	nscount; /* Number of name server RRs in authority section	*/
	uint16	arcount; /* Number of RRs in additional records section		*/
} PackedStructure;

struct QuestionInfo {
	uint16	type;	/* Type of question		*/
	uint16	class;	/* Class of question	*/
} PackedStructure;

struct RecordInfo {
	uint16	type;
	uint16	class;
	uint32	ttl;
	uint16	datalength;
} PackedStructure;

struct MXData {
	uint16	preference;
} PackedStructure;

struct AData {
	uint32	address;
} PackedStructure;

#pragma pack(pop)

/* Constants for flags field of Header */
#define f_TypeResponse	0x8000	/* Packet contains response							*/
#define f_TypeQuery		0x0000	/* Packet contains query							*/

#define f_OpStatus		0x1000	/* Server status query								*/
#define f_OpInverse		0x0800	/* Inverse query									*/
#define f_OpStandard	0x0000	/* Standard query									*/

#define f_Authoritative 0x0400	/* Response is authoritative						*/
#define f_Truncated		0x0200	/* Packet was truncated by network					*/
#define f_WantRecursive	0x0100	/* Recursive lookup requested						*/
#define f_RecursiveUsed	0x0080	/* Recursive lookup available/used					*/

#define f_RCMask		0x000F	/* Throw away all but the return code				*/
#define f_ErrRefused	0x0005	/* The request was refused							*/
#define f_ErrNotImp		0x0004	/* Query type isn't implemented by server			*/
#define f_ErrName		0x0003	/* The name doesn't exist							*/
#define f_ErrFailure	0x0002	/* The name server experience an internal error		*/
#define f_ErrFormat		0x0001	/* The server can't interpret the query				*/
#define f_ErrNone		0x0000	/* No errors occurred								*/

/* Query class constants */
#define class_IN	0x0001	/* Internet class */

/* Prototypes */
static int EncodeName(char *name, char *buf, size_t bufsize);
static int DecodeName(char *response, uint32 offset, char *name);
static int CompareHosts(const void *name1, const void *name2);
static void FreeResolvers(void);


int 
DNSResolve(char *host, DNSRecord **list, int type, int *list_count, unsigned long ResolverAddress)
{
	BOOL				cnamelooping;						/* Are we looping on a CNAME?				*/
	int					actualTries;
	char				query[MTU];							/* Query packet								*/
	char				answer[MTU];						/* Answer packet							*/
	char				hostname[MAXDNSNAMELENGTH + 1];		/* Our local host							*/
	char				hostcopy[MAXDNSNAMELENGTH + 1];		/* Local copy of host to lookup	*/
	fd_set				fdr;								/* Readability socket mask					*/
	int					sock;
	struct Header		*queryH;							/* Header of query packet					*/
	struct Header		*answerH;							/* Header of answer packet					*/
	DNSRecord			*answers;							/* Array of answers							*/
	struct MXData		*mxdata;							/* Overlay for MX data						*/
	struct AData		*adata;								/* Overlay for A data						*/
	struct RecordInfo	*recinfo;							/* Overlay for answer record				*/
	struct QuestionInfo	*queryquestion;						/* Question info for query packet			*/
	struct sockaddr_in	to_sin;								/* Address of nameserver					*/
	struct sockaddr_in	from_sin;							/* Our address								*/
	struct timeval		tv;									/* Timout info								*/
	uint8				tries;								/* Number of times we've tried the query	*/
	uint32				answeroff;							/* Offset into answer packet				*/
	uint32				i;
	uint32				cnameloops = 0;						/* How many times have we looped on CNAME	*/
	uint32				numanswers;							/* Number of answers in response			*/
	uint32				queryoff;							/* Offset into query packet					*/
	uint32				size;								/* Size of response							*/
	int					curResolver;						/* Current resolver							*/
	int					resolver_count;						/* Local version of ResolverCount			*/		
	char				**resolvers;						/* Local version of Resolvers				*/
	int					ret_value;							/* Return value								*/
	

	/***** SETUP *****/
	if ((strlen(host) > MAXDNSNAMELENGTH) || (!strchr(host, '.'))) {
		return(DNS_BADHOSTNAME);
	}

	if (ResolverAddress == 0) {
		if (ResolverCount < 1) {
			return(DNS_FAIL);
		}
		resolvers = Resolvers;
		resolver_count = ResolverCount;
	} else {
		struct in_addr addr;

		resolver_count = 1;
		resolvers = malloc(sizeof(char *));
		addr.S_un.S_addr = ResolverAddress;
		resolvers[0] = _strdup(inet_ntoa(addr));
	}

	curResolver = 0;

	if (type!=RR_PTR) {
		strcpy_s(hostcopy, sizeof(hostcopy), host);
	} else {
		int	a,b,c,d, ok;
		char	*ptr, *ptr2;

		if (host[strlen(host)-1]!='A') {
			ok=0;
			strcpy_s(hostcopy, sizeof(hostcopy), host);
			ptr=strchr(hostcopy, '.');
			if (ptr) {
				*ptr='\0';
				a=atol(hostcopy);
				ptr2=strchr(ptr+1, '.');
				if (ptr2) {
					*ptr2='\0';
					b=atol(ptr+1);
					ptr=strchr(ptr2+1, '.');
					if (ptr) {
						*ptr='\0';
						c=atol(ptr2+1);
						d=atol(ptr+1);
						sprintf_s(hostcopy, sizeof(hostcopy), "%d.%d.%d.%d.IN-ADDR.ARPA", d, c, b, a);
						ok=1;
					}
				}
			}
			if(!ok) {
				return(DNS_BADHOSTNAME);
			}
		} else {
			strcpy_s(hostcopy, sizeof(hostcopy), host);
		}
	}	
	srand((unsigned int)time(NULL));
	queryH = (struct Header*)&query;	/* These are overlays to make the code		*/
	answerH = (struct Header*)&answer;	/* easier to write and more readable		*/
	*list = NULL;						/* Just to be safe							*/
	*list_count = 0;

	/* We loop here in case we get a CNAME in response to the query. We'll stop looping when
	 * we get an MX or A record, which is what we're looking for */
	do {
#if DEBUG_RESOLVER
		ConsolePrintf("Starting query loop\n");
#endif
		sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(sock < 0) {
			ret_value = DNS_FAIL;
			goto cleanup;
		}
		
		memset(&to_sin, 0, sizeof(to_sin));
		to_sin.sin_family = AF_INET;
		/* Address set in the loop below */
		to_sin.sin_port = htons(53);

		memset(&from_sin, 0, sizeof(from_sin));
		from_sin.sin_family = AF_INET;
		from_sin.sin_port = htons(0);								/* Any port */

		if(bind(sock, (struct sockaddr*)&from_sin, sizeof(from_sin))) {
			IPclose(sock);
			return(DNS_FAIL);
		}

		/***** INITIALIZE *****/
		cnamelooping = FALSE;	/* Will be set to TRUE if we get a CNAME response */
		tries = 0;
		actualTries = resolver_count * MAXTRIES;

		/***** BUILD QUERY *****/
#if DEBUG_RESOLVER
		ConsolePrintf("Building query\n");
#endif
		queryH->id = htons((uint16)rand());
		queryH->flags = htons(f_TypeQuery | f_OpStandard | f_WantRecursive);
		queryH->qdcount = htons(1);
		queryH->ancount = queryH->nscount = queryH->arcount = htons(0);

		queryoff = HEADERSIZE;
		queryoff += EncodeName(hostcopy, query + queryoff, MTU - queryoff);
		queryquestion = (struct QuestionInfo*)(query + queryoff);
		queryquestion->type = htons((uint16)type);
		queryquestion->class = htons(class_IN);
		queryoff += sizeof(queryquestion->type) + sizeof(queryquestion->class);
	
#if DEBUG_RESOLVER
		ConsolePrintf("---------- QUERY ----------\n");
		for(x = 0; x < queryoff; ++x) {
			ConsolePrintf("%02x %c ", query[x], query[x]);
		}
		ConsolePrintf("\n---------------------------\n");
#endif

		/***** RUN QUERY *****/
		do {
			if (Exiting) {
				if (sock != -1) {
					IPclose(sock);
				}
				ret_value = DNS_FAIL;
				goto cleanup;
			}

			to_sin.sin_addr.s_addr = inet_addr(resolvers[curResolver]);

			if(sendto(sock, query, queryoff, 0, (struct sockaddr*)&to_sin, sizeof(to_sin)) != (int)queryoff) {
				IPclose(sock);
				ret_value = DNS_FAIL;
				goto cleanup;
			}
		
			/* We have to do this every time because select() changes the mask and timeval struct */
			FD_ZERO(&fdr);
			FD_SET(sock, &fdr);
			tv.tv_sec = TIMEOUT;
			tv.tv_usec = 0;

			if(select(FD_SETSIZE, &fdr, NULL, NULL, &tv) <= 0) {
				curResolver++;
				if (curResolver >= resolver_count) {
					curResolver=0;
				}
				continue;		/* Timed out */
			}
		
			size = recv(sock, answer, MTU, 0);
			if (Exiting) {
				IPclose(sock);
				ret_value = DNS_FAIL;
				goto cleanup;
			}
#if DEBUG_RESOLVER
			ConsolePrintf("Size = %lu\n", size);
#endif

			if(size > 0 && answerH->id == queryH->id) {
				break;
			}

			curResolver++;
			if (curResolver >= resolver_count) {
				curResolver=0;
			}
		} while(++tries < actualTries);
		IPclose(sock);

		if(tries >= actualTries) {
			ret_value = DNS_TIMEOUT;
			goto cleanup;
		}
	
#if DEBUG_RESOLVER
		ConsolePrintf("---------- RESPONSE ----------\n");
		for(x = 0; x < size; ++x) {
			ConsolePrintf("%02x %c ", answer[x], answer[x]);
		}
		ConsolePrintf("\n------------------------------\n");
#endif

		/***** DECODE PACKET *****/
		answerH->flags = ntohs(answerH->flags);
		if((answerH->flags & f_RCMask) != f_ErrNone) {
			if((answerH->flags & f_RCMask) == f_ErrName) {
				ret_value = DNS_BADHOSTNAME;
				goto cleanup;
			} else {
				ret_value = DNS_FAIL;
				goto cleanup;
			}
		}
	
		numanswers = ntohs(answerH->ancount);
		if(numanswers == 0) {
			if ((type != RR_NS) && (type != RR_SOA)) {
				return(DNS_NORECORDS);
			}
			if (ntohs(answerH->nscount) == 0) {
				return(DNS_NORECORDS);
			}
			numanswers += ntohs(answerH->nscount);
		}

		/* The extra record is for a "NULL" termination record */
		answers = malloc(sizeof(DNSRecord) * (numanswers + 1));
		if(answers == NULL) {
			ret_value = DNS_FAIL;
			goto cleanup;
		}

		answeroff = HEADERSIZE;
		answeroff+= DecodeName(answer, answeroff, answers[0].A.name);
		answeroff+= sizeof(struct QuestionInfo);

/*		answeroff = queryoff; */	/* Skip question, which includes modified header */
		for(i = 0; (i < numanswers) && (!cnamelooping); ++i) {
			answeroff += DecodeName(answer, answeroff, answers[i].A.name);
			recinfo = (struct RecordInfo*)(answer + answeroff);
			answeroff += RECINFOSIZE;

#if DEBUG_RESOLVER
			ConsolePrintf("Question  : %s\n", answers[i].A.name);
			ConsolePrintf("Type      : %d\n", ntohs(recinfo->type));
			ConsolePrintf("Class     : %d\n", ntohs(recinfo->class));
			ConsolePrintf("TTL       : %lu\n", ntohl(recinfo->ttl));
			ConsolePrintf("Length    : %d\n", ntohs(recinfo->datalength));
#endif

			recinfo->type = ntohs(recinfo->type);
			switch(recinfo->type) {
				case RR_A:
					answers[i].type = RR_A;
					adata = (struct AData*)(answer + answeroff);
					answers[i].A.addr.s_addr = adata->address;
					answeroff += ADATASIZE;
#if DEBUG_RESOLVER
					ConsolePrintf("A Record\n");
					ConsolePrintf("Address   : %s\n", inet_ntoa(answers[i].A.addr));
#endif
					break;

				case RR_AAAA:
					answers[i].type = RR_AAAA;
					memcpy(&(answers[i].AAAA.addr), answer + answeroff, sizeof(struct in6_addr));
					answeroff += sizeof(struct in6_addr);
#if DEBUG_RESOLVER
					char buf[46];
					ConsolePrintf("AAAA Record\n");
					inet_ntop(AF_INET6, &answers[i].AAAA.addr, buf, 46);
					ConsolePrintf("Address   : %s\n", buf);
#endif
					break;

				case RR_MX:
					answers[i].type = RR_MX;
					mxdata = (struct MXData*)(answer + answeroff);
					answers[i].MX.preference = ntohs(mxdata->preference);
					answeroff += MXDATASIZE;
					answeroff += DecodeName(answer, answeroff, answers[i].MX.name);
					answers[i].MX.addr.s_addr = 0;

#if DEBUG_RESOLVER
					ConsolePrintf("MX Record\n");
					ConsolePrintf("Preference: %d\n", ntohs(answers[i].MX.preference));
					ConsolePrintf("Name      : %s\n", answers[i].MX.name);
#endif
					break;
				
				case RR_NS:
					answers[i].type = RR_NS;
					answeroff += DecodeName(answer, answeroff, answers[i].NS.nsdname);
#if DEBUG_RESOLVER
					ConsolePrintf("NS   : %s\n", inet_ntoa(answers[i].NS.nsdname));
#endif
					break;
				
				case RR_TXT:
					answers[i].type = RR_TXT;
					answers[i].TXT.len = *(answer+answeroff);
					answeroff += sizeof(unsigned char);
					memcpy(answers[i].TXT.data, answer+answeroff, answers[i].TXT.len);
					answers[i].TXT.data[answers[i].TXT.len]='\0';
					answeroff += answers[i].TXT.len;
#if DEBUG_RESOLVER
					ConsolePrintf("TXT Record\n");
					ConsolePrintf("Length   : %d\n", Answers[i].TXT.len);
					ConsolePrintf("Value    : %s\n", Answers[i].TXT.data);
#endif
					break;

				case RR_CNAME:
#if AUTO_RESOLVE_CNAME
					/* Instead of giving the CNAME back to the caller, we'll be nice and do the
					 * A lookup for them. */
					answeroff += DecodeName(answer, answeroff, answers[i].A.name);
#if DEBUG_RESOLVER
					ConsolePrintf("Got CNAME, looking up %s\n", answers[i].A.name);
#endif
					strcpy_s(hostcopy, sizeof(hostcopy), answers[i].A.name);
					free(answers);
					answers = NULL;

					cnamelooping = TRUE;
					++cnameloops;
#else
					answers[i].type = RR_CNAME;
					answeroff += DecodeName(answer, answeroff, answers[i].CNAME.name);
#endif
					break;

				case RR_PTR: {
					answeroff += DecodeName(answer, answeroff, answers[i].PTR.name);
					answers[i].type = RR_PTR;
#if DEBUG_RESOLVER
					ConsolePrintf("Got PTR, name:%s\n", answers[i].PTR.name);
#endif
					break;
				}

				case RR_TLSA:
					answers[i].type = RR_TLSA;
					answers[i].TLSA.usage = *(answer+answeroff);
					answeroff += sizeof(unsigned char);
					answers[i].TLSA.selector = *(answer+answeroff);
					answeroff += sizeof(unsigned char);
					answers[i].TLSA.matching_type = *(answer+answeroff);
					answeroff += sizeof(unsigned char);
					answeroff += DecodeName(answer, answeroff, answers[i].TLSA.cert_assoc_data);
#if DEBUG_RESOLVER
					ConsolePrintf("TLSA Record\n");
					ConsolePrintf("Value    : %s\n", Answers[i].TLSA.cert_assoc_data);
#endif
					break;

				case RR_SOA: {
					unsigned char	*ptr;

					answers[i].type = RR_SOA;

					answeroff += DecodeName(answer, answeroff, answers[i].SOA.mname);
					answeroff += DecodeName(answer, answeroff, answers[i].SOA.rname);

					answers[i].SOA.serial=ntohl(answer[answeroff] | answer[answeroff+1]<<8 | answer[answeroff+2]<<16 | answer[answeroff+3] << 24);
					answeroff += 4;

					answers[i].SOA.refresh=ntohl(answer[answeroff] | answer[answeroff+1]<<8 | answer[answeroff+2]<<16 | answer[answeroff+3] << 24);
					answeroff += 4;

					answers[i].SOA.retry=ntohl(answer[answeroff] | answer[answeroff+1]<<8 | answer[answeroff+2]<<16 | answer[answeroff+3] << 24);
					answeroff += 4;

					answers[i].SOA.expire=ntohl(answer[answeroff] | answer[answeroff+1]<<8 | answer[answeroff+2]<<16 | answer[answeroff+3] << 24);
					answeroff += 4;

					answers[i].SOA.minimum=ntohl(answer[answeroff] | answer[answeroff+1]<<8 | answer[answeroff+2]<<16 | answer[answeroff+3] << 24);
					answeroff += 4;

					/* Now fixup the email address */
					ptr=answers[i].SOA.rname;
					while (ptr[0] && ptr[0]!='.') {
						ptr++;
					}
					if (ptr[0]=='.') {
						ptr[0]='@';
					}

#if DEBUG_RESOLVER
					ConsolePrintf("SOA Record\n");
					ConsolePrintf("MName     : %s\n", answers[i].SOA.mname);
					ConsolePrintf("RName     : %s\n", answers[i].SOA.rname);
					ConsolePrintf("Serial    : %lu\n", answers[i].SOA.serial);
					ConsolePrintf("Refresh   : %lu\n", answers[i].SOA.refresh);
					ConsolePrintf("Retry     : %lu\n", answers[i].SOA.retry);
					ConsolePrintf("Expire    : %lu\n", answers[i].SOA.expire);
					ConsolePrintf("Minimum   : %lu\n", answers[i].SOA.minimum);
#endif
					break;
				}

				default:		/* We don't yet know how to deal with any other kinds of records */
					--i;
					--numanswers;
					break;
			}
		}
	} while(cnamelooping && (cnameloops < MAXCNAMELOOPS));

	if(cnameloops == MAXCNAMELOOPS) {
		ret_value = DNS_FAIL;
		goto cleanup;
	}

	/* We have to sort the MX records by preference. If we are one of the MX hosts, we also
	 * have to remove ourselves and anyone with higher precedence than us to prevent mail
	 * loops.
	 */
	if(type == RR_MX) {
		gethostname(hostname, sizeof(hostname));	
		if(numanswers > 1) {
			qsort(answers, numanswers, sizeof(DNSRecord), CompareHosts);
		}

		for(i = 0; i < numanswers; ++i) {
			if(_stricmp(hostname, answers[i].A.name) == 0) {
				unsigned long	match;

				/* Remove all hosts with our preference to prevent possible loops */
				match=i;
				while ((i>0) && (answers[i-1].MX.preference==answers[match].MX.preference)) {
					i--;
				}
				numanswers = i;
				break;
			}
		}
	}
	
	if( numanswers == 0) {
		free(answers);
		ret_value = DNS_NORECORDS;
		goto cleanup;
	}

	answers[numanswers].A.name[0] = '\0';
	answers[numanswers].MX.preference = 0;

	*list = answers;
	*list_count = numanswers;

#if DEBUG_RESOLVER
	if(type == RR_A) {
		i = 0;
		while((*list)[i].A.name[0] != '\0') {
			ConsolePrintf("%15s  : %s\n", inet_ntoa((*list)[i].A.addr), (*list)[i].A.name);
			++i;
		}
	}
#endif

	ret_value = DNS_SUCCESS;
cleanup:
	if (ResolverAddress != 0) {
		if (resolvers != NULL) {
			free(resolvers[0]);
			free(resolvers);
		}
	}

	return(ret_value);
}

static int
CompareHosts(const void *name1, const void *name2) 
{
	if(((DNSRecord*)name1)->MX.preference > ((DNSRecord*)name2)->MX.preference) {
		return(1);
	} else if (((DNSRecord*)name1)->MX.preference < ((DNSRecord*)name2)->MX.preference) {
		return(-1);
	}
	
	return(0);
}

static int 
EncodeName(char *name, char *buf, size_t bufsize) 
{
	BOOL	done	= FALSE;	/* Flag to stop processing */
	char	*ptr1	= name;		/* Beginning of current label */
	char	*ptr2	= NULL;		/* End of the current label */
	uint8	length	= 0;		/* Length of the current label */
	uint8	index	= 0;		/* Index into encoded buffer */
	
	/* Encode one label at a time */
	do {
		/* Find the end of the label */
		ptr2 = strchr(ptr1, '.');

		/* Is this the last label? */
		if(ptr2 == NULL) {
			ptr2 = ptr1 + strlen(ptr1) + 1;	/* Should already be '\0' */
			done = TRUE;
		}

		/* Separate this label */
		*ptr2 = '\0';
		
		/* Put in length byte */
		length = (uint8)strlen(ptr1);
		buf[index++] = length;

		/* Copy label */
		strcpy_s(buf + index, bufsize - index, ptr1);
		index += length;

		/* Set up for the next loop */
		if (!done)
			*ptr2='.';

		ptr1 = ptr2 + 1;
	} while(!done);
	
	/* Terminate with 0 length byte */
	buf[index++] = 0;
	
	return(index);		/* Tell caller how long the encoded name is */
}

static int
DecodeName(char *response, uint32 offset, char *name) 
{
	BOOL		pointer		= FALSE;		/* Is the label a pointer? */
	uint8		length;						/* Length of current labeL */
	uint16	nameoffset	= 0;			/* Offset into decoded name */
	uint32	encodedlen	= 0;			/* Length of encoded name */

	/* Process one label at a time till we get to 0 length label */

	do {
		/* Check for a pointer */
		if(response[offset] & 0xC0) {
			uint16	target;		/* Target of pointer */
			
			target = (response[offset++] & 0x3F) * 256;
			target += (uint8)response[offset];
			
			offset = target;

			/* The length of the encoded name only increases if we haven't already
			 * followed a pointer */
			if(!pointer) {
				encodedlen += 2;
			}
			
			pointer = TRUE;
		}
		
		length = response[offset++];

		if (length) {
			memcpy(name + nameoffset, response + offset, length);
			nameoffset += length;
			name[nameoffset++] = '.';
			
			offset += length;
		} else {
			/* Handle situation where the first length byte is 0 (=[ROOT]) */
			if (!pointer && encodedlen==0) {
				name[0]='.';
				name[1]='\0';
				return(1);
			}
		}

		if (!pointer) {
			encodedlen += length + 1;
		}
	} while(response[offset]!=0);

	if(!pointer) {
		++encodedlen;
	}

	/* Yes, we do want to overwrite the final '.' */
	name[--nameoffset] = '\0';
	
	return(encodedlen);
}

char *
DNSQueryTypeToString(int type)
{
	switch (type) {
		case RR_A: return "IPv4 Address";
		case RR_NS: return "Authoritative Name Server";
		case RR_CNAME: return "Canonical Name (alias)";
		case RR_SOA: return "Start of Zone Authority";
		case RR_PTR: return "Domain Name Pointer";
		case RR_MX: return "Mail Exchanger";
		case RR_TXT: return "Text";
		case RR_AAAA: return "IPv6 Address";
		case RR_SRV: return "Service Location Record";
		case RR_KX: return "Key Exchange Delegation";
		case RR_DS: return "DS";
		case RR_RRSIG: return "Signature for DNSSec Record Set";
		case RR_NSEC: return "Next Secure Record";
		case RR_DNSKEY: return "DNSSec Key Record ";
		case RR_CDNSKEY: return "Child copy of DNSKey";
		case RR_TLSA: return "Transport Layer Security Protocol";
		case RR_AXFR: return "Pseudo record - Zone Transfer";
		case RR_CAA: return "Certification Authority Restriction";
		case RR_TA: return "Trust Authority";
		case RR_DLV: return "Lookaside Validation record";
		default:
			return "unknown";
	}
}

void
AddResolver(char *ResolverValue)
{
	Resolvers=realloc(Resolvers, (ResolverCount+1) * sizeof(char *));
	if (!Resolvers) {
#if defined(LINUX)
		syslog(LOG_ERR, "Could not add resolver, out of memory.");
#else
		ConsolePrintf("Could not add resolver, out of memory.");
#endif
		return;
	}
	Resolvers[ResolverCount] = _strdup(ResolverValue);
	if (!Resolvers[ResolverCount]) {
#if defined(LINUX)
		syslog(LOG_ERR, "Could not add resolver, out of memory.");
#else
		ConsolePrintf("Could not add resolver, out of memory.");
#endif
		return;
	}
	ResolverCount++;
}

static void
FreeResolvers(void)
{
	int i;

	for (i=0; i<ResolverCount; i++)
		free(Resolvers[i]);

	if (Resolvers) {
		free(Resolvers);
	}
}

BOOL
ShutdownResolver(void)
{
	FreeResolvers();
	return(TRUE);
}

BOOL
InitResolver(char **resolvers, int count)
{
	char *resolver;
	for (int i = 0; i < count; i++) {
		resolver = resolvers[i];
		AddResolver(resolver);
		ConsolePrintf("Adding resolver %s", resolver);
	}

	return(TRUE);
}
