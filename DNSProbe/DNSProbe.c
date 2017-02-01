/*
 * Author: Pter Dennis Bartok (peter@venafi.com)
 */

#include "dnsprobe.h"
#include "resolve.h"

BOOL Lookup(char *value, int lookup_type);
void DumpRecords(char *lookup, int type, DNSRecord *records, int rec_count);

int Exiting;
char **resolvers;


int main(int argc, char* argv[]) {
	char *lookupname;
	int lookup_type;

	IPInit();

	lookup_type = RR_A;
	resolvers = malloc(sizeof(char *) * 2);
	resolvers[0] = "8.8.8.8";

	InitResolver(resolvers, 1);
	if (argc > 1) {
		lookupname = argv[1];
	} else {
		lookupname = "google.com";
	}
	if (inet_addr(lookupname) != INADDR_NONE) {
		lookup_type = RR_PTR;
	}

	Lookup(lookupname, lookup_type);

	return 0;
}

BOOL
Lookup(char *value, int lookup_type) {
	DNSRecord *records;
	int status;
	int rec_count;
	char *detail_name;
	unsigned long authority;

	rec_count = 0;

	if (value != NULL) {
		status = DNSResolve(value, &records, lookup_type, &rec_count, 0);
	} else {
		printf("Gotta give me a value to look up");
		return FALSE;
	}
	if ((status == DNS_SUCCESS) && (rec_count == 0)) {
		printf("Strange - success on lookup, but no records returned");
		return FALSE;
	}

	printf("Resolving %s\n", value);
	detail_name = NULL;
	switch (status) {
		case DNS_SUCCESS: {
			for (int i = 0; i < rec_count; i++) {
				switch (lookup_type) {
					case RR_A: {
						printf("IPv4 Address Record\n");
						printf("  %s: %s\n", records[i].A.name, inet_ntoa(records[i].A.addr));
						if (detail_name == NULL) detail_name = records[i].A.name;
						break;
					}

					case RR_AAAA: {
						char buf[46];

						printf("IPv6 Address Record");
						inet_ntop(AF_INET6, &records[i].AAAA.addr, buf, 46);
						printf("  %s: %s\n", records[i].AAAA.name, buf);
						if (detail_name == NULL) detail_name = records[i].AAAA.name;
						break;
					}

					case RR_PTR: {
						printf("Name Record");
						printf("  %s: %s", value, records[i].PTR.name);
						if (detail_name == NULL) detail_name = records[i].PTR.name;
						break;
					}
				}
			}

			break;
		}

		case DNS_NORECORDS: {
			printf("No %s records exist", value);
			return FALSE;
		}

		case DNS_BADHOSTNAME: {
			printf("The hostname does not exist");
			return FALSE;
		}

		case DNS_TIMEOUT: {
			printf("The DNS server did not respond in a timely fashion");
			return FALSE;
		}

		case DNS_FAIL: {
			printf("Network or code failure");
			return FALSE;
		}
	}

	// Get the autoritative name server
	status = DNSResolve(detail_name, &records, RR_NS, &rec_count, 0);
	if ((status != DNS_SUCCESS) || (rec_count == 0)) {
		printf("Failed to look up NS authority\n");
		return FALSE;
	}
	DumpRecords(detail_name, RR_NS, records, rec_count);
	
	// Get the IP address of the authority
	status = DNSResolve(records[0].NS.nsdname, &records, RR_A, &rec_count, 0);
	if ((status != DNS_SUCCESS) || (rec_count == 0)) {
		printf("Failed to look up the A records of the NS authority\n");
		return FALSE;
	}

	authority = records[0].A.addr.S_un.S_addr;

	// look up details about 'value'
	status = DNSResolve(detail_name, &records, RR_SOA, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		DumpRecords(detail_name, RR_SOA, records, rec_count);
	} else {
		printf("No Zone Authority (SOA) Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_AAAA, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		DumpRecords(detail_name, RR_AAAA, records, rec_count);
	} else {
		printf("No IPv6 Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_CNAME, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		DumpRecords(detail_name, RR_CNAME, records, rec_count);
	} else {
		printf("No CNAME Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_MX, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		DumpRecords(detail_name, RR_MX, records, rec_count);
	} else {
		printf("No Mail Exchanger (MX) Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_TLSA, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		DumpRecords(detail_name, RR_TLSA, records, rec_count);
	} else {
		printf("No Transport Layer Security Protocol (TLSA) Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_TXT, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		DumpRecords(detail_name, RR_TXT, records, rec_count);
	} else {
		printf("No Text (TXT) Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_CAA, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		DumpRecords(detail_name, RR_CAA, records, rec_count);
	} else {
		printf("No CAA Records\n");
	}

	return TRUE;
}

void
DumpRecords(char *lookup, int type, DNSRecord *records, int rec_count) {
	printf("Query '%s', type '%s':\n", lookup, DNSQueryTypeToString(type));

	for (int i = 0; i < rec_count; i++) {
		switch (records[i].type) {
			case RR_A: {
				printf(" IPv4 Address\n");
				printf("  %s: %s\n", records[i].A.name, inet_ntoa(records[i].A.addr));
				break;
			}

			case RR_AAAA: {
				char buf[46];

				printf(" IPv6 Address\n");
				inet_ntop(AF_INET6, &records[i].AAAA.addr, buf, 46);
				printf("  %s: %s\n", records[i].AAAA.name, buf);
				break;
			}

			case RR_MX: {
				printf(" Mail Exchanger\n");
				printf("  %s: Pref %d\n", records[i].MX.name, records[i].MX.preference);
				break;
			}

			case RR_PTR: {
				printf(" PTR (Name from Address)\n");
				printf("  %s", records[i].PTR.name);
				break;
			}

			case RR_TXT: {
				printf(" Text\n  ");
				for (int j = 0; j < records[i].TXT.len; j++) {
					if (isascii(records[i].TXT.data[j])) {
						printf("%c", records[i].TXT.data[j]);
					} else {
						printf("[%x]", records[i].TXT.data[j]);
					}
				}
				printf("\n");
				break;
			}

			case RR_SOA: {
				printf(" Zone Authority\n");
				printf("  Primary Source : %s\n", records[i].SOA.mname);
				printf("  Primary Contact: %s\n", records[i].SOA.rname);
				printf("  Serial         : %u\n", records[i].SOA.serial);
				break;
			}

			case RR_TLSA: {
				printf(" Certificate Association Data\n");
				printf("  Cert Association Data : %s\n", records[i].TLSA.cert_assoc_data);
				break;
			}

			case RR_NS: {
				printf(" Name Server\n");
				printf("  NS Name: %s\n", records[i].NS.nsdname);
				break;
			}

			case RR_CNAME: {
				printf(" Canonical Name\n");
				printf("  NS Name: %s\n", records[i].NS.nsdname);
				break;
			}

			case RR_CAA: {
				printf(" CAA\n");
				printf("  Flags: %u\n", records[i].CAA.flags);
				printf("  %s: %s\n", records[i].CAA.tag, records[i].CAA.value);
				break;
			}
		}
	}
}



