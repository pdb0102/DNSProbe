/*
 * Author: Pter Dennis Bartok (peter@venafi.com)
 */

#include "dnsprobe.h"
#include "resolve.h"

BOOL Lookup(char *value, int lookup_type);

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
		lookupname = "venafi.com";
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
	switch (status) {
		case DNS_SUCCESS: {
			switch (lookup_type) {
				case RR_A: {
					printf("Address Record%s\n", rec_count > 1 ? "s" : "");
					for (int i = 0; i < rec_count; i++) {
						printf("  %s: %s\n", records[i].A.name, inet_ntoa(records[i].A.addr));
					}
					detail_name = records[0].A.name;
					break;
				}

				case RR_PTR: {
					printf("Name Record%s\n", rec_count > 1 ? "s" : "");
					for (int i = 0; i < rec_count; i++) {
						printf("  %s: %s", value, records[i].PTR.name);
					}
					detail_name = records[0].PTR.name;
					break;
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
		printf("Zone Authority (SOA) Record%s\n", rec_count > 1 ? "s" : "");
		for (int i = 0; i < rec_count; i++) {
			printf("  Primary Source : %s\n", records[i].SOA.mname);
			printf("  Primary Contact: %s\n", records[i].SOA.rname);
			printf("  Serial         : %u\n", records[i].SOA.serial);
		}
	} else {
		printf("No Zone Authority (SOA) Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_MX, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		printf("Mail Exchanger Record%s\n", rec_count > 1 ? "s" : "");
		for (int i = 0; i < rec_count; i++) {
			printf("  Name         : %s\n", records[0].MX.name);
			printf("  Preference   : %u\n", records[i].MX.preference);
		}
	} else {
		printf("No Mail Exchanger (MX) Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_TLSA, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		printf("Transport Layer Security Protocol (TLSA) Record%s\n", rec_count > 1 ? "s" : "");
		for (int i = 0; i < rec_count; i++) {
			printf("  Cert Association Data : %s\n", records[0].TLSA.cert_assoc_data);
		}
	} else {
		printf("No Transport Layer Security Protocol (TLSA) Records\n");
	}

	status = DNSResolve(detail_name, &records, RR_TXT, &rec_count, authority);
	if (status == DNS_SUCCESS) {
		if (rec_count == 0) {
			printf("No TXT records\n");
		} else {
			printf("TXT records:%s\n", rec_count > 1 ? "s" : "");
			for (int i = 0; i < rec_count; i++) {
				printf("  %d: ", i);
				for (int j = 0; j < records[i].TXT.len; j++) {
					if (isascii(records[i].TXT.data[j])) {
						printf("%c", records[i].TXT.data[j]);
					} else {
						printf("[%x]", records[i].TXT.data[j]);
					}
				}
				printf("\n");
			}
		}
	} else {
		printf("No Text (TXT) Records\n");
	}

	return TRUE;
}



