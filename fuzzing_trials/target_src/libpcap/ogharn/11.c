#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

int LLVMFuzzerTestOneInput_11(char *fuzzData, size_t size)
{
	

   char* pcap_initvar1[256];
	sprintf(pcap_initvar1, "/tmp/lm6yl");
   struct bpf_program pcap_compilevar1;
	memset(&pcap_compilevar1, 0, sizeof(pcap_compilevar1));

   char* pcap_parsesrcstrvar0[256];
	sprintf(pcap_parsesrcstrvar0, "/tmp/vdx2b");
   char* pcap_parsesrcstrvar3[256];
	sprintf(pcap_parsesrcstrvar3, "/tmp/0upg9");
   int pcap_initval1 = pcap_init(0, pcap_initvar1);
	if((int)pcap_initval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   pcap_t* pcap_open_deadval1 = pcap_open_dead(0, 1);
	if(!pcap_open_deadval1){
		fprintf(stderr, "err");
		exit(0);	}
   int pcap_compileval1 = pcap_compile(pcap_open_deadval1, &pcap_compilevar1, fuzzData, size, pcap_initval1);
	if((int)pcap_compileval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int pcap_parsesrcstrval1 = pcap_parsesrcstr(pcap_parsesrcstrvar0, &pcap_compileval1, NULL, pcap_parsesrcstrvar3, NULL, pcap_initvar1);
	if((int)pcap_parsesrcstrval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   pcap_t* pcap_createval1 = pcap_create(pcap_parsesrcstrvar3, pcap_parsesrcstrvar0);
	if(!pcap_createval1){
		fprintf(stderr, "err");
		exit(0);	}
   int pcap_sendpacketval1 = pcap_sendpacket(pcap_createval1, pcap_parsesrcstrvar3, pcap_compileval1);
	if((int)pcap_sendpacketval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
