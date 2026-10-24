#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

int LLVMFuzzerTestOneInput_5(char *fuzzData, size_t size)
{
	

   char* pcap_initvar1[256];
	sprintf(pcap_initvar1, "/tmp/f4662");
   struct bpf_program pcap_compilevar1;
	memset(&pcap_compilevar1, 0, sizeof(pcap_compilevar1));

   char* pcap_parsesrcstrvar0[256];
	sprintf(pcap_parsesrcstrvar0, "/tmp/ifdns");
   char* pcap_parsesrcstrvar3[256];
	sprintf(pcap_parsesrcstrvar3, "/tmp/4dfl9");
   char* pcap_createsrcstrvar2[256];
	sprintf(pcap_createsrcstrvar2, "/tmp/s83s5");
   char* pcap_createsrcstrvar5[256];
	sprintf(pcap_createsrcstrvar5, "/tmp/gt7jl");
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
   int pcap_createsrcstrval1 = pcap_createsrcstr(pcap_parsesrcstrvar3, pcap_compileval1, pcap_createsrcstrvar2, pcap_initvar1, pcap_parsesrcstrvar3, pcap_createsrcstrvar5);
	if((int)pcap_createsrcstrval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int pcap_datalink_name_to_valval1 = pcap_datalink_name_to_val(pcap_parsesrcstrvar3);
   return 0;
}
