#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

int LLVMFuzzerTestOneInput_24(char *fuzzData, size_t size)
{
	

   char* pcap_initvar1[256];
	sprintf(pcap_initvar1, "/tmp/cyz1y");
   struct bpf_program pcap_compilevar1;
	memset(&pcap_compilevar1, 0, sizeof(pcap_compilevar1));

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
   pcap_dumper_t* pcap_dump_open_appendval1 = pcap_dump_open_append(pcap_open_deadval1, pcap_initvar1);
	if(!pcap_dump_open_appendval1){
		fprintf(stderr, "err");
		exit(0);	}
   pcap_breakloop(pcap_open_deadval1);
   return 0;
}
