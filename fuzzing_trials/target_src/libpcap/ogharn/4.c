#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

int LLVMFuzzerTestOneInput_4(char *fuzzData, size_t size)
{
	

   unsigned int pcap_initvar0 = 1;
   char* pcap_initvar1[256];
	sprintf(pcap_initvar1, "/tmp/fase5");
   struct bpf_program pcap_compilevar1;
	memset(&pcap_compilevar1, 0, sizeof(pcap_compilevar1));

   struct pcap_pkthdr pcap_offline_filtervar1;
	memset(&pcap_offline_filtervar1, 0, sizeof(pcap_offline_filtervar1));

   int pcap_initval1 = pcap_init(pcap_initvar0, pcap_initvar1);
	if((int)pcap_initval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   pcap_t* pcap_open_deadval1 = pcap_open_dead(1, 1);
	if(!pcap_open_deadval1){
		fprintf(stderr, "err");
		exit(0);	}
   int pcap_compileval1 = pcap_compile(pcap_open_deadval1, &pcap_compilevar1, fuzzData, size, pcap_initval1);
	if((int)pcap_compileval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int pcap_offline_filterval1 = pcap_offline_filter(&pcap_compilevar1, &pcap_offline_filtervar1, pcap_initvar1);
   return 0;
}
