#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <libbpf.h>

int LLVMFuzzerTestOneInput_2(char *fuzzData, size_t size)
{
   
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(fuzzData, size, 1, fp);
    fclose(fp);
    fuzzData = filename;


   struct bpf_object* bpf_object__openval1 = bpf_object__open(fuzzData);
	if(!bpf_object__openval1){
		fprintf(stderr, "err");
		exit(0);	}
   int bpf_object__find_map_fd_by_nameval1 = bpf_object__find_map_fd_by_name(bpf_object__openval1, fuzzData);
   return 0;
}
