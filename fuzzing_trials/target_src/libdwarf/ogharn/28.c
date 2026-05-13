#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h>

static void function_pointer3458764516298326016fp(Dwarf_Error, Dwarf_Ptr){
	exit(0);
}
int LLVMFuzzerTestOneInput_28(char *fuzzData, size_t size)
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


   char* dwarf_init_path_avar1[256];
	sprintf(dwarf_init_path_avar1, "/tmp/xcofm");
   Dwarf_Ptr dwarf_init_path_avar6;
	memset(&dwarf_init_path_avar6, 0, sizeof(dwarf_init_path_avar6));

   Dwarf_Debug dwarf_init_path_avar7;
	memset(&dwarf_init_path_avar7, 0, sizeof(dwarf_init_path_avar7));

   Dwarf_Error dwarf_init_path_avar8;
	memset(&dwarf_init_path_avar8, 0, sizeof(dwarf_init_path_avar8));

   char** dwarf_gnu_debuglinkvar6[256];
	sprintf(dwarf_gnu_debuglinkvar6, "/tmp/5ofr1");
   char*** dwarf_gnu_debuglinkvar9[256];
	sprintf(dwarf_gnu_debuglinkvar9, "/tmp/xndbj");
   unsigned int dwarf_gnu_debuglinkvarU_INTsize = sizeof(dwarf_init_path_avar1);
   unsigned long dwarf_object_detector_path_bvar2 = 1;
   unsigned int dwarf_object_detector_path_bvar5 = 1;
   char* dwarf_package_versionval1 = dwarf_package_version();
	if(!dwarf_package_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_init_path_aval1 = dwarf_init_path_a(fuzzData, dwarf_init_path_avar1, sizeof(dwarf_init_path_avar1), DW_AT_call_parameter, DW_DLE_DEBUG_FRAME_DUPLICATE, function_pointer3458764516298326016fp, dwarf_init_path_avar6, &dwarf_init_path_avar7, &dwarf_init_path_avar8);
	if((int)dwarf_init_path_aval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!dwarf_init_path_avar1){
		fprintf(stderr, "err");
		exit(0);	}
	if(!dwarf_package_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
	if(!dwarf_init_path_avar1){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_gnu_debuglinkval1 = dwarf_gnu_debuglink(dwarf_init_path_avar7, &dwarf_init_path_avar1, &dwarf_package_versionval1, &fuzzData, &dwarf_init_path_aval1, &dwarf_init_path_aval1, dwarf_gnu_debuglinkvar6, &dwarf_init_path_avar1, &dwarf_gnu_debuglinkvarU_INTsize, dwarf_gnu_debuglinkvar9, &dwarf_init_path_aval1, &dwarf_init_path_avar8);
	if((int)dwarf_gnu_debuglinkval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_object_detector_path_bval1 = dwarf_object_detector_path_b(dwarf_package_versionval1, fuzzData, dwarf_object_detector_path_bvar2, &fuzzData, sizeof(fuzzData), &dwarf_object_detector_path_bvar5, &dwarf_init_path_aval1, &dwarf_init_path_aval1, NULL, NULL, &dwarf_init_path_aval1);
	if((int)dwarf_object_detector_path_bval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
