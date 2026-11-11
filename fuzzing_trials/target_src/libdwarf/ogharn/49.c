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
int LLVMFuzzerTestOneInput_49(char *fuzzData, size_t size)
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
	sprintf(dwarf_init_path_avar1, "/tmp/2f95a");
   Dwarf_Ptr dwarf_init_path_avar6;
	memset(&dwarf_init_path_avar6, 0, sizeof(dwarf_init_path_avar6));

   Dwarf_Debug dwarf_init_path_avar7;
	memset(&dwarf_init_path_avar7, 0, sizeof(dwarf_init_path_avar7));

   Dwarf_Error dwarf_init_path_avar8;
	memset(&dwarf_init_path_avar8, 0, sizeof(dwarf_init_path_avar8));

   Dwarf_Cie* dwarf_get_fde_list_ehvar1;
	memset(&dwarf_get_fde_list_ehvar1, 0, sizeof(dwarf_get_fde_list_ehvar1));

   Dwarf_Signed dwarf_get_fde_list_ehvar2;
	memset(&dwarf_get_fde_list_ehvar2, 0, sizeof(dwarf_get_fde_list_ehvar2));

   Dwarf_Fde* dwarf_get_fde_list_ehvar3;
	memset(&dwarf_get_fde_list_ehvar3, 0, sizeof(dwarf_get_fde_list_ehvar3));

   Dwarf_Signed dwarf_get_fde_list_ehvar4;
	memset(&dwarf_get_fde_list_ehvar4, 0, sizeof(dwarf_get_fde_list_ehvar4));

   Dwarf_Off dwarf_get_cu_die_offset_given_cu_header_offset_bvar1;
	memset(&dwarf_get_cu_die_offset_given_cu_header_offset_bvar1, 0, sizeof(dwarf_get_cu_die_offset_given_cu_header_offset_bvar1));

   Dwarf_Off dwarf_get_cu_die_offset_given_cu_header_offset_bvar3;
	memset(&dwarf_get_cu_die_offset_given_cu_header_offset_bvar3, 0, sizeof(dwarf_get_cu_die_offset_given_cu_header_offset_bvar3));

   char* dwarf_package_versionval1 = dwarf_package_version();
	if(!dwarf_package_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_init_path_aval1 = dwarf_init_path_a(fuzzData, dwarf_init_path_avar1, sizeof(dwarf_init_path_avar1), DW_AT_call_parameter, DW_DLE_DEBUG_FRAME_DUPLICATE, function_pointer3458764516298326016fp, dwarf_init_path_avar6, &dwarf_init_path_avar7, &dwarf_init_path_avar8);
	if((int)dwarf_init_path_aval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_get_fde_list_ehval1 = dwarf_get_fde_list_eh(dwarf_init_path_avar7, &dwarf_get_fde_list_ehvar1, &dwarf_get_fde_list_ehvar2, &dwarf_get_fde_list_ehvar3, &dwarf_get_fde_list_ehvar4, &dwarf_init_path_avar8);
	if((int)dwarf_get_fde_list_ehval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_get_cu_die_offset_given_cu_header_offset_bval1 = dwarf_get_cu_die_offset_given_cu_header_offset_b(dwarf_init_path_avar7, dwarf_get_cu_die_offset_given_cu_header_offset_bvar1, DW_LANG_Ada2005, &dwarf_get_cu_die_offset_given_cu_header_offset_bvar3, &dwarf_init_path_avar8);
	if((int)dwarf_get_cu_die_offset_given_cu_header_offset_bval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   dwarf_dealloc_error(dwarf_init_path_avar7, dwarf_init_path_avar8);
   return 0;
}
