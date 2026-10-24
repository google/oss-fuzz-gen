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
int LLVMFuzzerTestOneInput_120(char *fuzzData, size_t size)
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
	sprintf(dwarf_init_path_avar1, "/tmp/gys6k");
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

   Dwarf_Unsigned dwarf_linenovar1;
	memset(&dwarf_linenovar1, 0, sizeof(dwarf_linenovar1));

   Dwarf_Unsigned dwarf_get_loclist_offset_index_valuevar2;
	memset(&dwarf_get_loclist_offset_index_valuevar2, 0, sizeof(dwarf_get_loclist_offset_index_valuevar2));

   Dwarf_Unsigned dwarf_get_loclist_offset_index_valuevar3;
	memset(&dwarf_get_loclist_offset_index_valuevar3, 0, sizeof(dwarf_get_loclist_offset_index_valuevar3));

   Dwarf_Unsigned dwarf_get_loclist_offset_index_valuevar4;
	memset(&dwarf_get_loclist_offset_index_valuevar4, 0, sizeof(dwarf_get_loclist_offset_index_valuevar4));

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
   int dwarf_linenoval1 = dwarf_lineno(NULL, &dwarf_linenovar1, &dwarf_init_path_avar8);
	if((int)dwarf_linenoval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_get_loclist_offset_index_valueval1 = dwarf_get_loclist_offset_index_value(NULL, dwarf_linenovar1, dwarf_get_loclist_offset_index_valuevar2, &dwarf_get_loclist_offset_index_valuevar3, &dwarf_get_loclist_offset_index_valuevar4, &dwarf_init_path_avar8);
	if((int)dwarf_get_loclist_offset_index_valueval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
