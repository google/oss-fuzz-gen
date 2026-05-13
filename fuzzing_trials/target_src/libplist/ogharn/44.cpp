#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_44(char *fuzzData, size_t size)
{
	

   plist_format_t plist_from_memoryoverload3var3;
	memset(&plist_from_memoryoverload3var3, 0, sizeof(plist_from_memoryoverload3var3));

   char* plist_set_key_valvar1[size+1];
	sprintf((char *)plist_set_key_valvar1, "/tmp/smb6l");
   char** plist_to_binvar1[size+1];
	sprintf((char *)plist_to_binvar1, "/tmp/ba9f3");
   uint32_t plist_to_binvaruint32_tsize = sizeof(plist_to_binvar1);
   plist_t plist_new_dictval1 = plist_new_dict();
   plist_err_t plist_from_memoryoverload3val1 = plist_from_memory(fuzzData, size, &plist_new_dictval1, &plist_from_memoryoverload3var3);
	if(plist_from_memoryoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   plist_set_key_val(plist_new_dictval1, (char* )plist_set_key_valvar1);
   plist_err_t plist_to_binval1 = plist_to_bin(plist_new_dictval1, (char **)plist_to_binvar1, &plist_to_binvaruint32_tsize);
	if(plist_to_binval1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
