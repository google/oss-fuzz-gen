#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_55(char *fuzzData, size_t size)
{
	

   plist_format_t plist_from_memoryoverload3var3;
	memset(&plist_from_memoryoverload3var3, 0, sizeof(plist_from_memoryoverload3var3));

   char* plist_write_to_filevar1[size+1];
	sprintf((char *)plist_write_to_filevar1,"/tmp/e6qzj");
   plist_t plist_new_dictval1 = plist_new_dict();
   plist_err_t plist_from_memoryoverload3val1 = plist_from_memory(fuzzData, size, &plist_new_dictval1, &plist_from_memoryoverload3var3);
	if(plist_from_memoryoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   plist_err_t plist_write_to_fileval1 = plist_write_to_file(plist_new_dictval1, (char *)plist_write_to_filevar1,plist_from_memoryoverload3var3, PLIST_OPT_INDENT);
	if(plist_write_to_fileval1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   int plist_int_val_is_negativeval1 = plist_int_val_is_negative(plist_new_dictval1);
	if((int)plist_int_val_is_negativeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   plist_err_t plist_write_to_fileoverload2val1 = plist_write_to_file(plist_new_dictval1, fuzzData, PLIST_FORMAT_LIMD, PLIST_OPT_INDENT);
	if(plist_write_to_fileoverload2val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
