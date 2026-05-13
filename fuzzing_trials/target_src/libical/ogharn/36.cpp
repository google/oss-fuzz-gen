#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_36(char *fuzzData, size_t size)
{
	
        

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   int icalcomponent_count_errorsval1 = icalcomponent_count_errors(icalcomponent_new_from_stringval1);
	if(icalcomponent_count_errorsval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   icalvalue_set_boolean(NULL, icalcomponent_count_errorsval1);
   return 0;
}
