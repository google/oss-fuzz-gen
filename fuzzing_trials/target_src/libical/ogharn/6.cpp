#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_6(char *fuzzData, size_t size)
{
	
        
   icalproperty_status ICAL_STATUS_XVAL = ICAL_STATUS_X;

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_set_status(icalcomponent_new_from_stringval1, ICAL_STATUS_XVAL);
   icalproperty_status icalcomponent_get_statusval1 = icalcomponent_get_status(icalcomponent_new_from_stringval1);
   icalvalue_set_status(NULL, icalcomponent_get_statusval1);
   return 0;
}
