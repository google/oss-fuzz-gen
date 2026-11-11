#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <hf.h>
#include <keys.h>
#include <msg_parser.h>
#include <parse_addr_spec.h>
#include <parse_allow.h>
#include <parse_body.h>
#include <parse_content.h>
#include <parse_cseq.h>
#include <parse_date.h>
#include <parse_def.h>
#include <parse_disposition.h>
#include <parse_diversion.h>
#include <parse_event.h>
#include <parse_expires.h>
#include <parse_fline.h>
#include <parse_from.h>
#include <parse_hname2.h>
#include <parse_identity.h>
#include <parse_identityinfo.h>
#include <parse_methods.h>
#include <parse_nameaddr.h>
#include <parse_option_tags.h>
#include <parse_param.h>
#include <parse_ppi_pai.h>
#include <parse_privacy.h>
#include <parse_refer_to.h>
#include <parse_require.h>
#include <parse_retry_after.h>
#include <parse_rpid.h>
#include <parse_rr.h>
#include <parse_sipifmatch.h>
#include <parse_subscription_state.h>
#include <parse_supported.h>
#include <parse_to.h>
#include <parse_uri.h>
#include <parse_via.h>
#include <parser_f.h>

int LLVMFuzzerTestOneInput_86(char *fuzzData, size_t size)
{
	

   struct sip_uri parse_urivar2;
	memset(&parse_urivar2, 0, sizeof(parse_urivar2));

   char* parse_addr_specvar0[size+1];
	sprintf(parse_addr_specvar0, "/tmp/fr3m1");
   struct to_body parse_addr_specvar2;
	memset(&parse_addr_specvar2, 0, sizeof(parse_addr_specvar2));

   event_t event_parservar2;
	memset(&event_parservar2, 0, sizeof(event_parservar2));

   char* parse_priv_valuevar0[size+1];
	sprintf(parse_priv_valuevar0, "/tmp/t10bi");
   int parse_urival1 = parse_uri(fuzzData, size, &parse_urivar2);
	if((int)parse_urival1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   char* parse_addr_specval1 = parse_addr_spec(parse_addr_specvar0, fuzzData, &parse_addr_specvar2, size);
	if(!parse_addr_specval1){
		fprintf(stderr, "err");
		exit(0);	}
   int event_parserval1 = event_parser(parse_addr_specval1, sizeof(parse_addr_specval1), &event_parservar2);
	if((int)event_parserval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   unsigned int parse_priv_valueval1 = parse_priv_value(parse_priv_valuevar0, sizeof(parse_priv_valuevar0), &event_parserval1);
	if((int)parse_priv_valueval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
