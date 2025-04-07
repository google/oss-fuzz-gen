#ifndef __NETWORK_UTILITIES_H
#define __NETWORK_UTILITIES_H

#include <stdint.h>

#define NETUTIL_IF_ERROR				-1
#define NETUTIL_IF_MATCHED				0
#define NETUTIL_IF_DEFAULT				1

typedef enum{
	EUI_FMT_IEEE_FFFE,
	EUI_FMT_IEEE_FFFF,
	EUI_FMT_SMTC,
}eui_fmt;

int netutil_get_mac_addr(char *iface, uint8_t *mac_address);
void netutil_eui48_to_eui64(eui_fmt fmt, uint8_t *eui48, uint8_t *eui64);

#endif
