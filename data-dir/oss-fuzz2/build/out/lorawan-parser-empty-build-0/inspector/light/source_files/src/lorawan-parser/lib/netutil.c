#include "netutil.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

// http://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
int netutil_get_mac_addr(char *iface, uint8_t *mac_address)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int ret = NETUTIL_IF_ERROR;
    int iface_flag = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        return NETUTIL_IF_ERROR;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        return NETUTIL_IF_ERROR;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if( ( iface != NULL)  && ( 0 == strcmp(ifr.ifr_name, iface) ) ){
            iface_flag = 1;
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                if (ifr.ifr_flags & IFF_LOOPBACK) { // don't count loopback
                    continue;
                }
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    ret = NETUTIL_IF_MATCHED;
                    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
                }
            }
            break;
        }
    }

    if( ( ret == NETUTIL_IF_ERROR ) && ( iface_flag == 0 ) ){
        it = ifc.ifc_req;
        for (; it != end; ++it) {
            strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                if (ifr.ifr_flags & IFF_LOOPBACK) { // don't count loopback
                    continue;
                }
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    ret = NETUTIL_IF_DEFAULT;
                    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
                    break;
                }
            }
        }
    }

    return ret;
}

void netutil_eui48_to_eui64(eui_fmt fmt, uint8_t *eui48, uint8_t *eui64)
{
	if(fmt == EUI_FMT_SMTC){
		eui64[0] = 0xFF;
		eui64[1] = 0xFE;
		eui64[2] = eui48[0];
		eui64[3] = eui48[1];
		eui64[4] = eui48[2];
		eui64[5] = eui48[3];
		eui64[6] = eui48[4];
		eui64[7] = eui48[5];
	}else{
		eui64[0] = eui48[0];
		eui64[1] = eui48[1];
		eui64[2] = eui48[2];
		if(fmt == EUI_FMT_IEEE_FFFE){
			eui64[3] = 0xFF;
			eui64[4] = 0xFE;
		}else{
			eui64[3] = 0xFF;
			eui64[4] = 0xFF;
		}
		eui64[5] = eui48[3];
		eui64[6] = eui48[4];
		eui64[7] = eui48[5];
	}
}
