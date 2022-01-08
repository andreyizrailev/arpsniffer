#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "mac_vendor.h"

/* Timeout for delivering packets to the app after they arrive to kernel */
#define PACKET_TIMEOUT_MS 1000

#define MAC_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ARGS(_x) _x[0], _x[1], _x[2], _x[3], _x[4], _x[5]

#define ERROR(_fmt, ...) fprintf(stderr, _fmt "\n", ##__VA_ARGS__);

static void
print_usage(const char *prog_name)
{
    printf("Usage: %s <device>\n", prog_name);
}

static void
check_options(int argc, char *argv[])
{
    if (argc != 2)
    {
        print_usage(argv[0]);
        exit(1);
    }
}

static pcap_t *
open_pcap(const char *device)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int dlt;

    handle = pcap_create(device, errbuf);
    if (handle == NULL)
    {
        ERROR("Failed to create a pcap handle for device '%s', error: %s",
              device, errbuf);
        return NULL;
    }

    if (pcap_set_promisc(handle, 1) != 0)
    {
        pcap_perror(handle, "pcap_set_promisc()");
        pcap_close(handle);
        return NULL;
    }

    if (pcap_set_timeout(handle, PACKET_TIMEOUT_MS) != 0)
    {
        pcap_perror(handle, "pcap_set_timeout()");
        pcap_close(handle);
        return NULL;
    }

    if (pcap_activate(handle) != 0)
    {
        pcap_perror(handle, "pcap_activate()");
        pcap_close(handle);
        return NULL;
    }

    dlt = pcap_datalink(handle);
    if (dlt != DLT_EN10MB)
    {
        ERROR("Device '%s' has datalink type %s, but only Ethernet is "
              "supported by this program",
              device, pcap_datalink_val_to_name(dlt));
        pcap_close(handle);
        return NULL;
    }

    return handle;
}

static int
set_arp_filter(pcap_t *handle, const char *device)
{
    bpf_u_int32 netaddr; /* Not used actually */
    bpf_u_int32 netmask;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    /* Get device's netmask needed for pcap_compile() */
    if (pcap_lookupnet(device, &netaddr, &netmask, errbuf) != 0)
    {
        ERROR("Failed to get netmask of device '%s', error: %s",
              device, errbuf);
        return 1;
    }

    /* Compile a bpf program to catch only arp packets */
    if (pcap_compile(handle, &filter, "arp", 0, netmask) != 0)
    {
        pcap_perror(handle, "pcap_compile() failed to compile 'arp' program");
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &filter) != 0)
    {
        pcap_perror(handle, "pcap_setfilter()");
        pcap_freecode(&filter);
        pcap_close(handle);
        return 1;
    }

    /* The filter can be freed right after pcap_setfilter() */
    pcap_freecode(&filter);

    return 0;
}

static void
process_packet(u_char *user, const struct pcap_pkthdr *header,
               const u_char *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ether_arp *arp_header;

    arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));

    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP)
    {
        ERROR("Caught non-ARP packet");
        return;
    }

    switch (ntohs(arp_header->arp_op))
    {
        case ARPOP_REQUEST:
            printf("Caught and ARP REQUEST\n");

            break;
        case ARPOP_REPLY:
            printf("Caught an ARP REPLY\n");

            break;
        default:
            ERROR("Caught an unsupported ARP packet with opcode %d",
                  arp_header->arp_op);
            return;
    }

    printf("Sender's MAC: " MAC_FMT "\n", MAC_ARGS(arp_header->arp_sha));
    printf("Sender's vendor is %s\n", get_vendor_by_mac(arp_header->arp_sha));
    printf("Receiver's MAC: " MAC_FMT "\n", MAC_ARGS(arp_header->arp_tha));
    /* Requests has zero receiver's MAC which is falsly recognised as Xerox */
    if (ntohs(arp_header->arp_op) != ARPOP_REQUEST)
    {
        printf("Receiver's vendor is %s\n",
               get_vendor_by_mac(arp_header->arp_tha));
    }
    printf("\n");
}

int
main(int argc, char *argv[])
{
    int ret = 0;
    char *device;
    pcap_t *handle;

    check_options(argc, argv);

    device = argv[1];

    handle = open_pcap(device);
    if (handle == NULL)
        return 1;

    if (set_arp_filter(handle, device) != 0)
        return 1;

    if (pcap_loop(handle, -1, process_packet, NULL) == PCAP_ERROR)
    {
        pcap_perror(handle, "pcap_loop()");
        ret = 1;
    }

    pcap_close(handle);

    return ret;
}
