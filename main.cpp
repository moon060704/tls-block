#include "ansheader.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x01
#define TLS_EXT_SNI 0x0000
#define MAX_FLOW_BUF 65536

struct FlowKey
{
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;

    bool operator<(const FlowKey& r) const
    {
        if(sip != r.sip) return sip < r.sip;
        if(dip != r.dip) return dip < r.dip;
        if(sport != r.sport) return sport < r.sport;
        return dport < r.dport;
    }
};

struct Context
{
    pcap_t* pcap;
    int raw_sock;
    Mac my_mac;
    std::string server_name;
    std::map<FlowKey, std::vector<uint8_t>> flows;
};

void usage()
{
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

int get_my_info(const char* dev, Mac* mac, Ip* ip)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return -1;
    }

    memcpy(mac->m, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        return -1;
    }

    struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    ip->ip = sin->sin_addr.s_addr;

    close(sock);
    return 0;
}

uint16_t calc_checksum(const void* data, int len)
{
    const uint16_t* ptr = (const uint16_t*)data;
    uint32_t sum = 0;

    while(len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }

    if(len == 1)
    {
        sum += *(const uint8_t*)ptr;
    }

    while(sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint16_t calc_ip_checksum(Ipv4Hdr* ip)
{
    ip->checksum = 0;
    return calc_checksum(ip, sizeof(Ipv4Hdr));
}

uint16_t calc_tcp_checksum(
    const Ipv4Hdr* ip,
    const TcpHdr* tcp,
    const uint8_t* payload,
    uint16_t payload_len
)
{
    uint16_t tcp_len = sizeof(TcpHdr) + payload_len;

    TcpPseudoHdr pseudo;
    memset(&pseudo, 0, sizeof(pseudo));

    pseudo.src_ip = ip->ip_src;
    pseudo.dst_ip = ip->ip_dst;
    pseudo.reserved = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.tcp_len = htons(tcp_len);

    std::vector<uint8_t> buf(sizeof(TcpPseudoHdr) + tcp_len);
    memcpy(buf.data(), &pseudo, sizeof(TcpPseudoHdr));
    memcpy(buf.data() + sizeof(TcpPseudoHdr), tcp, sizeof(TcpHdr));

    if(payload_len > 0 && payload != nullptr)
    {
        memcpy(buf.data() + sizeof(TcpPseudoHdr) + sizeof(TcpHdr), payload, payload_len);
    }

    return calc_checksum(buf.data(), (int)buf.size());
}

static uint16_t read16(const uint8_t* p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read24(const uint8_t* p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static bool is_tls_start(const uint8_t* data, uint16_t len)
{
    if(data == nullptr || len == 0) return false;
    if(data[0] != TLS_HANDSHAKE) return false;

    if(len >= 3)
    {
        uint16_t ver = read16(data + 1);
        if(ver < 0x0300 || ver > 0x0304) return false;
    }

    return true;
}

static int parse_client_hello_body(const uint8_t* body, size_t len, std::string& sni)
{
    size_t p = 0;

    if(len < 2 + 32 + 1) return -1;

    p += 2;
    p += 32;

    uint8_t session_len = body[p++];
    if(p + session_len > len) return -1;
    p += session_len;

    if(p + 2 > len) return -1;
    uint16_t cipher_len = read16(body + p);
    p += 2;

    if(p + cipher_len > len) return -1;
    p += cipher_len;

    if(p + 1 > len) return -1;
    uint8_t comp_len = body[p++];
    if(p + comp_len > len) return -1;
    p += comp_len;

    if(p + 2 > len) return -1;
    uint16_t ext_len = read16(body + p);
    p += 2;

    if(p + ext_len > len) return -1;

    size_t ext_end = p + ext_len;

    while(p + 4 <= ext_end)
    {
        uint16_t type = read16(body + p);
        uint16_t size = read16(body + p + 2);
        p += 4;

        if(p + size > ext_end) return -1;

        if(type == TLS_EXT_SNI)
        {
            const uint8_t* ext = body + p;

            if(size < 2) return -1;

            uint16_t list_len = read16(ext);
            size_t q = 2;
            size_t list_end = 2 + list_len;

            if(list_end > size) return -1;

            while(q + 3 <= list_end)
            {
                uint8_t name_type = ext[q++];
                uint16_t name_len = read16(ext + q);
                q += 2;

                if(q + name_len > list_end) return -1;

                if(name_type == 0)
                {
                    sni.assign((const char*)ext + q, name_len);
                    return 1;
                }

                q += name_len;
            }

            return -1;
        }

        p += size;
    }

    return -1;
}

static int parse_tls_sni(const std::vector<uint8_t>& buf, std::string& sni)
{
    size_t p = 0;
    std::vector<uint8_t> handshake;

    while(true)
    {
        if(buf.size() - p < 5) return 0;

        uint8_t type = buf[p];
        uint16_t ver = read16(buf.data() + p + 1);
        uint16_t record_len = read16(buf.data() + p + 3);

        if(type != TLS_HANDSHAKE) return -1;
        if(ver < 0x0300 || ver > 0x0304) return -1;
        if(record_len == 0 || record_len > 18432) return -1;

        if(buf.size() - p - 5 < record_len) return 0;

        const uint8_t* record_body = buf.data() + p + 5;
        handshake.insert(handshake.end(), record_body, record_body + record_len);

        if(handshake.size() >= 4)
        {
            uint8_t hs_type = handshake[0];
            uint32_t hs_len = read24(handshake.data() + 1);

            if(hs_type != TLS_CLIENT_HELLO) return -1;
            if(hs_len == 0 || hs_len > 65535) return -1;

            if(handshake.size() >= 4 + hs_len)
            {
                return parse_client_hello_body(handshake.data() + 4, hs_len, sni);
            }
        }

        p += 5 + record_len;
    }
}

static bool send_forward_rst(
    pcap_t* pcap,
    const Mac* my_mac,
    const EthHdr* org_eth,
    const Ipv4Hdr* org_ip,
    const TcpHdr* org_tcp,
    uint16_t org_tcp_data_size
)
{
    uint8_t packet[sizeof(EthIpTcpPacket)];
    memset(packet, 0, sizeof(packet));

    EthHdr* eth = (EthHdr*)packet;
    Ipv4Hdr* ip = (Ipv4Hdr*)(packet + sizeof(EthHdr));
    TcpHdr* tcp = (TcpHdr*)((uint8_t*)ip + sizeof(Ipv4Hdr));

    eth->dst_mac = org_eth->dst_mac;
    eth->src_mac = *my_mac;
    eth->eth_type = htons(ETH_P_IPV4);

    set_ipv4_vhl(ip, IP_VERSION_IPV4, sizeof(Ipv4Hdr));
    ip->tos = 0;
    ip->total_len = htons(sizeof(Ipv4Hdr) + sizeof(TcpHdr));
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = org_ip->ttl;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->ip_src = org_ip->ip_src;
    ip->ip_dst = org_ip->ip_dst;
    ip->checksum = calc_ip_checksum(ip);

    tcp->sport = org_tcp->sport;
    tcp->dport = org_tcp->dport;
    tcp->seq = htonl(ntohl(org_tcp->seq) + org_tcp_data_size);
    tcp->ack = org_tcp->ack;
    set_tcp_hlen(tcp, sizeof(TcpHdr));
    tcp->flags = TCP_RST | TCP_ACK;
    tcp->window = 0;
    tcp->checksum = 0;
    tcp->urgent = 0;
    tcp->checksum = calc_tcp_checksum(ip, tcp, nullptr, 0);

    if(pcap_sendpacket(pcap, packet, sizeof(packet)) != 0)
    {
        fprintf(stderr, "pcap_sendpacket forward rst failed: %s\n", pcap_geterr(pcap));
        return false;
    }

    return true;
}

static bool send_backward_rst(
    int raw_sock,
    const Ipv4Hdr* org_ip,
    const TcpHdr* org_tcp,
    uint16_t org_tcp_data_size
)
{
    uint8_t packet[sizeof(Ipv4Hdr) + sizeof(TcpHdr)];
    memset(packet, 0, sizeof(packet));

    Ipv4Hdr* ip = (Ipv4Hdr*)packet;
    TcpHdr* tcp = (TcpHdr*)(packet + sizeof(Ipv4Hdr));

    set_ipv4_vhl(ip, IP_VERSION_IPV4, sizeof(Ipv4Hdr));
    ip->tos = 0;
    ip->total_len = htons(sizeof(Ipv4Hdr) + sizeof(TcpHdr));
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 128;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->ip_src = org_ip->ip_dst;
    ip->ip_dst = org_ip->ip_src;
    ip->checksum = calc_ip_checksum(ip);

    tcp->sport = org_tcp->dport;
    tcp->dport = org_tcp->sport;
    tcp->seq = org_tcp->ack;
    tcp->ack = htonl(ntohl(org_tcp->seq) + org_tcp_data_size);
    set_tcp_hlen(tcp, sizeof(TcpHdr));
    tcp->flags = TCP_RST | TCP_ACK;
    tcp->window = 0;
    tcp->checksum = 0;
    tcp->urgent = 0;
    tcp->checksum = calc_tcp_checksum(ip, tcp, nullptr, 0);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip->ip_dst.ip;

    ssize_t res = sendto(
        raw_sock,
        packet,
        sizeof(packet),
        0,
        (struct sockaddr*)&dst,
        sizeof(dst)
    );

    if(res < 0)
    {
        perror("sendto backward rst");
        return false;
    }

    return true;
}

static void packet_handler(
    u_char* user,
    const struct pcap_pkthdr* header,
    const u_char* packet
)
{
    Context* ctx = (Context*)user;

    if(header->caplen < sizeof(EthHdr) + sizeof(Ipv4Hdr) + sizeof(TcpHdr))
    {
        return;
    }

    const EthHdr* eth = (const EthHdr*)packet;

    if(ntohs(eth->eth_type) != ETH_P_IPV4)
    {
        return;
    }

    const Ipv4Hdr* ip = (const Ipv4Hdr*)(packet + sizeof(EthHdr));

    if(ipv4_version(ip) != IP_VERSION_IPV4)
    {
        return;
    }

    if(ip->protocol != IP_PROTOCOL_TCP)
    {
        return;
    }

    uint8_t ip_hlen = ipv4_header_len(ip);

    if(ip_hlen < sizeof(Ipv4Hdr))
    {
        return;
    }

    uint16_t ip_total_len = ntohs(ip->total_len);

    if(ip_total_len < ip_hlen + sizeof(TcpHdr))
    {
        return;
    }

    if(header->caplen < sizeof(EthHdr) + ip_total_len)
    {
        return;
    }

    uint16_t frag = ntohs(ip->frag_off);

    if((frag & 0x3fff) != 0)
    {
        return;
    }

    const TcpHdr* tcp = (const TcpHdr*)((const uint8_t*)ip + ip_hlen);
    uint8_t tcp_hlen = tcp_header_len(tcp);

    if(tcp_hlen < sizeof(TcpHdr))
    {
        return;
    }

    if(ip_total_len < ip_hlen + tcp_hlen)
    {
        return;
    }

    const uint8_t* tcp_data = (const uint8_t*)tcp + tcp_hlen;
    uint16_t tcp_data_size = ip_total_len - ip_hlen - tcp_hlen;

    if(tcp_data_size == 0)
    {
        return;
    }

    FlowKey key;
    key.sip = ip->ip_src.ip;
    key.dip = ip->ip_dst.ip;
    key.sport = tcp->sport;
    key.dport = tcp->dport;

    auto it = ctx->flows.find(key);

    if(it == ctx->flows.end())
    {
        if(!is_tls_start(tcp_data, tcp_data_size))
        {
            return;
        }

        it = ctx->flows.emplace(key, std::vector<uint8_t>()).first;
    }

    std::vector<uint8_t>& buf = it->second;
    buf.insert(buf.end(), tcp_data, tcp_data + tcp_data_size);

    if(buf.size() > MAX_FLOW_BUF)
    {
        ctx->flows.erase(key);
        return;
    }

    std::string sni;
    int res = parse_tls_sni(buf, sni);

    if(res == 0)
    {
        return;
    }

    ctx->flows.erase(key);

    if(res < 0)
    {
        return;
    }

    if(sni != ctx->server_name)
    {
        return;
    }

    bool forward_sent = send_forward_rst(
        ctx->pcap,
        &ctx->my_mac,
        eth,
        ip,
        tcp,
        tcp_data_size
    );

    bool backward_sent = send_backward_rst(
        ctx->raw_sock,
        ip,
        tcp,
        tcp_data_size
    );

    if(forward_sent && backward_sent)
    {
        printf("blocked %s\n", sni.c_str());
        fflush(stdout);
    }
}

int main(int argc, char* argv[])
{
    if(argc != 3)
    {
        usage();
        return EXIT_FAILURE;
    }

    const char* dev = argv[1];
    const char* server_name = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if(pcap == nullptr)
    {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    struct bpf_program fp;
    if(pcap_compile(pcap, &fp, "tcp port 443", 1, PCAP_NETMASK_UNKNOWN) == 0)
    {
        if(pcap_setfilter(pcap, &fp) != 0)
        {
            fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pcap));
        }

        pcap_freecode(&fp);
    }
    else
    {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pcap));
    }

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(raw_sock < 0)
    {
        perror("socket(AF_INET, SOCK_RAW, IPPROTO_RAW)");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    int opt = 1;
    if(setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt(IP_HDRINCL)");
        close(raw_sock);
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    Context ctx;
    ctx.pcap = pcap;
    ctx.raw_sock = raw_sock;
    ctx.server_name = server_name;

    Ip my_ip;
    if(get_my_info(dev, &ctx.my_mac, &my_ip) < 0)
    {
        close(raw_sock);
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    int res = pcap_loop(pcap, 0, packet_handler, (u_char*)&ctx);
    if(res == -1)
    {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(pcap));
    }

    close(raw_sock);
    pcap_close(pcap);

    return EXIT_SUCCESS;
}
