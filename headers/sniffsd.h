#ifndef SNIFFSD_H_
#define SNIFFSD_H_

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>

#define ROOT_DIR "/"
#define START "start"
#define NETHERNET "eth0"
#define SELECT "select"
#define SHOW "show"
#define STAT "stat"
#define STOP "stop"
//ethernet headers are always exactly 14 bytes 
#define SIZE_ETHERNET 14

// IP header
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define N 128
#define M 256
#define BSIZE  1024

#include <set>
#include <algorithm>
#include <string>
#include <utility>
#include <map>
#include <unordered_map>
#include <vector>

struct NetData{
    
    using Packets = std::map<std::string, std::size_t>;
    using Packet = std::pair<std::string, std::size_t>;
    NetData() = default;
    
    void AddPacket(const std::string &);
    Packets  GetPackets() const;
    int FindPacket(const std::string &);
    
    
private:    
    Packets packets_m;
};
using NetDevices = std::unordered_map<std::string, NetData>;
using Slaves = std::set<int>;
using NameDevices = std::vector<std::string>;

pcap_t *JoinInterface(NameDevices &, const char *);
void CountDevices(NameDevices &);

void Daemon(void);
int SocketSettings(void);
int set_nonblock(int);

#endif