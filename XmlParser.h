#include "types.h"
#include "XendIp.h"
#include "XendIp_module.h"
#include "debug.h"

typedef struct _ip_pac {
    struct _ip_pac* next;
    struct _ip_pac* prev;
    sendip_module* first;
    sendip_module* last;
    sendip_data packet;
    unsigned int num_modules;
    unsigned int datalen;
    char* hdrs;
    char* data;
    sendip_data** headers;
    sendip_data d;
} ip_packet;

typedef struct _ip_p {
    unsigned int ip_n_solid;
    unsigned int port_n_solid;
    unsigned int ip_n_start;
    unsigned int port_n_start;
    unsigned int ip_n_end;
    unsigned int port_n_end;

    xmlChar* ip_c_solid;
    xmlChar* port_c_solid;
    xmlChar* ip_c_start;
    xmlChar* port_c_start;
    xmlChar* ip_c_end;
    xmlChar* port_c_end;
} ip_port;

typedef struct _fuz_info {
    bool src_ip_fuzz;
    bool src_pt_fuzz;
    bool dst_ip_fuzz;
    bool dst_pt_fuzz;
    bool reverse;
    unsigned int delay; //delay between test cases, whose unit is mili-second
    unsigned int iteration; //times that an identical sequence will be sent
} fuzzing_info;

#if DEBUG
static int dump_ipp_config(ip_port* ipp);
static int dump_fuzz_config(fuzzing_info* fuzz);
#endif

static int fuzz_info_init(fuzzing_info* fi);
static int init_ip_packet(ip_packet* ip_p);

static unsigned int ip_cton(char* ip);
static char* ip_ntoc(unsigned int ip_n, char* ip_c);
static char* port_ntoc(unsigned int ip_n, char* ip_c);

static sendip_module* load_module_x(char* modname, ip_packet* ip_p);
static void unload_module_x(sendip_module* module);

static int bgp_rip_ntp_builder(xmlNodePtr node, ip_packet* ipPacket);
static int tcp_udp_icmp_builder(xmlNodePtr node, ip_packet* ipPacket);
static int ip_builder (xmlNodePtr node);
static void build_the_packet();

static void stamp_and_send(char* host_name, unsigned int ip_s, unsigned int ip_d, unsigned int port_s, unsigned int port_d);
static void free_packet(ip_packet* packet);
static void free_ipp (ip_port* ipp);

int Xml_Fuzzer ( char* fileName);

extern int sendpacket(sendip_data *data, char *hostname, int af_type, bool verbose);
extern int compact_string(char *data_out);
