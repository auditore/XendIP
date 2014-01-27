#include "types.h"
#include "XendIp_module.h"

extern int Xml_Fuzzer (char * __file);

typedef struct _s_m {
	struct _s_m *next;
	struct _s_m *prev;
	char *name;
	char optchar;
	sendip_data * (*initialize)(void);
	bool (*do_opt)(const char *optstring, const char *optarg, 
						sendip_data *pack);
	bool (*set_addr)(char *hostname, sendip_data *pack);
	bool (*finalize)(char *hdrs, sendip_data *headers[], sendip_data *data, 
						  sendip_data *pack);
	sendip_data *pack;
	void *handle;
	sendip_option *opts;
	int num_opts;
} sendip_module;
