/******************************************
Author: Yifu Li
Date: 2013-12-31
File Name: XmlParser.c
Purpose: Implement an XML parser for XendIp 
 ******************************************/

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>
#include <iconv.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ctype.h> /* isprint */

/* everything else */
#include "XmlParser.h"
#include "XendIp_module.h"
#include "debug.h"
#include "ipv4.h"

/*
* The linked list that defines all packets in a 'sequence'.
*/
ip_packet* first_packet;
ip_packet* last_packet;

/*
* The linked list that defines all kinds of protocols used in the fuzzing test.
*/
sendip_module* first_loaded;
sendip_module* last_loaded;

#if DEBUG_DUMP
/*
* This function displays the ip address / port infomation in debug mode.
*/
static int dump_ipp_config(ip_port* ipp)
{
    fprintf(stderr,"ip_c_solid    = %s\n",(char*)ipp->ip_c_solid);
    fprintf(stderr,"ip_c_start    = %s\n",(char*)ipp->ip_c_start);
    fprintf(stderr,"ip_c_end      = %s\n",(char*)ipp->ip_c_end);
    fprintf(stderr,"port_c_solid  = %s\n",(char*)ipp->port_c_solid);
    fprintf(stderr,"port_c_start  = %s\n",(char*)ipp->port_c_start);
    fprintf(stderr,"port_c_end    = %s\n",(char*)ipp->port_c_end);
    fprintf(stderr,"\n\n");
    fprintf(stderr,"ip_n_solid    = %8x\n",ipp->ip_n_solid);
    fprintf(stderr,"ip_n_start    = %8x\n",ipp->ip_n_start);
    fprintf(stderr,"ip_n_end      = %8x\n",ipp->ip_n_end);
    fprintf(stderr,"port_n_solid  = %d\n",ipp->port_n_solid);
    fprintf(stderr,"port_n_start  = %d\n",ipp->port_n_start);
    fprintf(stderr,"port_n_end    = %d\n",ipp->port_n_end);

    return 0;
}

/*
* This function displays the fuzzing infomation in debug mode.
*/
static int dump_fuzz_config(fuzzing_info* fuzz)
{

    fprintf(stderr,"src_ip_fuzz   = %d\n",(const int)fuzz->src_ip_fuzz);
    fprintf(stderr,"src_pt_fuzz   = %d\n",(const int)fuzz->src_pt_fuzz);
    fprintf(stderr,"dst_ip_fuzz   = %d\n",(const int)fuzz->dst_ip_fuzz);
    fprintf(stderr,"dst_pt_fuzz   = %d\n",(const int)fuzz->dst_pt_fuzz);
    fprintf(stderr,"reverse       = %d\n",(const int)fuzz->reverse);
    fprintf(stderr,"delay         = %d\n",fuzz->delay);
    return 0;
}
#endif

/*
* This function initiates the fuzzing information structure.
*/
static int fuzz_info_init(fuzzing_info* fi)
{
    if (fi == NULL)
        fprintf(stderr,"fuzz_info_init: Something must be wrong!\n");
    else
    {
        fi->src_ip_fuzz = FALSE;
        fi->src_pt_fuzz = FALSE;
        fi->dst_ip_fuzz = FALSE;
        fi->dst_pt_fuzz = FALSE;
        fi->reverse     = FALSE;
        fi->delay       = 0;
    }

    return 0;
}

/*
* This function initiates the ip address and port information structure.
*/
static int init_ip_packet(ip_packet* ip_p)
{
    if(ip_p ==NULL)
        return -1;

    ip_p->next  = NULL;
    ip_p->prev  = NULL;
    ip_p->first = NULL;
    ip_p->last  = NULL;
    ip_p->packet.data = NULL;
    ip_p->packet.alloc_len = 0;
    ip_p->packet.modified = 0;
    ip_p->num_modules = 0;
    ip_p->datalen = 0;
    ip_p->hdrs = NULL;
    ip_p->data = NULL;
    ip_p->headers = NULL;
    ip_p->d.data = NULL;
    ip_p->d.alloc_len = 0;
    ip_p->d.modified = 0;

    return 0;
}

/*
* The function turns a port number from integer format to string format.
*/
static char* port_ntoc(unsigned int port_n, char* port_c)
{
    unsigned int tmp = 0;
    unsigned int i = 0;

    if (port_c == NULL)
    {
        fprintf(stderr,"port_ntoc: Null pointer is not allowed!\n");
    }
    else if (port_n > 65535)
    {
        fprintf(stderr,"port_ntoc: port number is out of range!\n");
    }
    else
    {
        port_c[0] =(char)((unsigned int)(48+port_n/10000));
        port_c[1] =(char)((unsigned int)(48+(port_n/1000)%10));
        port_c[2] =(char)((unsigned int)(48+(port_n/100)%10));
        port_c[3] =(char)((unsigned int)(48+(port_n/10)%10));
        port_c[4] =(char)((unsigned int)(48+port_n%10));
    }

    for(i = 0; i < 5; i++)
    {
        if(port_c[i] == '0')
            continue;
        else
        {
            port_c += i;
            break;
        }
    }

#if DEBUG
    printf("port_ntoc: port_c = %s\n", port_c);
#endif

    return port_c;
}

/*
* The function turns an ip address from integer format to string format.
*/
static char* ip_ntoc(unsigned int ip_n, char* ip_c)
{
    unsigned int tmp_n;
    char ip_c0 = '\0';
    char ip_c1 = '\0';
    char ip_c2 = '\0';
    unsigned int i = 0;

    if (ip_c == NULL)
    {
        fprintf(stderr,"ip_ntoc: Null pointer is not allowed!\n");
    }
    else
    {
        tmp_n = (ip_n & 0xff000000) >> 24;

        if (tmp_n < 10)
        {
            ip_c[i] = (char)(48+tmp_n);
            ip_c[i+1] = '.';
            i += 2;
        }
        else if (tmp_n <100)
        {
            ip_c[i] = (char)((unsigned int)(48+tmp_n/10));
            ip_c[i+1] = (char)((unsigned int)(48+tmp_n%10));
            ip_c[i+2] = '.';
            i += 3;
        }
        else if (tmp_n < 256)
        {
            ip_c[i] = (char)((unsigned int)(48+tmp_n/100));
            ip_c[i+1] = (char)((unsigned int)(48+(tmp_n/10)%10));
            ip_c[i+2] = (char)((unsigned int)(48+tmp_n%10));
            ip_c[i+3] = '.';
            i += 4;
        }
        else
        {
            fprintf(stderr,"IP address out of RANGE!\n");
            return -1;
        }

        tmp_n = (ip_n & 0x00ff0000) >> 16;

        if (tmp_n < 10)
        {
            ip_c[i] = (char)(48+tmp_n);
            ip_c[i+1] = '.';
            i += 2;
        }
        else if (tmp_n <100)
        {
            ip_c[i] = (char)((unsigned int)(48+tmp_n/10));
            ip_c[i+1] = (char)((unsigned int)(48+tmp_n%10));
            ip_c[i+2] = '.';
            i += 3;
        }
        else if (tmp_n < 256)
        {
            ip_c[i] = (char)((unsigned int)(48+tmp_n/100));
            ip_c[i+1] = (char)((unsigned int)(48+(tmp_n/10)%10));
            ip_c[i+2] = (char)((unsigned int)(48+tmp_n%10));
            ip_c[i+3] = '.';
            i += 4;
        }
        else
        {
            fprintf(stderr,"IP address out of RANGE!\n");
            return -2;
        }

        tmp_n = (ip_n & 0x0000ff00) >> 8;

        if (tmp_n < 10)
        {
            ip_c[i] = (char)(48+tmp_n);
            ip_c[i+1] = '.';
            i += 2;
        }
        else if (tmp_n <100)
        {
            ip_c[i] = (char)((unsigned int)(48+tmp_n/10));
            ip_c[i+1] = (char)((unsigned int)(48+tmp_n%10));
            ip_c[i+2] = '.';
            i += 3;
        }
        else if (tmp_n < 256)
        {
            ip_c[i] = (char)((unsigned int)(48+tmp_n/100));
            ip_c[i+1] = (char)((unsigned int)(48+(tmp_n/10)%10));
            ip_c[i+2] = (char)((unsigned int)(48+tmp_n%10));
            ip_c[i+3] = '.';
            i += 4;
        }
        else
        {
            fprintf(stderr,"IP address out of RANGE!\n");
            return -3;
        }

        tmp_n = (ip_n & 0x000000ff);

        if (tmp_n < 10)
        {
            ip_c[i] = (char)(48+tmp_n);
        }
        else if (tmp_n <100)
        {
            ip_c[i] = (char)((unsigned int)(48+tmp_n/10));
            ip_c[i+1] = (char)((unsigned int)(48+tmp_n%10));
        }
        else if (tmp_n < 256)
        {
            ip_c[i] = (char)((unsigned int)(48+tmp_n/100));
            ip_c[i+1] = (char)((unsigned int)(48+(tmp_n/10)%10));
            ip_c[i+2] = (char)((unsigned int)(48+tmp_n%10));
        }
        else
        {
            fprintf(stderr,"IP address out of RANGE!\n");
            return -4;
        }
    }

    return ip_c;
}

/*
* The function turns an ip address from string format to string format.
*/
static unsigned int ip_cton(char* ip)
{

    unsigned int sum=0,i=0,j=0,n=0;
    int cnt=4;
    char tmp[4];
    tmp[0] = tmp[1] = tmp[2] = tmp[3] = '\0'; 

    if( ip != NULL )
    {
        while(cnt>0)
        {
            unsigned int tmpsum=0;

            if((ip[j]!='.')&&(ip[j]!='\0'))
            {
                tmp[i]=ip[j]; 
                i++;j++;
            }
            else
            {
                i=0;j++;            
                tmpsum=atoi((const char*)tmp);
                if (cnt!=1)
                {
                    for(n=cnt-1;n>=1;n--)
                        tmpsum*=256;
                }
                tmp[0] = tmp[1] = tmp[2] = tmp[3] = '\0';
                cnt--;            
            }

            sum+=tmpsum;
        }
    }
    else
        sum = 0;

    return sum;
}

/*
* This function frees the ip address / port information structure.
*/
static void free_ipp (ip_port* ipp)
{
    if(ipp->ip_c_solid != NULL)
    {
        free(ipp->ip_c_solid);
        ipp->ip_c_solid = NULL;
    }

    if(ipp->port_c_solid != NULL)
    {
        free(ipp->port_c_solid);
        ipp->port_c_solid = NULL;
    }

    if(ipp->ip_c_start != NULL);
    {
        free(ipp->ip_c_start);
        ipp->ip_c_start = NULL;
    }

    if(ipp->port_c_start != NULL);
    {
        free(ipp->port_c_start);
        ipp->port_c_start = NULL;
    }

    if(ipp->ip_c_end != NULL);
    {
        free(ipp->ip_c_end);
        ipp->ip_c_end = NULL;
    }

    if(ipp->port_c_end != NULL);
    {
        free(ipp->port_c_end);
        ipp->port_c_end = NULL;
    }
}

/*
* This function frees 'packet' structure.
*/
static void free_packet(ip_packet* packet)
{
    if(packet->first != NULL)
    {
        free(packet->first);
        packet->first = NULL;
    }
    if(packet->hdrs != NULL)
    {
        free(packet->hdrs);
        packet->hdrs = NULL;
    }
    if(packet->headers != NULL)
    {
        free(packet->headers);
        packet->headers = NULL;
    }
    if(packet->data != NULL)
    {
        free(packet->data);
        packet->data = NULL;
    }
    if(packet->packet.data != NULL)
    {
        free(packet->packet.data);
        packet->packet.data = NULL;
    }
}

/*
* This function unloads the dynamic libraries which helps defining the protocols.
*/
static void unload_module_x(sendip_module* module)
{
    if (module->name != NULL)
    {
        free(module->name);
        module->name = NULL;
    }

#if DEBUG
    printf("packdata address is 0x\tpack address is 0x%x\n",(unsigned int) module->pack);
#endif

    (void)dlclose(module->handle);
}

/*
* This function loads the dynamic libraries which helps defining the protocols, maintain the linked list of 
* loaded modules and insert the copy of the new module to its corresponding packet.
*/
static sendip_module* load_module_x(char* modname, ip_packet* ip_p)
{
    sendip_module *newmod_load;
    sendip_module *newmod = malloc(sizeof(sendip_module));
    sendip_module *cur;
    int (*n_opts)(void);
    sendip_option * (*get_opts)(void);
    char (*get_optchar)(void);

    /*
       Since the protocols are defined in dynamic libraries, each should be loaded only once.
       In XendIp, I use a linked list to keep all loaded modules. Each time a module needs to
       be loaded, this linked list should be checked first, and if the needed module is already
       in the list, just make a copy.
       */
    for(cur=first_loaded;cur!=NULL;cur=cur->next)
    {
        if(!strcmp(modname,cur->name)) 
        {
            memcpy(newmod,cur,sizeof(sendip_module));

            newmod->pack=NULL;
            newmod->prev=ip_p->last;
            newmod->next=NULL;
            
            /** Insert the module to the packet who needs it. **/
            ip_p->last = newmod;
            if(ip_p->last->prev) ip_p->last->prev->next = ip_p->last;
            if(!ip_p->first) ip_p->first=ip_p->last;

            ip_p->num_modules+=1;

            return newmod;
        }
    }

    /** If the module has not been loaded yet, just load it. **/
    newmod_load = malloc(sizeof(sendip_module));
    newmod_load->name = malloc(strlen(modname)+strlen(SENDIP_LIBS)+strlen(".so")+2);
    strcpy(newmod_load->name,modname);
    if(NULL==(newmod_load->handle=dlopen(newmod_load->name,RTLD_NOW))) {
        char *error0=strdup(dlerror());
        sprintf(newmod_load->name,"./%s.so",modname);
        if(NULL==(newmod_load->handle=dlopen(newmod_load->name,RTLD_NOW))) {
            char *error1=strdup(dlerror());
            sprintf(newmod_load->name,"%s/%s.so",SENDIP_LIBS,modname);
            if(NULL==(newmod_load->handle=dlopen(newmod_load->name,RTLD_NOW))) {
                char *error2=strdup(dlerror());
                sprintf(newmod_load->name,"%s/%s",SENDIP_LIBS,modname);
                if(NULL==(newmod_load->handle=dlopen(newmod_load->name,RTLD_NOW))) {
                    char *error3=strdup(dlerror());
                    fprintf(stderr,"Couldn't open module %s, tried:\n",modname);
                    fprintf(stderr,"  %s\n  %s\n  %s\n  %s\n", error0, error1,
                        error2, error3);
                    free(newmod_load);
                    free(error3);
                    return FALSE;
                }
                free(error2);
            }
            free(error1);
        }
        free(error0);
    }
    strcpy(newmod_load->name,modname);
    if(NULL==(newmod_load->initialize=dlsym(newmod_load->handle,"initialize"))) {
        fprintf(stderr,"%s doesn't have an initialize function: %s\n",modname,
            dlerror());
        dlclose(newmod_load->handle);
        free(newmod_load);
        return FALSE;
    }
    if(NULL==(newmod_load->do_opt=dlsym(newmod_load->handle,"do_opt"))) {
        fprintf(stderr,"%s doesn't contain a do_opt function: %s\n",modname,
            dlerror());
        dlclose(newmod_load->handle);
        free(newmod_load);
        return FALSE;
    }
    newmod_load->set_addr=dlsym(newmod_load->handle,"set_addr"); // don't care if fails
    if(NULL==(newmod_load->finalize=dlsym(newmod_load->handle,"finalize"))) {
        fprintf(stderr,"%s\n",dlerror());
        dlclose(newmod_load->handle);
        free(newmod_load);
        return FALSE;
    }
    if(NULL==(n_opts=dlsym(newmod_load->handle,"num_opts"))) {
        fprintf(stderr,"%s\n",dlerror());
        dlclose(newmod_load->handle);
        free(newmod_load);
        return FALSE;
    }
    if(NULL==(get_opts=dlsym(newmod_load->handle,"get_opts"))) {
        fprintf(stderr,"%s\n",dlerror());
        dlclose(newmod_load->handle);
        free(newmod_load);
        return FALSE;
    }
    if(NULL==(get_optchar=dlsym(newmod_load->handle,"get_optchar"))) {
        fprintf(stderr,"%s\n",dlerror());
        dlclose(newmod_load->handle);
        free(newmod_load);
        return FALSE;
    }

    newmod_load->num_opts = n_opts();
    newmod_load->optchar=get_optchar();
    /* TODO: check uniqueness */
    newmod_load->opts = get_opts();

    newmod_load->pack=NULL;
    newmod_load->next=NULL;

    /** Insert the copy of the new module to the corresponding packet before inserting the new module to the loaded module list. **/
    memcpy(newmod,newmod_load,sizeof(sendip_module));

    newmod_load->prev=last_loaded;
    last_loaded = newmod_load;
    if(last_loaded->prev) last_loaded->prev->next = last_loaded;
    if(!first_loaded) first_loaded=last_loaded;

    newmod->prev=ip_p->last;
    ip_p->last = newmod;
    if(ip_p->last->prev) ip_p->last->prev->next = ip_p->last;
    if(!ip_p->first) ip_p->first=ip_p->last;

    ip_p->num_modules+=1;

    return newmod;
}

/*
* This function parses the bgp / rip / ntp related content of the XML configuration document and it also 
* helps to build the package.
*/
static int bgp_rip_ntp_builder(xmlNodePtr node, ip_packet* ipPacket)
{
    xmlChar* curNodeContent;
    xmlNodePtr l7SubNodePtr;
    sendip_module* l7Module;

    l7SubNodePtr = node->xmlChildrenNode;

    l7Module = load_module_x((char*)(node->name), ipPacket);
    l7Module->pack = l7Module->initialize();

    while( l7SubNodePtr != NULL)
    {
        if( l7SubNodePtr->type == XML_COMMENT_NODE )
        {
            l7SubNodePtr = l7SubNodePtr->next;
            continue;
        }
        else if( !xmlStrcmp(l7SubNodePtr->name, BAD_CAST "payload" ))
        {
            curNodeContent = xmlNodeGetContent(l7SubNodePtr);

            ipPacket->datalen = strlen((char*)curNodeContent);
            ipPacket->data = malloc(ipPacket->datalen);
            memcpy(ipPacket->data, curNodeContent, ipPacket->datalen);
            ipPacket->datalen = compact_string(ipPacket->data);

            xmlFree(curNodeContent);
            curNodeContent = NULL;
        }
        else
        {

            curNodeContent = xmlNodeGetContent(l7SubNodePtr);
            if(!l7Module->do_opt((char*)l7SubNodePtr->name, (char*)curNodeContent,l7Module->pack)) 
            {
                fprintf(stderr, "You must define a bad option for \"%s\": \"%s\"\n",(char*)(node->name), (char*)(l7SubNodePtr->name));
            }

            xmlFree(curNodeContent);
            curNodeContent = NULL;
        }

        l7SubNodePtr = l7SubNodePtr->next;
    }

    return 0;
}

/*
* This function parses the tcp / udp / icmp related content of the XML configuration document and it also 
* helps to build the package.
*/
static int tcp_udp_icmp_builder(xmlNodePtr node, ip_packet* ipPacket)
{
    xmlChar* curNodeContent;
    xmlNodePtr l3SubNodePtr;
    sendip_module* l3Module;

    l3SubNodePtr = node->xmlChildrenNode;

    l3Module = load_module_x((char*)(node->name), ipPacket);
    l3Module->pack = l3Module->initialize();

    while( l3SubNodePtr != NULL)
    {
        if( l3SubNodePtr->type == XML_COMMENT_NODE )
        {
            l3SubNodePtr = l3SubNodePtr->next;
            continue;
        }
        else
        {
            if(( !xmlStrcmp(l3SubNodePtr->name, BAD_CAST "bgp" )) || ( !xmlStrcmp(l3SubNodePtr->name, BAD_CAST "rip" )) || ( !xmlStrcmp(l3SubNodePtr->name, BAD_CAST "ntp" )))
            {
                bgp_rip_ntp_builder(l3SubNodePtr, ipPacket);
            }
            else if( !xmlStrcmp(l3SubNodePtr->name, BAD_CAST "payload" ))
            {
                curNodeContent = xmlNodeGetContent(l3SubNodePtr);

                ipPacket->datalen = strlen((char*)curNodeContent);
                ipPacket->data = malloc(ipPacket->datalen);
                memcpy(ipPacket->data, curNodeContent, ipPacket->datalen);
                ipPacket->datalen = compact_string(ipPacket->data);

                xmlFree(curNodeContent);
                curNodeContent = NULL;
            }
            else
            {
                curNodeContent = xmlNodeGetContent(l3SubNodePtr);
                if(!l3Module->do_opt((char*)l3SubNodePtr->name, (char*)curNodeContent,l3Module->pack)) 
                {
                    fprintf(stderr, "You must define a bad option for \"%s\": \"%s\"\n",(char*)(node->name), (char*)(l3SubNodePtr->name));
                }

                xmlFree(curNodeContent);
                curNodeContent = NULL;
            }
        }

        l3SubNodePtr = l3SubNodePtr->next;
    }

    return 0;
}

/*
* This function parses the ipv4 / ipv6 related content of the XML configuration document and it also 
* helps to build the package.
*/
static int ip_builder (xmlNodePtr node)
{
    ip_packet* ipPacket;
    xmlChar* curNodeContent;
    xmlNodePtr ipSubNodePtr;
    sendip_module* ipModule;
    
    /** When an ip node is met in the parsing process of the XML document, an new 'packet' is supposed to be added
     to the package linked list which represents the 'sequence' that is sent repeatedly in the fuzzing test.**/
    ipPacket = malloc (sizeof(ip_packet));

    if(init_ip_packet(ipPacket))
    {
        fprintf(stderr,"Something must be wrong when doing \"init_ip_packet\"\n");
        return -1;
    }
    ipSubNodePtr = node->xmlChildrenNode;

    ipPacket->prev = last_packet;
    last_packet = ipPacket;
    if(last_packet->prev) last_packet->prev->next = last_packet;
    if(!first_packet) first_packet=last_packet;

    ipModule = load_module_x((char*)(node->name), ipPacket);
    ipModule->pack = ipModule->initialize();

    while( ipSubNodePtr != NULL)
    {
        if( ipSubNodePtr->type == XML_COMMENT_NODE )
        {
            ipSubNodePtr = ipSubNodePtr->next;
            continue;
        }
        else
        {

            if(( !xmlStrcmp(ipSubNodePtr->name, BAD_CAST "icmp" )) || ( !xmlStrcmp(ipSubNodePtr->name, BAD_CAST "tcp" )) || ( !xmlStrcmp(ipSubNodePtr->name, BAD_CAST "udp" )))
            {
                tcp_udp_icmp_builder(ipSubNodePtr, ipPacket);
            }
            else if( !xmlStrcmp(ipSubNodePtr->name, BAD_CAST "f" ))
            {
                //TODO
                fprintf(stderr,"Sorry, the file payload function has not been implemented yet!\n");
            }
            else if( !xmlStrcmp(ipSubNodePtr->name, BAD_CAST "payload" ))
            {
                curNodeContent = xmlNodeGetContent(ipSubNodePtr);

                ipPacket->datalen = strlen((char*)curNodeContent);
                ipPacket->data = malloc(ipPacket->datalen);
                memcpy(ipPacket->data, curNodeContent, ipPacket->datalen);
                ipPacket->datalen = compact_string(ipPacket->data);

                xmlFree(curNodeContent);
                curNodeContent = NULL;
            }
            else if( !xmlStrcmp(ipSubNodePtr->name, BAD_CAST "ipv6" ))
            {
                //TODO
                fprintf(stderr,"Sorry, the fuzzing function of ipv6 has not been implemented yet!\n");
            }
            else
            {
                curNodeContent = xmlNodeGetContent(ipSubNodePtr);
                if(!ipModule->do_opt((char*)ipSubNodePtr->name, (char*)curNodeContent,ipModule->pack)) 
                {
                    fprintf(stderr, "You must define a bad option for \"%s\": \"%s\"\n",(char*)(node->name), (char*)(ipSubNodePtr->name));
                }

                xmlFree(curNodeContent);
                curNodeContent = NULL;
            }
        }

        ipSubNodePtr = ipSubNodePtr->next;
    }

    return 0;
}

/*
* This function scans the linked list that represents the whole sequence, dig into every ip packet and
* sew all levels of headers and payload within it together to make it ready to send.
*/
static void build_the_packet()
{
    ip_packet* curPacket;
    sendip_module* curModule;

    int i;

#if DEBUG
    printf("--------------------------------------------------------------------------------------------->build_the_packet:\n");
#endif

    /** Scan the list of ip packets **/
    for(curPacket = first_packet; curPacket!=NULL; curPacket = curPacket->next)
    {
        /** Calculate the length of the package and alloc its space. **/
        if(curPacket->packet.data == NULL)
        {
            for(curModule=curPacket->first;curModule!=NULL;curModule=curModule->next) 
            {
                curPacket->packet.alloc_len+=curModule->pack->alloc_len;
#if DEBUG
                printf("curModule->pack->alloc_len = %d\n",curModule->pack->alloc_len);
#endif
            }
#if DEBUG
            printf("curPacket->packet.alloc_len = %d\n",curPacket->packet.alloc_len);
#endif

            if(curPacket->data != NULL) 
                curPacket->packet.alloc_len+=curPacket->datalen;

            curPacket->packet.data = malloc(curPacket->packet.alloc_len);
        }

        /** Sew the payload, 4th and 7th levels (if any) of packets within the current ip package together. **/
        for(i=0, curModule=curPacket->first;curModule!=NULL;curModule=curModule->next) 
        {
            memcpy((char *)curPacket->packet.data+i,curModule->pack->data,curModule->pack->alloc_len);

            i+=curModule->pack->alloc_len;
        }

        if(curPacket->data != NULL) 
            memcpy((char *)((curPacket->packet.data)+i),curPacket->data,curPacket->datalen);

        /* //TODO
        if(datafile != -1) {
        munmap(data,datalen);
        close(datafile);
        datafile=-1;
        }

        if(randomflag) free(data);
         */

        /** Adjust some bits necessary from inside out **/
#if DEBUG
        printf("curPacket->num_modules = %d\n",curPacket->num_modules);
#endif

        if(curPacket->hdrs == NULL)
        {
            curPacket->hdrs = malloc((curPacket->num_modules)*(sizeof(char)));

            for(i=0,curModule=curPacket->first;curModule!=NULL;curModule=curModule->next,i++) 
                curPacket->hdrs[i]=curModule->optchar;
        }

        if(curPacket->headers == NULL)
        {
            curPacket->headers = malloc((curPacket->num_modules)*(sizeof(sendip_data*)));

            for(i=0,curModule=curPacket->first;curModule!=NULL;curModule=curModule->next,i++) 
                curPacket->headers[i]=curModule->pack;
        }

        curPacket->d.alloc_len = curPacket->datalen;
        curPacket->d.data = (char *)(curPacket->packet.data)+curPacket->packet.alloc_len-curPacket->datalen;

        for(i=curPacket->num_modules-1,curModule=curPacket->last;curModule!=NULL;curModule=curModule->prev,i--) 
        {
            /* Remove this header from enclosing list */
            curPacket->hdrs[i]='\0';
            curPacket->headers[i] = NULL;

#if DEBUG
            printf("headers = %d\td = %d\tpack = %d\n",(int)(curPacket->headers), (int)(&(curPacket->d)), (int)(curModule->pack));
#endif
            curModule->finalize(curPacket->hdrs, curPacket->headers, &(curPacket->d), curModule->pack);
#if DEBUG
            printf("After finalize!\n");
#endif

            /* Get everything ready for the next call */
            curPacket->d.data=(char *)(curPacket->d.data)-curModule->pack->alloc_len;
            curPacket->d.alloc_len+=curModule->pack->alloc_len;
        }
    }
}

/*
* This function set the ip address and port number (for both source and destination) of every ip package in the sequence
* and send the sequence.
*/
static void stamp_and_send(char* host_name, unsigned int ip_s, unsigned int ip_d, unsigned int port_s, unsigned int port_d)
{
    ip_packet* curPacket;
    sendip_module* curModule;

    int af_type;
    int i;

    char* ipS = NULL;
    char* ipD = NULL;
    char* portS = NULL;
    char* portD = NULL;

    char* ipS_1 = NULL;
    char* ipD_1 = NULL;
    char* portS_1 = NULL;
    char* portD_1 = NULL;

#if DEBUG
    printf("--------------------------------------------------------------------------------------------->stamp_and_send:\n");
#endif

    /** Transform the ip address and port number from string format to integer format. **/
    ipS = malloc(16);
    memset(ipS,'\0',16);

    portS = malloc(8);
    memset(portS,'\0',8);

    ipD = malloc(16);
    memset(ipD,'\0',16);

    portD = malloc(8);
    memset(portD,'\0',8);

    ipS_1 = ip_ntoc(ip_s, ipS);
    ipD_1 = ip_ntoc(ip_d, ipD);
    portS_1 = port_ntoc(port_s, portS);
    portD_1 = port_ntoc(port_d, portD);

#if DEBUG
    printf("portS = %s\tportD = %s\tlength of ipS_1 is %d\n",portS,portD,strlen(portS_1));
#endif

    /** Build and Send all the packets **/
    for(curPacket = first_packet; curPacket!=NULL; curPacket = curPacket->next)
    {
        /** Set IP address and Port Number **/
        for(curModule=curPacket->first;curModule!=NULL;curModule=curModule->next) 
        {
#if DEBUG
            printf("curModule->name = %s\n",curModule->name);
#endif
            if(!strcmp(curModule->name, "ipv4"))
            {
                curModule->do_opt((&"is"), ipS_1, curModule->pack); 
                curModule->do_opt((&"id"), ipD_1, curModule->pack); 
#if DEBUG
                printf("ipv4 check!\tcurModule->pack = %dsaddr = %x\n",(unsigned int)(curModule->pack),((ip_header *)curModule->pack->data)->saddr);
#endif
            }
            else if(!strcmp(curModule->name, "ipv6"))
            {
#if DEBUG
                printf("ipv6 check!\n");
#endif
                continue;
                //TODO
            }
            else if(!strcmp(curModule->name, "tcp"))
            {
#if DEBUG
                printf("tcp check!\n");
#endif
                curModule->do_opt((&"ts"), portS_1, curModule->pack); 
                curModule->do_opt((&"td"), portD_1, curModule->pack); 
            }
            else if(!strcmp(curModule->name, "udp"))
            {
#if DEBUG
                printf("udp check!\n");
#endif
                curModule->do_opt((&"us"), portS_1, curModule->pack); 
                curModule->do_opt((&"ud"), portD_1, curModule->pack); 
            }
            else
                continue;
        }

        /** Sew 4th and 7th levels (if any) of packets within the current ip package together. **/
        for(i=0, curModule=curPacket->first;curModule!=NULL;curModule=curModule->next) 
        {
            memcpy((char *)curPacket->packet.data+i,curModule->pack->data,curModule->pack->alloc_len);
            i+=curModule->pack->alloc_len;
        }
        /*
        //TODO Add any data
        if(data != NULL) memcpy((char *)packet.data+i,data,datalen);
        if(datafile != -1) {
        munmap(data,datalen);
        close(datafile);
        datafile=-1;
        }

        if(randomflag) free(data);
         */

        /** Adjust some bits necessary from inside out **/
#if DEBUG
        printf("curPacket->num_modules = %d\n",curPacket->num_modules);
#endif

        curPacket->d.alloc_len = curPacket->datalen;
        curPacket->d.data = (char *)(curPacket->packet.data)+curPacket->packet.alloc_len-curPacket->datalen;

        for(i=0,curModule=curPacket->first;curModule!=NULL;curModule=curModule->next,i++) 
        {
            curPacket->hdrs[i]=curModule->optchar;
#if DEBUG
            printf("curModule->optchar = %c\n",curModule->optchar);
#endif
            curPacket->headers[i]=curModule->pack;
        }

        for(i=curPacket->num_modules-1,curModule=curPacket->last;curModule!=NULL;curModule=curModule->prev,i--) 
        {
            /* Remove this header from enclosing list */
            curPacket->hdrs[i]='\0';
            curPacket->headers[i] = NULL;

#if DEBUG
            printf("headers = %d\td = %d\tpack = %d\n",(int)(curPacket->headers), (int)(&(curPacket->d)), (int)(curModule->pack));
#endif
            curModule->finalize(curPacket->hdrs, curPacket->headers, &(curPacket->d), curModule->pack);
#if DEBUG
            printf("After finalize!\n");
#endif

            /* Get everything ready for the next call */
            curPacket->d.data=(char *)(curPacket->d.data)-curModule->pack->alloc_len;
            curPacket->d.alloc_len+=curModule->pack->alloc_len;
        }

        /* And send the packet */

        if(curPacket->first==NULL)
        {
            if(curPacket->data == NULL)
            {
                fprintf(stderr,"Nothing specified to send!\n");
                //print_usage();
                free(curPacket->packet.data);
                unload_module_x(FALSE);
                return 1;
            }
            else
            {
                af_type = AF_INET;
            }
        }
        else if(curPacket->first->optchar=='i')
            af_type = AF_INET;
        else if(curPacket->first->optchar=='6')
            af_type = AF_INET6;
        else 
        {
            fprintf(stderr,"Either IPv4 or IPv6 must be the outermost packet\n");
            unload_module_x(FALSE);
            free(curPacket->packet.data);
            return 1;
        }

#if DEBUG
        printf("##############################################################################################\n");
#endif
        i = sendpacket(&(curPacket->packet),host_name,af_type,0);
#if DEBUG
        printf("i = %d\taf_type = %d\tpack = %d\thostname = %s\n",i,af_type,((unsigned int)(&(curPacket->packet))),host_name);
#endif
    }

    /** Clean up **/
    free(ipS);
    free(ipD);
    free(portS);
    free(portD);
}

/*
* This function parses the XML configuration document and abstracts all the information it contains, including:
* how many machines / cards are involved, the duty of each machine / card, all kinds of fuzzing information,
* the details of every sequence and every ip packet (based on whatever sendip supports), everything. It also
* ignores the XML comments automaticlly.
*/
static int xml_parser(xmlDocPtr doc, fuzzing_info* fuzz_info, ip_port* srcIpp, ip_port* dstIpp, xmlChar** hostname)
{
    xmlNodePtr root, machines, config, sequence;
    xmlAttrPtr curAttrPtr;
    xmlChar* curAttrPtrContent;

    if ( doc == NULL )
    {  
        fprintf(stderr,"Document not parsed successfully. \n");    
        return -1;
    }

    /** Find and Parse the Root Element that ought to be "XendIP"  **/    

    root = xmlDocGetRootElement(doc);

    if ( root == NULL )
    {
        fprintf(stderr,"empty document\n");
        xmlFreeDoc(doc);
        return -1;
    }

#if DEBUG
    fprintf(stderr,"root node is '%s'.\n",root->name);
#endif

    if (xmlStrcmp(root->name, BAD_CAST "XendIp"))
    {
        fprintf(stderr,"document of the wrong type, root node != XendIp");
        xmlFreeDoc(doc);
        return -1;
    } 

    /** Parse the "Machines" Elements which is right inside the Root element **/   

    xmlNodePtr curRootSubNodePtr = root->xmlChildrenNode;

    while( (curRootSubNodePtr != NULL) ) //TODO: in this version we suppose XendIp shall be run on a single machine so the XML doc is to contain only one "Group" node.
    {
        if (curRootSubNodePtr->type == XML_COMMENT_NODE)
        {
            curRootSubNodePtr = curRootSubNodePtr->next;
            continue;
        }
        else
        {
            machines = curRootSubNodePtr; 
        }

        curRootSubNodePtr = curRootSubNodePtr->next;
    }

    if( machines == NULL )
    {
        fprintf(stderr,"There is no \"Machines\" element in your XML document, and this is not allowed!!!\n");
        return -1;
    }
    else
    {
        curAttrPtr = machines->properties;

        while( curAttrPtr != NULL )
        {
            if (!xmlStrcmp(curAttrPtr->name, BAD_CAST "id"))
            {
                curAttrPtrContent = xmlGetProp(machines,curAttrPtr->name);
#if DEBUG
                fprintf(stderr,"Parsing Machines %s,",curAttrPtrContent);
#endif
                //TODO groupNumber = atoi((const char*)curAttrPtrContent);

                xmlFree(curAttrPtrContent);
                curAttrPtrContent = NULL;
            }
            else if (!xmlStrcmp(curAttrPtr->name, BAD_CAST "machines_cnt"))
            {
                curAttrPtrContent = xmlGetProp(machines,curAttrPtr->name);
#if DEBUG
                fprintf(stderr," in %s machines.\n",curAttrPtrContent);
#endif
                //TODO machineCount = atoi((const char*)curAttrPtrContent);

                xmlFree(curAttrPtrContent);
                curAttrPtrContent = NULL;
            }
            else
            {
                curAttrPtrContent = xmlGetProp(machines,curAttrPtr->name);
#if DEBUG
                fprintf(stderr,"Unknown Attribute in Machines: %s.\n",curAttrPtrContent);
#endif
                //TODO

                xmlFree(curAttrPtrContent);
                curAttrPtrContent = NULL;
            }
            curAttrPtr = curAttrPtr->next;
        }
    }

    /** Locate the "Config" and "Sequence" elements which are right inside the "Machines" element **/

    xmlNodePtr curMachinesSubNodePtr = machines->xmlChildrenNode;

    while( (curMachinesSubNodePtr != NULL) ) 
    {
        if (curMachinesSubNodePtr->type == XML_COMMENT_NODE)
        {
            curMachinesSubNodePtr = curMachinesSubNodePtr->next;
            continue;
        }
        else if (!xmlStrcmp(curMachinesSubNodePtr->name, BAD_CAST "Config")) 
            config = curMachinesSubNodePtr; 
        else if (!xmlStrcmp(curMachinesSubNodePtr->name, BAD_CAST "Sequence")) 
            sequence = curMachinesSubNodePtr; 

        curMachinesSubNodePtr = curMachinesSubNodePtr->next;
    }


    /** Parse the content of "Config" element **/

    if( config == NULL )
    {
        fprintf(stderr,"Since there is no \"Config\" element in your XML document, XendIp will sent your sequence only once!\n");
    }
    else
    {
        xmlNodePtr curConfigSubNodePtr = config->xmlChildrenNode;
        curAttrPtr = config->properties;

        while( curAttrPtr != NULL )
        {
            if( !xmlStrcmp(curAttrPtr->name, BAD_CAST "reverse") )
            {
                curAttrPtrContent = xmlGetProp(config,curAttrPtr->name);
                if( !xmlStrcmp(curAttrPtrContent, BAD_CAST "true") )
                    fuzz_info->reverse = TRUE;
                else
                    fuzz_info->reverse = FALSE;

                xmlFree(curAttrPtrContent);
                curAttrPtrContent = NULL;
            }
            else if( !xmlStrcmp(curAttrPtr->name, BAD_CAST "delay") )
            {
                curAttrPtrContent = xmlGetProp(config,curAttrPtr->name);
                fuzz_info->delay = atoi((const char*)curAttrPtrContent);

                xmlFree(curAttrPtrContent);
                curAttrPtrContent = NULL;
            }
            else
                fprintf(stderr,"Undefined Attribute in \"Config\": %s.\n",(const char*)(curAttrPtr->name));
            curAttrPtr = curAttrPtr->next;
        }

        while( curConfigSubNodePtr != NULL )
        {
            if( curConfigSubNodePtr->type == XML_COMMENT_NODE )
            {
                curConfigSubNodePtr = curConfigSubNodePtr->next;
                continue;
            }
            else
            {
                if(!xmlStrcmp(curConfigSubNodePtr->name, BAD_CAST"src_ip"))
                {   
                    curAttrPtr = curConfigSubNodePtr->properties;

                    while( curAttrPtr != NULL )
                    {
                        if( !xmlStrcmp(curAttrPtr->name, BAD_CAST "fuzz") )
                        {
                            curAttrPtrContent = xmlGetProp(curConfigSubNodePtr,curAttrPtr->name);

                            if(!xmlStrcmp(curAttrPtrContent, BAD_CAST"seq"))
                                fuzz_info->src_ip_fuzz = TRUE;
                            else if(!xmlStrcmp(curAttrPtrContent, BAD_CAST"solid"))
                                fuzz_info->src_ip_fuzz = FALSE;
                            else
                                fprintf(stderr,"Sorry the Mutation Method \"%s\" has not been implemented.\n",(const char*)(curAttrPtrContent));

                            xmlFree(curAttrPtrContent);
                            curAttrPtrContent = NULL;
                        }
                        else
                            fprintf(stderr,"Undefined Attribute in \"src_ip\": %s.\n",(const char*)(curAttrPtr->name));

                        curAttrPtr = curAttrPtr->next;
                    }

                    xmlNodePtr curSrcIpSubNodePtr = curConfigSubNodePtr->xmlChildrenNode;

                    while( curSrcIpSubNodePtr != NULL )
                    {
                        if( curSrcIpSubNodePtr->type == XML_COMMENT_NODE )
                        {
                            curSrcIpSubNodePtr = curSrcIpSubNodePtr->next;
                            continue;
                        }
                        else
                        {
                            if( fuzz_info->src_ip_fuzz )
                            {
                                if(!xmlStrcmp(curSrcIpSubNodePtr->name, BAD_CAST"start"))
                                {
                                    srcIpp->ip_c_start = xmlNodeGetContent(curSrcIpSubNodePtr);
                                    srcIpp->ip_n_start = ip_cton((char*)(srcIpp->ip_c_start));
                                }
                                else if(!xmlStrcmp(curSrcIpSubNodePtr->name, BAD_CAST"end"))
                                {
                                    srcIpp->ip_c_end = xmlNodeGetContent(curSrcIpSubNodePtr);
                                    srcIpp->ip_n_end = ip_cton((char*)(srcIpp->ip_c_end));
                                }
                                else
                                    fprintf(stderr,"Both the start and end ip address should be defined when the content of  \"fuzz\" attribute is not \"solid\".\n");
                            }
                            else
                            {
                                if( !xmlStrcmp(curSrcIpSubNodePtr->name, BAD_CAST "ip_addr") )
                                {
                                    srcIpp->ip_c_solid = xmlNodeGetContent(curSrcIpSubNodePtr);
                                    srcIpp->ip_n_solid = ip_cton((char*)(srcIpp->ip_c_solid));
                                }
                                else
                                    fprintf(stderr,"Since it is not in fuzzing mode, please define a single ip address in \"ip_addr\" sub-element.\n");
                            }
                        }

                        curSrcIpSubNodePtr = curSrcIpSubNodePtr->next;
                    }
                }
                else if(!xmlStrcmp(curConfigSubNodePtr->name, BAD_CAST"dst_ip"))
                {   
                    curAttrPtr = curConfigSubNodePtr->properties;

                    while( curAttrPtr != NULL )
                    {
                        if( !xmlStrcmp(curAttrPtr->name, BAD_CAST "fuzz") )
                        {
                            curAttrPtrContent = xmlGetProp(curConfigSubNodePtr,curAttrPtr->name);

                            if(!xmlStrcmp(curAttrPtrContent, BAD_CAST"seq"))
                                fuzz_info->dst_ip_fuzz = TRUE;
                            else if(!xmlStrcmp(curAttrPtrContent, BAD_CAST"solid"))
                                fuzz_info->dst_ip_fuzz = FALSE;
                            else
                                fprintf(stderr,"Sorry the Mutation Method \"%s\" has not been implemented.\n",(const char*)(curAttrPtrContent));

                            xmlFree(curAttrPtrContent);
                            curAttrPtrContent = NULL;
                        }
                        else
                            fprintf(stderr,"Undefined Attribute in \"dst_ip\": %s.\n",(const char*)(curAttrPtr->name));

                        curAttrPtr = curAttrPtr->next;
                    }

                    xmlNodePtr curDstIpSubNodePtr = curConfigSubNodePtr->xmlChildrenNode;

                    while( curDstIpSubNodePtr != NULL)
                    {
                        if( curDstIpSubNodePtr->type == XML_COMMENT_NODE )
                        {
                            curDstIpSubNodePtr = curDstIpSubNodePtr->next;
                            continue;
                        }
                        else
                        {
                            if( fuzz_info->dst_ip_fuzz )
                            {
                                if(!xmlStrcmp(curDstIpSubNodePtr->name, BAD_CAST"start"))
                                {
                                    dstIpp->ip_c_start = xmlNodeGetContent(curDstIpSubNodePtr);
                                    dstIpp->ip_n_start = ip_cton((char*)(dstIpp->ip_c_start));
                                }
                                else if(!xmlStrcmp(curDstIpSubNodePtr->name, BAD_CAST"end"))
                                {
                                    dstIpp->ip_c_end = xmlNodeGetContent(curDstIpSubNodePtr);
                                    dstIpp->ip_n_end = ip_cton((char*)(dstIpp->ip_c_end));
                                }
                                else
                                {
                                    fprintf(stderr,"Both the start and end ip address should be defined when the content of  \"fuzz\" attribute is not \"solid\".\n");
                                }
                            }
                            else
                            {
                                if( !xmlStrcmp(curDstIpSubNodePtr->name, BAD_CAST "ip_addr") )
                                {
                                    dstIpp->ip_c_solid = xmlNodeGetContent(curDstIpSubNodePtr);
                                    dstIpp->ip_n_solid = ip_cton((char*)(dstIpp->ip_c_solid));
                                }
                                else
                                    fprintf(stderr,"Since it is not in fuzzing mode, please define a single ip address in \"ip_addr\" sub-element.\n");
                            }
                        }

                        curDstIpSubNodePtr = curDstIpSubNodePtr->next;
                    }
                }
                else if(!xmlStrcmp(curConfigSubNodePtr->name, BAD_CAST"src_port"))
                {   
                    curAttrPtr = curConfigSubNodePtr->properties;

                    while( curAttrPtr != NULL )
                    {
                        if( !xmlStrcmp(curAttrPtr->name, BAD_CAST "fuzz") )
                        {
                            curAttrPtrContent = xmlGetProp(curConfigSubNodePtr,curAttrPtr->name);

                            if(!xmlStrcmp(curAttrPtrContent, BAD_CAST"seq"))
                                fuzz_info->src_pt_fuzz = TRUE;
                            else if(!xmlStrcmp(curAttrPtrContent, BAD_CAST"solid"))
                                fuzz_info->src_pt_fuzz = FALSE;
                            else
                                fprintf(stderr,"Sorry the Mutation Method \"%s\" has not been implemented.\n",(const char*)(curAttrPtrContent));

                            xmlFree(curAttrPtrContent);
                            curAttrPtrContent = NULL;
                        }
                        else
                            fprintf(stderr,"Undefined Attribute in \"src_port\": %s.\n",(const char*)(curAttrPtr->name));

                        curAttrPtr = curAttrPtr->next;
                    }

                    xmlNodePtr curSrcPortSubNodePtr = curConfigSubNodePtr->xmlChildrenNode;

                    while( curSrcPortSubNodePtr != NULL)
                    {
                        if( curSrcPortSubNodePtr->type == XML_COMMENT_NODE )
                        {
                            curSrcPortSubNodePtr = curSrcPortSubNodePtr->next;
                            continue;
                        }
                        else
                        {
                            if( fuzz_info->src_pt_fuzz )
                            {
                                if(!xmlStrcmp(curSrcPortSubNodePtr->name, BAD_CAST"start"))
                                {
                                    srcIpp->port_c_start = xmlNodeGetContent(curSrcPortSubNodePtr);
                                    srcIpp->port_n_start = atoi((const char*)(srcIpp->port_c_start));
                                }
                                else if(!xmlStrcmp(curSrcPortSubNodePtr->name, BAD_CAST"end"))
                                {
                                    srcIpp->port_c_end = xmlNodeGetContent(curSrcPortSubNodePtr);
                                    srcIpp->port_n_end = atoi((const char*)(srcIpp->port_c_end));
                                }
                                else
                                    fprintf(stderr,"Both the start and end ip address should be defined when the content of  \"fuzz\" attribute is not \"solid\".\n");
                            }
                            else
                            {
                                if( !xmlStrcmp(curSrcPortSubNodePtr->name, BAD_CAST "port") )
                                {
                                    srcIpp->port_c_solid = xmlNodeGetContent(curSrcPortSubNodePtr);
                                    srcIpp->port_n_solid = atoi((const char*)(srcIpp->port_c_solid));
                                }
                                else
                                    fprintf(stderr,"Since it is not in fuzzing mode, please define a single ip address in \"port\" sub-element.\n");
                            }
                        }

                        curSrcPortSubNodePtr = curSrcPortSubNodePtr->next;
                    }
                }
                else if(!xmlStrcmp(curConfigSubNodePtr->name, BAD_CAST"dst_port"))
                {   
                    curAttrPtr = curConfigSubNodePtr->properties;

                    while( curAttrPtr != NULL )
                    {
                        if( !xmlStrcmp(curAttrPtr->name, BAD_CAST "fuzz") )
                        {
                            curAttrPtrContent = xmlGetProp(curConfigSubNodePtr,curAttrPtr->name);

                            if(!xmlStrcmp(curAttrPtrContent, BAD_CAST"seq"))
                                fuzz_info->dst_pt_fuzz = TRUE;
                            else if(!xmlStrcmp(curAttrPtrContent, BAD_CAST"solid"))
                                fuzz_info->dst_pt_fuzz = FALSE;
                            else
                                fprintf(stderr,"Sorry the Mutation Method \"%s\" has not been implemented.\n",(const char*)(curAttrPtrContent));

                            xmlFree(curAttrPtrContent);
                            curAttrPtrContent = NULL;
                        }
                        else
                            fprintf(stderr,"Undefined Attribute in \"dst_port\": %s.\n",(const char*)(curAttrPtr->name));

                        curAttrPtr = curAttrPtr->next;
                    }

                    xmlNodePtr curDstPortSubNodePtr = curConfigSubNodePtr->xmlChildrenNode;

                    while( curDstPortSubNodePtr != NULL)
                    {
                        if( curDstPortSubNodePtr->type == XML_COMMENT_NODE )
                        {
                            curDstPortSubNodePtr = curDstPortSubNodePtr->next;
                            continue;
                        }
                        else
                        {
                            if( fuzz_info->dst_pt_fuzz )
                            {
                                if(!xmlStrcmp(curDstPortSubNodePtr->name, BAD_CAST"start"))
                                {
                                    dstIpp->port_c_start = xmlNodeGetContent(curDstPortSubNodePtr);
                                    dstIpp->port_n_start = atoi((const char*)(dstIpp->port_c_start));
                                }
                                else if(!xmlStrcmp(curDstPortSubNodePtr->name, BAD_CAST"end"))
                                {
                                    dstIpp->port_c_end = xmlNodeGetContent(curDstPortSubNodePtr);
                                    dstIpp->port_n_end = atoi((const char*)(dstIpp->port_c_end));
                                }
                                else
                                    fprintf(stderr,"Both the start and end ip address should be defined when the content of  \"fuzz\" attribute is not \"solid\".\n");
                            }
                            else
                            {
                                if( !xmlStrcmp(curDstPortSubNodePtr->name, BAD_CAST "port") )
                                {
                                    dstIpp->port_c_solid = xmlNodeGetContent(curDstPortSubNodePtr);
                                    dstIpp->port_n_solid = atoi((const char*)(dstIpp->port_c_solid));
                                }
                                else
                                    fprintf(stderr,"Since it is not in fuzzing mode, please define a single ip address in \"port\" sub-element.\n");
                            }
                        }

                        curDstPortSubNodePtr = curDstPortSubNodePtr->next;
                    }
                }
                else if(!xmlStrcmp(curConfigSubNodePtr->name, BAD_CAST"hostname"))
                {
                    *hostname = xmlNodeGetContent(curConfigSubNodePtr);
                }
                else
                    fprintf(stderr,"Undefined sub-element of \"Config\": %s.\n",(const char*)(curConfigSubNodePtr->name));

            }

            curConfigSubNodePtr = curConfigSubNodePtr->next;
        }
    }
#if DEBUG_DUMP
    fprintf(stderr,"<--------------------     Dump overall fuzzing info     -------------------->\n");
    dump_fuzz_config(fuzz_info);
    fprintf(stderr,"<--------------------    Dump source ip fuzzing info    -------------------->\n");
    dump_ipp_config(srcIpp);
    fprintf(stderr,"<--------------------  Dump destnation ip fuzzing info  -------------------->\n");
    dump_ipp_config(dstIpp);
    fprintf(stderr, "hostname = %s\n",*hostname);
#endif

    /** Parse the content of "Sequence" element **/
    if( sequence == NULL )
    {
        fprintf(stderr,"Since there is no \"Sequence\" element in your XML document, WHAT DO YOU WANT XendIp TO DO ???\n");
        return -1;
    }
    else
    {
        xmlNodePtr curSequenceSubNodePtr = sequence->xmlChildrenNode;

        while(curSequenceSubNodePtr != NULL)
        {
            if( curSequenceSubNodePtr->type == XML_COMMENT_NODE )
            {
                curSequenceSubNodePtr = curSequenceSubNodePtr->next;
                continue;
            }
            else
            {

                if(( !xmlStrcmp(curSequenceSubNodePtr->name, BAD_CAST "ipv4" )) || ( !xmlStrcmp(curSequenceSubNodePtr->name, BAD_CAST "ipv6" )))
                {
                    ip_builder(curSequenceSubNodePtr);
                }
                else
                    fprintf(stderr,"Either an ipv4 or ipv6 should be the outermost packet! \n");
            }
            curSequenceSubNodePtr = curSequenceSubNodePtr->next; 
        }
    }
}

/*
* The Fuzzing extension of 'sendip' based on XML configuration and parsing.
* This extension implements such functions: based on all the function that
* 'sendip' supports, it is not only able to send a sequence of different ip
* packets, but also able to send the sequence repeatedly in a fuzzing way.
*/
int Xml_Fuzzer ( char* fileName)
{
    /** Initialization **/

    xmlDocPtr doc;

    ip_packet* curPacket;
    sendip_module* curModule;

    ip_port *srcIpp, *dstIpp;
    fuzzing_info* fuzz_info;


//    char* dataPayload; //TODO
    xmlChar* hostname = NULL;  

    int i;

    unsigned int curIp1n = 0;
    unsigned int curIp2n = 0;
    unsigned int curPort1n = 0;
    unsigned int curPort2n = 0;

    fuzz_info = malloc(sizeof(fuzzing_info));
    fuzz_info_init(fuzz_info);

    srcIpp = malloc(sizeof(struct _ip_p));
    dstIpp = malloc(sizeof(struct _ip_p));
    memset(srcIpp,'\0',sizeof(struct _ip_p));
    memset(dstIpp,'\0',sizeof(struct _ip_p));

    /** Find and Read the XML file **/    

    doc = xmlReadFile(fileName,"UTF-8",XML_PARSE_NOBLANKS);

    xml_parser(doc, fuzz_info, srcIpp, dstIpp, &hostname);

#if DEBUG
    printf("$$$$$$$$$$$$$$$$$$$$host name = %s\t%s \n",hostname,dstIpp->ip_c_solid);
#endif

    build_the_packet();

    /** Do the Fuzzing **/
    if(!(fuzz_info->reverse))
    {
        if(fuzz_info->dst_ip_fuzz)
        {
            for(curIp2n = dstIpp->ip_n_start; curIp2n <= dstIpp->ip_n_end; curIp2n++)
            {
                if(fuzz_info->dst_pt_fuzz)
                {
                    for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                    {
                        if(fuzz_info->src_ip_fuzz)
                        {
                            for(curIp1n = srcIpp->ip_n_start; curIp1n <= srcIpp->ip_n_end; curIp1n++)
                            {
                                if(fuzz_info->src_pt_fuzz)
                                {
                                    for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                                    {
#if DEBUG
                                printf("We go here1\n");
#endif
                                        stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                        usleep(fuzz_info->delay);
                                    }
                                }
                                else
                                {
#if DEBUG
                                printf("We go here2\n");
#endif
                                    curPort1n = srcIpp->port_n_solid;
                                    stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                    usleep(fuzz_info->delay);
                                }
                            }
                        }
                        else
                        {
                            curIp1n = srcIpp->ip_n_solid;
                            if(fuzz_info->src_pt_fuzz)
                            {
                                for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                                {
#if DEBUG
                                printf("We go here3\n");
#endif
                                    stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                    usleep(fuzz_info->delay);
                                }
                            }
                            else
                            {
#if DEBUG
                                printf("We go here4\n");
#endif
                                curPort1n = srcIpp->port_n_solid;
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                    }
                }
                else
                {
                    curPort2n = dstIpp->port_n_solid;
                    if(fuzz_info->src_ip_fuzz)
                    {
                        for(curIp1n = srcIpp->ip_n_start; curIp1n <= srcIpp->ip_n_end; curIp1n++)
                        {
                            if(fuzz_info->src_pt_fuzz)
                            {
                                for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                                {
#if DEBUG
                                printf("We go here5\n");
#endif
                                    stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                    usleep(fuzz_info->delay);
                                }
                            }
                            else
                            {
#if DEBUG
                                printf("We go here6\n");
#endif
                                curPort1n = srcIpp->port_n_solid;
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                    }
                    else
                    {
                        curIp1n = srcIpp->ip_n_solid;
                        if(fuzz_info->src_pt_fuzz)
                        {
                            for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                            {
#if DEBUG
                                printf("We go here7\n");
#endif
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                        else
                        {
#if DEBUG
                                printf("We go here8\n");
#endif
                            curPort1n = srcIpp->port_n_solid;
                            stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                            usleep(fuzz_info->delay);
                        }
                    }
                }
            }
        }
        else
        {
            curIp2n = dstIpp->ip_n_solid;
            if(fuzz_info->dst_pt_fuzz)
            {
                for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                {
                    if(fuzz_info->src_ip_fuzz)
                    {
                        for(curIp1n = srcIpp->ip_n_start; curIp1n <= srcIpp->ip_n_end; curIp1n++)
                        {
                            if(fuzz_info->src_pt_fuzz)
                            {
                                for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                                {
#if DEBUG
                                printf("We go here9\n");
#endif
                                    stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                    usleep(fuzz_info->delay);
                                }
                            }
                            else
                            {
#if DEBUG
                                printf("We go here10\n");
#endif
                                curPort1n = srcIpp->port_n_solid;
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                    }
                    else
                    {
                        curIp1n = srcIpp->ip_n_solid;
                        if(fuzz_info->src_pt_fuzz)
                        {
                            for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                            {
#if DEBUG
                                printf("We go here11\n");
#endif
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                        else
                        {
#if DEBUG
                                printf("We go here12\n");
#endif
                            curPort1n = srcIpp->port_n_solid;
                            stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                            usleep(fuzz_info->delay);
                        }
                    }
                }
            }
            else
            {
                curPort2n = dstIpp->port_n_solid;
                if(fuzz_info->src_ip_fuzz)
                {
                    for(curIp1n = srcIpp->ip_n_start; curIp1n <= srcIpp->ip_n_end; curIp1n++)
                    {
                        if(fuzz_info->src_pt_fuzz)
                        {
                            for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                            {
#if DEBUG
                                printf("------------------------------------------------------------------->We go here13\n");
#endif
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                        else
                        {
#if DEBUG
                                printf("We go here14\n");
#endif
                            curPort1n = srcIpp->port_n_solid;
                            stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                            usleep(fuzz_info->delay);
                        }
                    }
                }
                else
                {
                    curIp1n = srcIpp->ip_n_solid;
                    if(fuzz_info->src_pt_fuzz)
                    {
                        for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                        {
#if DEBUG
                                printf("We go here15\n");
#endif
                            stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                            usleep(fuzz_info->delay);
                        }
                    }
                    else
                    {
#if DEBUG
                                printf("We go here16\n");
#endif
                        curPort1n = srcIpp->port_n_solid;
                        stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                        usleep(fuzz_info->delay);
                    }
                }
            }
        }
    }
    else
    {
        if(fuzz_info->src_ip_fuzz)
        {
            for(curIp1n = srcIpp->ip_n_start; curIp1n <= srcIpp->ip_n_end; curIp1n++)
            {
                if(fuzz_info->src_pt_fuzz)
                {
                    for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                    {
                        if(fuzz_info->dst_ip_fuzz)
                        {
                            for(curIp2n = dstIpp->ip_n_start; curIp2n <= dstIpp->ip_n_end; curIp2n++)
                            {
                                if(fuzz_info->dst_pt_fuzz)
                                {
                                    for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                                    {
#if DEBUG
                                printf("We go here17\n");
#endif
                                        stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                        usleep(fuzz_info->delay);
                                    }
                                }
                                else
                                {
#if DEBUG
                                printf("We go here18\n");
#endif
                                    curPort2n = dstIpp->port_n_solid;
                                    stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                    usleep(fuzz_info->delay);
                                }
                            }
                        }
                        else
                        {
                            curIp2n = dstIpp->ip_n_solid;
                            if(fuzz_info->dst_pt_fuzz)
                            {
                                for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                                {
#if DEBUG
                                printf("We go here19\n");
#endif
                                    stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                    usleep(fuzz_info->delay);
                                }
                            }
                            else
                            {
#if DEBUG
                                printf("We go here20\n");
#endif
                                curPort2n = dstIpp->port_n_solid;
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                    }
                }
                else
                {
                    curPort1n = srcIpp->port_n_solid;
                    if(fuzz_info->dst_ip_fuzz)
                    {
                        for(curIp2n = dstIpp->ip_n_start; curIp2n <= dstIpp->ip_n_end; curIp2n++)
                        {
                            if(fuzz_info->dst_pt_fuzz)
                            {
                                for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                                {
#if DEBUG
                                printf("We go here21\n");
#endif
                                    stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                    usleep(fuzz_info->delay);
                                }
                            }
                            else
                            {
#if DEBUG
                                printf("We go here22\n");
#endif
                                curPort2n = dstIpp->port_n_solid;
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                    }
                    else
                    {
                        curIp2n = dstIpp->ip_n_solid;
                        if(fuzz_info->dst_pt_fuzz)
                        {
                            for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                            {
#if DEBUG
                                printf("We go here23\n");
#endif
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                        else
                        {
#if DEBUG
                                printf("We go here24\n");
#endif
                            curPort2n = dstIpp->port_n_solid;
                            stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                            usleep(fuzz_info->delay);
                        }
                    }
                }
            }
        }
        else
        {
            curIp1n = srcIpp->ip_n_solid;
            if(fuzz_info->src_pt_fuzz)
            {
                for(curPort1n = srcIpp->port_n_start; curPort1n <= srcIpp->port_n_end; curPort1n++)
                {
                    if(fuzz_info->dst_ip_fuzz)
                    {
                        for(curIp2n = dstIpp->ip_n_start; curIp2n <= dstIpp->ip_n_end; curIp2n++)
                        {
                            if(fuzz_info->dst_pt_fuzz)
                            {
                                for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                                {
#if DEBUG
                                printf("We go here25\n");
#endif
                                    stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                    usleep(fuzz_info->delay);
                                }
                            }
                            else
                            {
#if DEBUG
                                printf("We go here26\n");
#endif
                                curPort2n = dstIpp->port_n_solid;
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                    }
                    else
                    {
                        curIp2n = dstIpp->ip_n_solid;
                        if(fuzz_info->dst_pt_fuzz)
                        {
                            for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                            {
#if DEBUG
                                printf("We go here27\n");
#endif
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                        else
                        {
#if DEBUG
                                printf("We go here28\n");
#endif
                            curPort2n = dstIpp->port_n_solid;
                            stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                            usleep(fuzz_info->delay);
                        }
                    }
                }
            }
            else
            {
                curPort1n = srcIpp->port_n_solid;
                if(fuzz_info->dst_ip_fuzz)
                {
                    for(curIp2n = dstIpp->ip_n_start; curIp2n <= dstIpp->ip_n_end; curIp2n++)
                    {
                        if(fuzz_info->dst_pt_fuzz)
                        {
                            for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                            {
#if DEBUG
                                printf("We go here29\n");
#endif
                                stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                                usleep(fuzz_info->delay);
                            }
                        }
                        else
                        {
#if DEBUG
                                printf("We go here30\n");
#endif
                            curPort2n = dstIpp->port_n_solid;
                            stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                            usleep(fuzz_info->delay);
                        }
                    }
                }
                else
                {
                    curIp2n = dstIpp->ip_n_solid;
                    if(fuzz_info->dst_pt_fuzz)
                    {
                        for(curPort2n = dstIpp->port_n_start; curPort2n <= dstIpp->port_n_end; curPort2n++)
                        {
#if DEBUG
                                printf("We go here31\n");
#endif
                            stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                            usleep(fuzz_info->delay);
                        }
                    }
                    else
                    {
#if DEBUG
                                printf("We go here32\n");
#endif
                        curPort2n = dstIpp->port_n_solid;
                        stamp_and_send(hostname,curIp1n,curIp2n,curPort1n,curPort2n);
                        usleep(fuzz_info->delay);
                    }
                }
            }
        }
    }

    /** Clean up **/ 

    for(curModule=last_loaded; curModule!=NULL; curModule=curModule->prev) 
    {
        unload_module_x(curModule);

        if(curModule->next != NULL)
        {
            free(curModule->next);
            curModule->next = NULL;
        }
    }

    free(first_loaded);
    first_loaded = NULL;

    for(curPacket = last_packet; curPacket!=NULL; curPacket = curPacket->prev)
    {
        for(curModule=curPacket->last; curModule!=NULL; curModule=curModule->prev)
        {
#if DEBUG
            printf("Packets' cleaning up: 0x%x\t0x%x\n",(unsigned int)curModule->pack,(unsigned int)curModule->pack->data);
#endif
            free(curModule->pack->data);
            curModule->pack->data = NULL;
            free(curModule->pack);
            curModule->pack = NULL;

            if(curModule->next != NULL)
            {
                free(curModule->next);
                curModule->next = NULL;
            }
        }

        free_packet(curPacket);

        if(curPacket->next != NULL)
        {
            free(curPacket->next);
            curPacket->next = NULL;
        }
    }

    free(first_packet);
    first_packet = NULL;

    free_ipp(srcIpp);
    free(srcIpp);
    srcIpp = NULL;

    free_ipp(dstIpp);
    free(dstIpp);
    dstIpp = NULL;

    free(fuzz_info);
    fuzz_info = NULL;

    free(hostname);
    hostname = NULL;

    xmlFreeDoc(doc);

    return 0;
}
