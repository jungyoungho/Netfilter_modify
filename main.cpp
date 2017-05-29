#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <iostream>

/* returns packet id */

#pragma pack(push,1)
struct cspack
{
    uint16_t tcppro;
    uint32_t sd;
    uint32_t dd;
    uint16_t offset;
};

struct thsum
{
    uint16_t sport;
    uint16_t dport;
    uint16_t seqnum;
    uint16_t acnum;
    uint16_t offset;
    uint8_t flags;
    uint16_t window;
};

#pragma pack(pop)

char * condi;
int drop_mess;
char * change1;
char * change2;

void sendpacket(struct iphdr *ipp, struct tcphdr *tp, uint8_t *packet)
{

}

void search(char *body, char *find, int length)
{
    int len = strlen(body);
    //printf("%s\n",find);
    for(; length>0; length--)
    {
            if(memcmp(body,find,len)==0)
            {
                 memcpy(find,change2,7);
                 //찾은 문자열을 배열에 변수나 배열에 저장하고 change2와 바꾼다.
                 find++;
                 if(find==NULL)
                     break;
            }
            else
                find++;

    }

}
static u_int32_t print_pkt (struct nfq_data *tb)
{

    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    u_char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);  //ph?
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
                struct iphdr *ipp;
                ipp=(struct iphdr*)data;

                if(ipp->protocol == IPPROTO_TCP)
                {
                    data += sizeof(struct iphdr);
                    data += sizeof(struct tcphdr);

                    struct tcphdr *tp;
                    tp = (struct tcphdr*)data;

                    char *body = change1;
                    char *find = (char*)data;
                    search(body,find,ret);
                    printf("%s \n",find);

                    //checksum < -- fix here!!
                    //1.IP헤더(상위프로토콜 + 송신자IP주소 + 발신자 IP 주소) + TCP 헤더길이
                    struct cspack cs;
                    uint16_t csp[5];
                    cs.tcppro=0x0006;
                    cs.sd=ntohl(ipp->saddr);
                    cs.dd=ntohl(ipp->daddr);
                    cs.offset=tp->doff;
                    memcpy(csp,&cs,sizeof(cs));
                    int sum;
                    for(int i=0; i<5; i++)
                    {
                        sum += csp[i];
                    }

                    printf("\n IP헤더(상위프로토콜 + 송신자IP주소 + 발신자 IP 주소) + TCP 헤더길이 = %04x\n",sum);
/*
                    struct thsum ts;
                    uint16_t ths[sizeof(ts)];
                    ts.sport = tp->th_sport;
                    ts.dport = tp->th_dport;
                    ts.seqnum = tp->seq;
                    ts.acnum  = tp->ack_seq;
                    ts.offset = tp->doff;
                    ts.flags = tp->th_flags;
                    ts.window = tp->window;
                    memcpy(ths,&ts,sizeof(ts));
                    int sum2;
                    for(int i=0; i<7; i++)
                    {
                        sum2 += ths[i];
                    }
                    printf("\n tcp header sum = %04x  \n",sum2);
*/
                    //checksum

                    //send packet
                    uint8_t *packet;

                    //sendpacket(ipp, tp, packet);  <- fix here first
                    for(; ret>0; ret--)
                    {
                        uint32_t *host_start = (uint32_t *)data;
                        if(*host_start == ntohl(0x486f7374))
                        {
                           int len = strlen(condi);
                           if(memcmp(condi,(char*)data+6,len)==0) // or strncmp
                           {
                                drop_mess=1;
                                printf(">> This URL is Drop!!\n");
                                break;
                           }
                           else
                           {
                               drop_mess=0;
                               break;
                           }
                        }
                        else
                            data++;
                    }
           }
           printf("payload_len=%d ", ret);
           fputc('\n', stdout);
    }
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("Entering callback\n");

    if(drop_mess ==1)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    else if(drop_mess==0)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char *argv[])
{
    if(argc!=4)
    {
        printf(" 사용법 : <Write URL> <Want Word> <Change Word\n");
        return 0;
    }
    condi = argv[1];
    change1 = argv[2];
    change2 = argv[3];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));



    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received \n");
            nfq_handle_packet(h, buf, rv); //패킷받는곳
            continue;
        }

        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
