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

#pragma pack(push,1)
struct pseudo_h
{
    uint32_t sd;
    uint32_t dd;
    uint8_t proto;
    uint8_t reserve;
    uint16_t tcpleng;
};

#pragma pack(pop)
char * change1;
char * change2;

void search(char *para1, char *find_tcpdata, int length)
{
    int len = strlen(para1);

    for(; length>0; length--)
    {
            if(memcmp(para1,find_tcpdata,len)==0)
            {
                 memcpy(find_tcpdata,change2,len);    //찾은 문자열을 배열에 변수나 배열에 저장하고 change2와 바꾼다.
                 find_tcpdata++;
                 if(find_tcpdata==NULL)
                     break;
            }
            else
                find_tcpdata++;
    }

}

int32_t cal_carry(int32_t sum)
{
    if(sum>=65536)
    {
        sum=sum-65536+1;
        return sum;
    }
    else
        return sum;
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
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
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


                int32_t iphdl = (ipp->ihl)*4;
                int32_t total = ntohs(ipp->tot_len);
                int32_t tcp_tcpdata = total - iphdl;

                //pseudo checksum
                uint16_t csp[7];
                struct pseudo_h cs;
                cs.sd=ntohl(ipp->saddr);
                cs.dd=ntohl(ipp->daddr);
                cs.proto=ipp->protocol;
                cs.reserve=0;
                cs.tcpleng=tcp_tcpdata;

                memcpy(csp,&cs,sizeof(cs));  //memcpy사용하지 않고 계산해라

                int32_t sum{0};
                for(int i=0; i<7; i++)
                {
                    sum += csp[i];
                    sum=cal_carry(sum);
                }

                if(ipp->protocol == IPPROTO_TCP)
                {
                    data += iphdl;
                    struct tcphdr *tp;
                    tp = (struct tcphdr*)data;

                    printf("\n");
                    uint16_t ch =ntohs(tp->check);

                    printf("\n");
                    tp->check=0x0; //체크섬 계산을 위해 0으로 맞춤
                    data += tp->th_off * 4;
                    char *para1 = change1;
                    char *find_tcpdata = (char*)data;
                    search(para1,find_tcpdata,ret);
                    printf("\n\n%s\n",find_tcpdata);

                    data -= tp->th_off * 4; //다시 바뀐값에서의 데이터 끼리의 합을 구하기위해

                    int cal_tcp;
                    if(tcp_tcpdata % 2 == 1)
                        cal_tcp=tcp_tcpdata/2 + 1;
                    else
                        cal_tcp=tcp_tcpdata/2;

                    printf("\nqseudo 헤더 = %04x \n",sum);
                    printf("tcp_tcpdata(total - iphdl) = %d\n", tcp_tcpdata);
                    printf("cal_tcp = %d\n", cal_tcp);


                    //tcp checksum 계산

                    uint16_t tdata[cal_tcp]{0};
                    int32_t sumsum{0};
                    uint16_t *p = (uint16_t*)data; //2byte로 받기 위해서 포인터로 집어줌
                    int i=0;
                    while(i<cal_tcp)
                    {
                        if((i+1==cal_tcp) && i % 2 == 1)
                            tdata[cal_tcp-1]=(uint8_t)*p;  //2바이트씩 묶엇을때 홀수일경우 해결
                        else
                            tdata[i] = ntohs(*(p++));

                        sumsum += tdata[i++];
                        sumsum=cal_carry(sumsum);

                    }
                    printf("pseudo = 0x%04x\n",sum);
                    printf("sumsum = 0x%04x\n",sumsum);
                    int32_t cal1 =sumsum-ch;
                    int32_t cal2 =0;      // 변경 carry 부분 함수화하기
                    cal2 = sum+cal1;
                    if(cal2>=65536)
                        cal2=cal2-65536+1;

                    uint16_t fin_check = (uint16_t)~cal2;
                    printf("fin check = 0x%04x\n",cal2);
                    printf("fin check 을 1의 보수화하면 checksum = 0x%04x\n", fin_check);
                    tp->check=ntohs(fin_check);

                    data -= iphdl; //다시 총패킷을 구하기위해 iphdr의 시작점으로
                    uint8_t tcp_pack[total];  //16비트인 tcp data를 8비트로 바꾼패킷
                    int j=0;
                    while(j<total)  //패킷을 배열에 넣어서 패킷완성(iphdr ~ tcpdata)
                    {
                        //printf("%02x ", *data);
                        tcp_pack[j]= *(data++);
                        j++;
                    }


                    int cc=0;
                    for(int i=0 ; i<total; i++)
                    {
                         printf("%02x ", tcp_pack[i]);
                         if(++cc % 16 == 0)
                            printf("\n");
                    }
                    printf("\n");
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

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); //3,4번 인자를 이용하여 전송 3 = len 4 = 시작주소
}

int main(int argc, char *argv[])
{
    if(argc!=3)
    {
        printf(" 사용법 : <Want Word> <Change Word\n");
        return 0;
    }
    change1 = argv[1];
    change2 = argv[2];
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
