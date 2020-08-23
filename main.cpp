#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/ether.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

unordered_map<string, bool> hosts_mp;
vector<string> hosts;

const bool useBinarySearch = true;

bool isBadHost(string &host) {
    if (useBinarySearch) {
        auto it = lower_bound(hosts.begin(), hosts.end(), host);
        if (it < hosts.end() && *it == host) { //if *it isn't equal host, host will not exist in banned-hosts.
            return true;
        }
        return false;
    }else{
        return hosts_mp[host]; //unordered_map case
    }
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *tb, void *Vdata)
{
    int id = nfq_get_msg_packet_hdr(tb) ? ntohl(nfq_get_msg_packet_hdr(tb)->packet_id) : 0;
    unsigned char *data;

    int status = NF_ACCEPT;

    if (nfq_get_payload(tb, &data) >= 0) {
        auto *_ip = (ip*)(data);
        auto *tcp = (tcphdr*)(data + _ip->ip_hl * 4);
        char *http = reinterpret_cast<char *>(data + _ip->ip_hl * 4 + tcp->th_off * 4);

        string str = string(http);
        int host_pos = str.find("Host: ");
        if (host_pos != string::npos) {
            string host = str.substr(host_pos + string("Host: ").size(), str.find("\n", host_pos) - host_pos - string("Host: ").size() - 1);

            //algorithm:
            //we should exclude linear search because time complexity is O(N)
            //we can think about binary search(using vector or set in C++ STL) and map
            //Binary search has O(log N) complexity.
            //map's time complexity follows its hash algorithm and it is mutable.
            //Nevertheless, the map's average time complexity is better than the linear search.

            if (isBadHost(host)) status = NF_DROP;
        }
    }

    return nfq_set_verdict(qh, id, status, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
	
	if (argc != 2) {
		cout << "Usage: /1m-block <host.txt>\n";
		return 0;
	}

    FILE *f = fopen(argv[1], "r");
    if (f != NULL) {
        string host;
        char buf;
        while ((buf = fgetc(f)) != EOF) {
            if (buf == '\n' && !host.empty()) {
                hosts_mp[host] = true;
                hosts.push_back(host);

                host.clear();
            }else host.push_back(buf);
        }

        if (!host.empty()) {
            hosts_mp[host] = true;
            hosts.push_back(host);
        }

        sort(hosts.begin(), hosts.end()); //For binary search, vector must be sorted.

        fclose(f);
    }

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
    qh = nfq_create_queue(h,  0, &cb, NULL);
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
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}