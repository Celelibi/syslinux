#include <stdint.h>
#include "net.h"
#include "fs/pxe/pxe.h"


/* DNS CLASS values we care about */
#define CLASS_IN	1

/* DNS TYPE values we care about */
#define TYPE_A		1
#define TYPE_CNAME	5

/* Default DNS port */
#define DNS_PORT	53

#define DNS_MAX_SERVERS 4		/* Max no of DNS servers */
uint32_t dns_server[DNS_MAX_SERVERS] = {0, };

/* Id of the current DNS query */
static uint16_t dns_query_id = 0;

enum dns_answer_state {
    DNS_ANSWER_IP,
    DNS_ANSWER_CNAME,
    DNS_ANSWER_MALFORMED
};

/*
 * The DNS header structure
 */
struct dnshdr {
    uint16_t id;
    uint16_t flags;
    /* number of entries in the question section */
    uint16_t qdcount;
    /* number of resource records in the answer section */
    uint16_t ancount;
    /* number of name server resource records in the authority records section*/
    uint16_t nscount;
    /* number of resource records in the additional records section */
    uint16_t arcount;
} __attribute__ ((packed));

/*
 * The DNS query structure
 */
struct dnsquery {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__ ((packed));


/*
 * The DNS Resource recodes structure
 */
struct dnsrr {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;   /* The lenght of this rr data */
    char     rdata[];
} __attribute__ ((packed));


/*
 * Turns the dotted domain name dotted into a sequence of labels ready for a DNS
 * query.
 * size is the size of the buffer pointer to by labels.
 * Returns the total number of written bytes.
 * Returns 0 if the buffer is too small, even if some data has been written.
 */
static size_t dns_mangle(unsigned char *labels, size_t size, const char *dotted)
{
    unsigned char *labels_start = labels;
    unsigned char *len = labels++;

    if (size < 1)
	return 0;

    size--;

    *len = 0;

    while (*dotted) {
	if (*dotted == '.') {
	    len = labels;
	    *len = 0;
	} else {
	    *labels = *dotted;
	    (*len)++;
	}

	labels++;
	dotted++;
	size--;

	if (*dotted && size < 1)
	    return 0;
    }

    /* Last label length must be 0 */
    if (*len && size < 1)
	return 0;

    if (*len)
        *labels++ = 0;

    return labels - labels_start;
}

/*
 * Turns the sequence of labels from a DNS query / answer to a dotted domain
 * name.
 * labels is the pointer to the sequence of labels.
 * buf is the buffer within which the labels are.
 * buf_size is the size of the buffer.
 * dotted is the buffer to fill with the dotted name, it is always nul
 * terminated.
 * dotted_size is the size of the buffer.
 * maxptr indicates the maximal number of pointers to follow.
 * Returns the number of bytes read from the pointer labels. Returns 0 if the
 * label sequence is malformed.
 * /!\ The returned value may be small if the domain name is compressed as per
 * RFC 1035 4.1.4.
 */
static size_t dns_demangle(const unsigned char *labels, const unsigned char *buf,
	size_t buf_size, char *dotted, size_t dotted_size, int maxptr)
{
    const unsigned char *labels_start = labels;
    const unsigned char *len = labels++;

    while (*len) {
	/* Compressed name */
	if (*len & 0xc0) {
	    const unsigned char *newlabels;
	    size_t size;

	    /* No more pointer following! */
	    if (maxptr == 0)
		goto err;

	    newlabels = buf + ((*len & 0x3f) << 8) + *(len + 1);

	    /* Sanity check */
	    if (newlabels < buf || newlabels >= buf + buf_size)
		goto err;

	    size = dns_demangle(newlabels, buf, buf_size, dotted, dotted_size, maxptr - 1);
	    if (size == 0)
		goto err;

	    return 2;
	}

	/* Just sanity checks */
	if (labels + *len + 1 >= buf + buf_size)
	    goto err;
	if (dotted_size < *len + 2U)
	    goto err;

	strncpy(dotted, (const char *)labels, *len);

	dotted += *len;
	strcpy(dotted, ".");
	dotted++;
	dotted_size -= *len + 1;

	labels += *len;
	len = labels++;
    }

    return labels - labels_start;

err:
    return 0;
}

/*
 * Compare two domain names in dotted format. The only trick is the last dot
 * that is optional.
 * Returns 0 if the names are equivalents, non-zero otherwise.
 */
static int dns_compare_names(const char *s1, const char *s2)
{
    size_t l1, l2;

    l1 = strlen(s1);
    l2 = strlen(s2);

    if (l1 == l2 + 1 && s1[l1 - 1] == '.')
	return strncmp(s1, s2, l2);

    if (l1 + 1 == l2 && s2[l2 - 1] == '.')
	return strncmp(s1, s2, l1);

    return strcmp(s1, s2);
}

/*
 * Fills the buffer with the DNS header + query ready to be sent to a name
 * server.
 * size is the size of the buffer.
 * Returns the exact size of the buffer that has been written.
 * If the buffer is too small, the returned size is 0, even if some data has
 * been partially written.
 */
static size_t dns_query_prepare(unsigned char *buff, size_t size,
	const char *name)
{
    struct dnshdr *hdr;
    struct dnsquery *query;
    size_t lnamesize;


    if (size < sizeof(*hdr))
	return 0;

    /* First, fill the DNS header struct */
    hdr = (struct dnshdr *)buff;
    hdr->id      = htons(dns_query_id++); /* New query ID */
    hdr->flags   = htons(0x0100);         /* Recursion requested */
    hdr->qdcount = htons(1);              /* One question */
    hdr->ancount = 0;                     /* No answers */
    hdr->nscount = 0;                     /* No NS */
    hdr->arcount = 0;                     /* No AR */

    buff += sizeof(*hdr);
    size -= sizeof(*hdr);

    lnamesize = dns_mangle(buff, size, name);
    if (lnamesize == 0)
	return 0;

    buff += lnamesize;
    size -= lnamesize;

    if (size < sizeof(*query))
	return 0;

    query = (struct dnsquery *)buff;

    /* Fill the DNS query packet */
    query->qtype  = htons(TYPE_A);
    query->qclass = htons(CLASS_IN);

    return sizeof(*hdr) + lnamesize + sizeof(*query);
}

/*
 * Parse the received buffer and extract the DNS answer that corresponds to the
 * given name.
 * buf_size is the data size of the buffer.
 * name is the string we want the IP address of.
 * *ip is filled with the answer if any.
 * cname is filled with the CNAME answer if any.
 * cname_size is the size if the cname buffer.
 * DNS_ANSWER_IP is returned if an IP address is found
 * DNS_ANSWER_CNAME is returned if a CNAME reply is found
 * DNS_ANSWER_MALFORMED in any other case, including a non-existing domain.
 */
static enum dns_answer_state dns_answer_parse(const unsigned char *buf,
	size_t buf_size, const char *name, uint32_t *ip, char *cname,
	size_t cname_size)
{
    const struct dnshdr *hdr;
    int qcnt, acnt;
    const unsigned char *qname;
    char textname[512];

    if (buf_size < sizeof(*hdr))
	goto out;

    hdr = (const struct dnshdr *)buf;

    /* Sanity check on the flags */
    if ((hdr->flags ^ htons(0x8000)) & htons(0xf80f))
	goto out;

    qcnt = htons(hdr->qdcount);
    acnt = htons(hdr->ancount);
    if (qcnt > 1)
	dprintf("dns_answer_parse: Suspicious DNS response with multiple queries\n");

    /* Skip questions */
    qname = buf + sizeof(*hdr);
    while (qcnt--) {
	size_t namesize;

	if (qname >= buf + buf_size)
	    goto out;

	namesize = dns_demangle(qname, buf, buf_size, textname, sizeof(textname), 10);
	if (namesize == 0)
	    goto out;

	if (dns_compare_names(textname, name)) {
	    dprintf("dns_answer_parse: Received a query for an unknown domain\n");
	    goto out;
	}

	qname += namesize + sizeof(struct dnsquery);
    }


    /* Iterate on the answers until a useful one is found. */
    while (acnt--) {
	size_t namesize;
	int same;
	size_t rdlen;
	struct dnsrr *rr;

	if (qname >= buf + buf_size)
	    goto out;

	namesize = dns_demangle(qname, buf, buf_size, textname, sizeof(textname), 10);
	if (namesize == 0)
	    goto out;

	same = !dns_compare_names(textname, name);

	rr = (struct dnsrr *)(qname + namesize);

	if ((unsigned char *)rr >= buf + buf_size)
	    goto out;

	rdlen = ntohs(rr->rdlength);

	if ((unsigned char *)rr + rdlen > buf + buf_size)
	    goto out;

	if (!same) {
	    dprintf("dns_answer_parse: Received an answer for an unknown domain.\n");
	    continue;
	}

	if (ntohs(rr->class) != CLASS_IN)
	    continue;

	if (ntohs(rr->type) == TYPE_A && rdlen == 4) {
	    *ip = *(uint32_t *)rr->rdata;
	    return DNS_ANSWER_IP;
	}

	if (ntohs(rr->type) == TYPE_CNAME) {
	    size_t cnamesize;

	    cnamesize = dns_demangle((unsigned char *)rr->rdata, buf, buf_size,
		    textname, sizeof(textname), 10);
	    if (cnamesize == 0)
		goto out;

	    strncpy(cname, textname, cname_size);
	    cname[cname_size - 1] = '\0';
	    return DNS_ANSWER_CNAME;
	}

	qname += namesize + sizeof(*rr) + rdlen;
    }

    dprintf("dns_answer_parse: Didn't find an interesting answer.\n");

out:
    /* If we get there, no meaningful reply were received. */
    return DNS_ANSWER_MALFORMED;
}

/*
 * Tells whether the IP address is that of a known DNS server.
 */
static int is_dns_server(uint32_t ip)
{
    int i;
    for (i = 0; i < DNS_MAX_SERVERS && dns_server[i]; i++) {
	if (dns_server[i] == ip)
	    return 1;
    }
    return 0;
}

/*
 * Perform the actual DNS query.
 */
static int dns_gethostbyname(const char *name, uint32_t *ip)
{
    unsigned char sendbuff[PKTBUF_SIZE];
    unsigned char recvbuff[PKTBUF_SIZE];
    char cname[512];
    struct pxe_pvt_inode socket;
    size_t sendsize;
    uint16_t recvsize;
    uint32_t recvip;
    uint16_t recvport;
    int dnsidx;
    int maxredirect = 10;
    int stop = 0;


    memset(&socket, 0, sizeof(socket));
    *ip = 0;

    if (core_udp_open(&socket))
	return -1;

    sendsize = dns_query_prepare(sendbuff, sizeof(sendbuff), name);

    /* Send the actual query on the network */
    dnsidx = 0;
    while (!stop && dnsidx < DNS_MAX_SERVERS && dns_server[dnsidx]) {
	enum dns_answer_state state;
	int err;

	core_udp_connect(&socket, dns_server[dnsidx], DNS_PORT);
	core_udp_send(&socket, sendbuff, sendsize);
	recvsize = sizeof(recvbuff);

	do {
	    err = core_udp_recv(&socket, recvbuff, &recvsize, &recvip, &recvport);
	    if (err)
		dprintf("dns_gethostbyname: Didn't receive anything.\n");
	    if (!is_dns_server(recvip) || recvport != DNS_PORT)
		dprintf("dns_gethostbyname: Received an unexpected UDP packet\n");
	} while (err == 0 && !(is_dns_server(recvip) && recvport == DNS_PORT));

	core_udp_disconnect(&socket);

	state = dns_answer_parse(recvbuff, recvsize, name, ip, cname, sizeof(cname));

	switch (state) {
	case DNS_ANSWER_IP:
	    stop = 1;
	    break;

	case DNS_ANSWER_CNAME:
	    /* Don't follow CNAME redirections forever */
	    maxredirect--;
	    if (maxredirect == 0) {
		stop = 1;
		break;
	    }

	    /* Ask the same server for the new name */
	    sendsize = dns_query_prepare(sendbuff, sizeof(sendbuff), cname);
	    name = cname;
	    *ip = 0;
	    break;

	case DNS_ANSWER_MALFORMED:
	    /* Just ask another server */
	    *ip = 0;
	    dnsidx++;
	    break;
	}
    }

    core_udp_close(&socket);

    return *ip == 0;
}

/*
 * parse the ip_str and return the ip address with *res.
 * return true if the whole string was consumed and the result
 * was valid.
 */
static bool parse_dotquad(const char *ip_str, uint32_t *res)
{
    const char *p = ip_str;
    uint8_t part = 0;
    uint32_t ip = 0;
    int i;

    for (i = 0; i < 4; i++) {
	while (is_digit(*p)) {
	    part = part * 10 + *p - '0';
	    p++;
	}
	if (i != 3 && *p != '.')
	    return false;

	ip = (ip << 8) | part;
	part = 0;
	p++;
    }
    p--;

    *res = htonl(ip);
    return *p == '\0';
}

__export uint32_t dns_resolv(const char *name)
{
    char fullname[512];
    uint32_t ip;
    int err;

    /*
     * Return failure on an empty input... this can happen during
     * some types of URL parsing, and this is the easiest place to
     * check for it.
     */
    if (!name || !*name)
	return 0;

    /* IP already in dotted notation */
    if (parse_dotquad(name, &ip))
	return ip;

    /* Special case for localhost */
    if (!strcmp(name, "localhost")) {
	parse_dotquad("127.0.0.1", &ip);
	return ip;
    }

    /* At this point we'll need at least one DNS server */
    if (dns_server[0] == 0)
	return 0;

    /* Is it a local (unqualified) domain name? */
    if (!strchr(name, '.') && LocalDomain[0]) {
	snprintf(fullname, sizeof(fullname), "%s.%s", name, LocalDomain);
	name = fullname;
    }

    err = dns_gethostbyname(name, &ip);
    if (err)
	return 0;

    return ip;
}
