#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

//All sizes in bytes
const int ID_SIZE = 2;
const int HDR_SIZE = 12;
const int MAX_WIRE_SIZE = 1024;
char *PORT = "53"; //getaddrinfo needs port to be a char*

//typedef struct {
//    char *name;
//    dns_rr_type type;
//    dns_rr_class class;
//    dns_rr_ttl ttl;
//    dns_rdata_len rdata_len;
//    unsigned char *rdata;
//} dns_rr;

/*
 * myopen_clientfd - Open connection with socket type <socktype> to server at <hostname, port> and
 *     return a socket descriptor ready for reading and writing. This
 *     function is reentrant and protocol-independent. use SOCK_DRAM as <socktype> for UDP connections
 *
 *     On error, returns:
 *       -2 for getaddrinfo error
 *       -1 with errno set for other errors.
 */
int myopen_clientfd(char *hostname, char *port, int socktype) {
    int clientfd, rc;
    struct addrinfo hints, *listp, *p;
    
    /* Get a list of potential server addresses */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = socktype;  /* Open a connection */
    hints.ai_flags = AI_NUMERICSERV;  /* ... using a numeric port arg. */
    hints.ai_flags |= AI_ADDRCONFIG;  /* Recommended for connections */
    if ((rc = getaddrinfo(hostname, port, &hints, &listp)) != 0) {
        fprintf(stderr, "getaddrinfo failed (%s:%s): %s\n", hostname, port, gai_strerror(rc));
        return -2;
    }
    
    /* Walk the list for one that we can successfully connect to */
    for (p = listp; p; p = p->ai_next) {
        /* Create a socket descriptor */
        if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
            continue; /* Socket failed, try the next */
        
        /* Connect to the server */
        if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1)
            break; /* Success */
        if (close(clientfd) < 0) { /* Connect failed, try another */  //line:netp:openclientfd:closefd
            fprintf(stderr, "open_clientfd: close failed: %s\n", strerror(errno));
            return -1;
        }
    }
    
    /* Clean up */
    freeaddrinfo(listp);
    if (!p) /* All connects failed */
        return -1;
    else    /* The last connect succeeded */
        return clientfd;
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */
	
	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

//dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
//    /*
//     * Extract the wire-formatted resource record at the offset specified by
//     * *indexp in the array of bytes provided (wire) and return a
//     * dns_rr (struct) populated with its contents. Update the value
//     * pointed to by indexp to the next value beyond the resource record.
//     *
//     * INPUT:  wire: a pointer to an array of bytes
//     * INPUT:  indexp: a pointer to the index in the wire where the
//     *              wire-formatted resource record begins
//     * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
//     *              we are extracting a full resource record or only a
//     *              query (i.e., in the question section of the DNS
//     *              message).  In the case of the latter, the ttl,
//     *              rdata_len, and rdata are skipped.
//     * OUTPUT: the resource record (struct)
//     */
//}


//int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
//    /*
//     * Convert a DNS resource record struct to DNS wire format, using the
//     * provided byte array (wire).  Return the number of bytes used by the
//     * name in wire format.
//     *
//     * INPUT:  rr: the dns_rr struct containing the rr record
//     * INPUT:  wire: a pointer to the array of bytes where the
//     *             wire-formatted resource record should be constructed
//     * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
//     *              we are constructing a full resource record or only a
//     *              query (i.e., in the question section of the DNS
//     *              message).  In the case of the latter, the ttl,
//     *              rdata_len, and rdata are skipped.
//     * OUTPUT: the length of the wire-formatted resource record.
//     *
//     */
//}

/*
 * Generates random id and puts it into beginning of wire
 * Returns the size of the id, which will be the index into wire after the id.
 * This size (I think) is going to be 4. But maybe not if we need the 0x before everything.
 */
int generate_random_id(unsigned char *wire)
{
    int i;
    for (i = 0; i < ID_SIZE; ++i) {
        wire[i] = rand() % 256;
    }
    return i;
}

/*
 * Generates header for dns query. For this lab, every header is same except for the id, which is random.
 * Header looks like:
 * xx xx 01 00  --> x's are for id. 01 for RD bit.
 * 00 01 00 00  --> 01 for total questions
 * 00 00 00 00
 * New size of wire is the global constant HDR_SIZE = 12
 */
void create_header(unsigned char *wire)
{
    int i = generate_random_id(wire);
    memset(&wire[i], 0, HDR_SIZE - i); //set all of header besides id to 0
    const int rd_index = 2;
    const int tot_q_index = 5;
    wire[rd_index] = 1;
    wire[tot_q_index] = 1;
}

/*
 * Convert a DNS name from string representation (dot-separated labels)
 * to DNS wire format, and put it on the wire starting at position HDR_SIZE.  Return
 * the new wire length.
 */
int encode_name_to_wire(char *qname, unsigned char *wire) {
    strcpy(&wire[HDR_SIZE+1], qname); //automatically encodes qname as its byte values.
    
    //Now need to insert size encodings at beginning (wire[HDR_SIZE]) and at every '.' that was in qname
    int qname_i = 0;
    int end_qname = 0; //0 = false
    while(!end_qname)
    {
        int insertion_i = HDR_SIZE + qname_i;
        int cnt = 0; //reset the counter
        for(; qname[qname_i] != '.'; qname_i++) {
            if(qname[qname_i] == '\0') {
                end_qname = 1; //1 = true
                break;
            }
            cnt++; //count the number of characters before the next period
        }
        wire[insertion_i] = cnt; //insert the count at the appropriate place
        qname_i++; //go to next char after the current period
    }
    
    return HDR_SIZE + qname_i + 1; //+1 b/c HDR_SIZE + qname_i points at the \0 in the wire, we want to point one past that
}

/*
 * Extract the wire-formatted DNS name at the offset specified by
 * *indexp in the array of bytes provided (wire) and return its string
 * representation (dot-separated labels) in a char array allocated for
 * that purpose.  Update the value pointed to by indexp to the next
 * value beyond the name.
 *
 * INPUT:  wire: a pointer to an array of bytes
 * INPUT:  indexp, the index in the wire where the wire-formatted name begins
 * OUTPUT: a string containing the string representation of the name,
 *              allocated on the heap.
 */




/*
 * Gets the IP from the wire and decodes it into its string representation (decimal dot notation)
 * For now, assumes that the last 4 bytes of the wire contain the IP address
 * INPUT: wire: pointer to the array of bytes that have the response from DNS server
 * INPUT: i: index into the wire where the IP address begins
 * INPUT: length: length of the wire
 * OUTPUT: the IP address in human readable form (Ex: 192.168.34.27)
 */
char *decode_ip_from_wire(unsigned char *wire, int i, int length) {
    int ipNums[4];
    //cout << mem[0] << " | dec: " << (int)(unsigned char)mem[0] << endl;
    
    int offset = i;
    while(i != length)
    {
        ipNums[i-offset] = (int)wire[i];
        //printf("ipNums[%d]: %d\n", i-offset, ipNums[i-offset]);
        i++;
    }
    
    char ip[16];
    snprintf(ip, sizeof ip, "%d.%d.%d.%d", ipNums[0], ipNums[1], ipNums[2], ipNums[3]);
    return ip;
}

/*
 * Creates question section of dns query
 * Starts at position HDR_SIZE on the wire. Puts encoding of qname on wire, followed by type and class fields
 * This should follow the encoding of qname:
 * 00 01 00 01  --> 1st 00 01 sets type to 1 (A) and 2nd 00 01 sets class to 1 (IN)
 */
int create_question(char *qname, unsigned char *wire)
{
    int i = encode_name_to_wire(qname, wire);
    //add type and class to wire:
    wire[i] = 0; i++;
    wire[i] = 1; i++;
    wire[i] = 0; i++;
    wire[i] = 1; i++;
    return i;
}

/*
 * Create a wire-formatted DNS (query) message using the provided byte
 * array (wire).  Create the header and question sections, including
 * the qname and qtype.
 *
 * INPUT:  qname: the string containing the name to be queried
 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
 *               message should be constructed
 * OUTPUT: the length of the DNS wire message
 */
unsigned short create_dns_query(char *qname, unsigned char *wire) {
    create_header(wire);
    return create_question(qname, wire);
}

/*
 * Extract the IPv4 address from the answer section, following any
 * aliases that might be found, and return the string representation of
 * the IP address.  If no address is found, then return NULL.
 *
 * INPUT:  qname: the string containing the name that was queried
 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
 * INPUT:  length: the length of the wire.
 * OUTPUT: a string representing the IP address in the answer; or NULL if none is found
 */
char *get_answer_address(char *qname, unsigned char *wire, int length) {
    //-------------------------------------------------------------- YOU ARE HERE --------------------------------------------------------------
    //Gameplan: First just try and decode example.com's IP address. There are no aliases and no extra IPs, so this will be a simple case
    //          Once this is working, find out about what people are talking about for multiple IP's and aliases (CNAMEs), and implement that.
    //------------------------------------------------------------------------------------------------------------------------------------------
    
    
    //Note - Only works if exactly one IP address found.
    //Doesn't work if no address found or for things like www.intel.com
    //Also, for multiple IP's found, it returns the wrong one (supposed to return first, but this returns last
    int i = length - 4; //if an IP address exists, this will not point to the first part of it
    
    return decode_ip_from_wire(wire, i, length);
}

/*
 * Send a message (request) over UDP to a server (server) and port
 * (port) and wait for a response, which is placed in another byte
 * array (response).  Create a socket, "connect()" it to the
 * appropriate destination, and then use send() and recv();
 *
 * INPUT:  request: a pointer to an array of bytes that should be sent
 * INPUT:  requestlen: the length of request, in bytes.
 * INPUT:  response: a pointer to an array of bytes in which the
 *             response should be received
 * OUTPUT: the size (bytes) of the response received
 */
int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, char *port) {
    int clientfd = myopen_clientfd(server, port, SOCK_DGRAM); //connect to dns server on port 53. SOCK_DGRAM means UDP connection
    if(send(clientfd, request, requestlen, 0) < 0) //0 param just does no flags. this is equivalent to book's rio_writen call.
        printf("Send failed\n");
    return recv(clientfd, response, MAX_WIRE_SIZE, 0);
}

char *resolve(char *qname, char *server) {
    //build DNS query message
    unsigned char msg[MAX_WIRE_SIZE];
    int msg_length = create_dns_query(qname, msg);
    //send message and receive response
    unsigned char response[MAX_WIRE_SIZE];
    int lengthResp = send_recv_message(msg, msg_length, response, server, PORT);
//    printf("Size of response: %d\n",lengthResp);
//    print_bytes(response, lengthResp);
    
    //extract IP address from response
    return get_answer_address(qname, response, lengthResp);
}

//make an open_myclientfd that adds an int type. then set ai_socktype in open_clientfd to SOCK_DGRAM
int main(int argc, char *argv[]) {
	srand(time(NULL)); //for generating random id
    char *ip;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server>\n", argv[0]);
		exit(1);
	}
    
    ip = resolve(argv[1], argv[2]);
    printf("%s => %s\n", argv[1], ip == NULL ? "NONE" : ip);
}





