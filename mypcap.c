/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2023
    
    Implemented By:     Stephen Ender
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // The input PCAP file
bool        bytesOK ;   // Does the capturer's byte ordering same as mine?
                        // Affects the global PCAP header and each packet's header

bool        microSec ;  // is the time stamp in Sec+microSec ?  or is it Sec+nanoSec

double      baseTime ;  // capturing time of the very 1st packet in this file
bool        baseTimeSet = false ;

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

void errorExit( char *str )
{
    if (str) puts(str) ;
    if ( pcapInput  )  fclose ( pcapInput  ) ;
    exit( EXIT_FAILURE );
}

void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ;
}

/*-------------------------------------------------------------------------*/
//  Put any additional utility functions of your creation here

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname' 
    and read its global header into buffer 'p'
    Side effects:    
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header 
          fields except for the magic_number

    Remember to check for incuming NULL pointers
    
    Returns:  0 on success
             -1 on failure  */

int readPCAPhdr( char *fname , pcap_hdr_t *p)
{
    // Open PCAP file
    pcapInput = fopen(fname, "r");
    if (pcapInput == NULL) {
        printf("Error opening file: %s", fname);
        return -1;
    }

    // Read global header into p
    size_t bytes_read = fread(&(p->magic_number), 4, 1, pcapInput);

    // Determine the capturer's byte ordering
    uint32_t standard_order = 0xa1b2c3d4;
    uint32_t reversed_order = 0xd4c3b2a1;
    uint32_t standard_nano = 0xa1b23c4d;
    uint32_t reversed_nano = 0x4d3cb2a1;
    if(p->magic_number == standard_order) {
        bytesOK = true;
        microSec = true;
    }
    if (p->magic_number == reversed_order) {
        bytesOK = false;
        microSec = true;
    }
    if (p->magic_number == standard_nano) {
        bytesOK = true;
        microSec = false;
    }
    if (p->magic_number == reversed_nano) {
        bytesOK = false;
        microSec = false;
    }

    // Read in the rest of the header
    if (bytesOK) {
        bytes_read += fread(&(p->version_major), 2, 1, pcapInput);
        bytes_read += fread(&(p->version_minor), 2, 1, pcapInput);
        bytes_read += fread(&(p->thiszone), 4, 1, pcapInput);
        bytes_read += fread(&(p->sigfigs), 4, 1, pcapInput);
        bytes_read += fread(&(p->snaplen), 4, 1, pcapInput);
        bytes_read += fread(&(p->network), 4, 1, pcapInput);
    } else {
        uint16_t version_maj_temp;
        bytes_read += fread(&(version_maj_temp), 2, 1, pcapInput);
        p->version_major = ntohs(version_maj_temp);
        uint16_t version_min_temp;
        bytes_read += fread(&(version_min_temp), 2, 1, pcapInput);
        p->version_minor = ntohs(version_min_temp);
        int32_t thiszone_temp;
        bytes_read += fread(&(thiszone_temp), 4, 1, pcapInput);
        p->thiszone = ntohl(thiszone_temp);
        uint32_t sigfigs_temp;
        bytes_read += fread(&(sigfigs_temp), 4, 1, pcapInput);
        p->sigfigs = ntohl(sigfigs_temp);
        uint32_t snaplen_temp;
        bytes_read += fread(&(snaplen_temp), 4, 1, pcapInput);
        p->snaplen = ntohl(snaplen_temp);
        uint32_t network_temp;
        bytes_read += fread(&(network_temp), 4, 1, pcapInput);
        p->network = ntohl(network_temp);
    }

    return 0;
}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void printPCAPhdr( const pcap_hdr_t *p ) 
{
    printf("magic number %X\n"  , p->magic_number  ) ;
    printf("major version %X\n", p->version_major);
    printf("minor version %X\n", p->version_minor);
    printf("GMT to local correction %X seconds\n", p->thiszone);
    printf("accuracy of timestamps %X\n", p->sigfigs);
    printf("Cut-off max length of captured packets %d\n", p->snaplen);
    printf("data link type %X\n", p->network);

}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame) 
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload
    
    If this is the very first packet from the PCAP file, set the baseTime 
    
    Returns true on success, or false on failure for any reason */

bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  )
{
    // Check for incoming NULL pointers
     if (p == NULL || ethFrame == NULL) {
        printf("Null pointer in getNextPacket.");
        return false;
    }

    // Read the header of the next paket in the PCAP file
    uint32_t packet_hdr_buffer[4];
    if (fread(packet_hdr_buffer, 4, 4, pcapInput) != 4) {
        return false;
    }

    // Reorder the bytes of the fields in this packet header
    if( ! bytesOK )   
    {
        for (int i = 0; i < 4; i++) {
            packet_hdr_buffer[i] = ntohl(packet_hdr_buffer[i]);
        }
    }

    // Move from buffer to struct
    p->ts_sec = packet_hdr_buffer[0];
    p->ts_usec = packet_hdr_buffer[1];
    p->incl_len = packet_hdr_buffer[2];
    p->orig_len = packet_hdr_buffer[3];
    
    // Read the 'incl_len' bytes from the PCAP file into the ethFrame[]
    fread(ethFrame, p->incl_len, 1, pcapInput);

    // If necessary, set the baseTime .. Pay attention to possibility of nano second 
    // time precision (instead of micro seconds )
    if(!baseTimeSet) {
        baseTimeSet = true;
        baseTime = p->ts_sec;
        if (microSec) {
            baseTime += p->ts_usec / 1000000.0;
        } else {
            baseTime += p->ts_usec / 1000000000.0;
        }
    }
    
    return true ;
}

/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */

void printPacketMetaData( const packetHdr_t *p  )
{
   // Calculate packet capture time
   double capture_time = p->ts_sec;
   if (microSec) {
       capture_time += p->ts_usec / 1000000.0;
   } else {
       capture_time += p->ts_usec / 1000000000.0;
   }
   double actual_time = capture_time - baseTime;

   // Print results
   printf("%14f %6d / %6d", actual_time, p->orig_len, p->incl_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy
   Recall that all multi-byte data is in Network-Byte-Ordering
*/

void printPacket( const etherHdr_t *frPtr )
{
    char        ipBuf[MAXIPv4ADDRLEN] ,
                macBuf[MAXMACADDRLEN] ;

    uint16_t    ethType = ntohs(frPtr->eth_type);

    // If this is NOT an IPv4 packet, print Source/Destination MAC addresses
    void *nextHdr = (void *) ( (uint8_t *) frPtr + sizeof(etherHdr_t)) ;

    switch( ethType )
    {
        case PROTO_ARP: // Print ARP message
            char macSource[MAXMACADDRLEN];
            char macDestination[MAXMACADDRLEN];
            macToStr(frPtr->eth_srcMAC, macSource);
            macToStr(frPtr->eth_dstMAC, macDestination);
            printf(" %-20s %-21s", macSource, macDestination);
            printARPinfo((arpMsg_t *) nextHdr);
            return ;
      
        case PROTO_IPv4: // Print IP datagram and upper protocols
            // print Source/Destination IP addresses
            char ipSource[MAXIPv4ADDRLEN];
            char ipDestination[MAXIPv4ADDRLEN];
            ipv4Hdr_t *ipHdr = (ipv4Hdr_t *) nextHdr;
            ipToStr(ipHdr->ip_srcIP, ipSource);
            ipToStr(ipHdr->ip_dstIP, ipDestination);
            printf(" %-20s %-21s", ipSource, ipDestination);
            printIPinfo((ipv4Hdr_t *) nextHdr);
            return ;

        default:
            macToStr(frPtr->eth_srcMAC, macSource);
            macToStr(frPtr->eth_dstMAC, macDestination);
            printf(" %-20s %-21s", macSource, macDestination);    
             printf( "Protocol %hu Not Supported Yet" , ethType ) ; 
             return ;
    }
}

/*-------------------------------------------------------------------------*/
/* Print ARP messages */

void printARPinfo( const arpMsg_t *p )
{
    printf("%-8s " , "ARP" );

    uint16_t operation = ntohs(p->arp_oper);

    switch(operation)
    {
        case ARPREQUEST:
            char target[MAXIPv4ADDRLEN];
            ipToStr(p->arp_tpa, target);
            char requester[MAXIPv4ADDRLEN];
            ipToStr(p->arp_spa, requester);

            printf("Who has %s ? " , target);
            printf("Tell %s" , requester) ; 
            break ;

        case ARPREPLY:
            char sender[MAXIPv4ADDRLEN];
            ipToStr(p->arp_spa, sender);
            char senderMac[MAXMACADDRLEN];
            macToStr(p->arp_sha, senderMac);
            printf("%s is at %s" , sender, senderMac) ;
            break ;

        default:
            printf("Invalid ARP Operation %4x" , p->arp_oper);
            break ;
    }
}

/*-------------------------------------------------------------------------*/
/* Print IP datagram and upper protocols  
   Recall that all multi-byte data is in Network-Byte-Ordering
*/

void    printIPinfo ( const ipv4Hdr_t *q )
{
    void       *nextHdr ;
    icmpHdr_t  *ic ;
    unsigned   ipHdrLen, ipPayLen , dataLen=0 , optLen = 0;

    // Calculate the IP header length in bytes
    ipHdrLen = ((q->ip_verHlen) & 0xf) * 4;
    // Calculate the IP payload length (total length - header length)
    ipPayLen = ntohs(q->ip_totLen) - ipHdrLen;

    // 'dataLen' is the number of bytes in the payload of the encapsulated
    // protocol without its header. For example, it could be the number of bytes
    // in the payload of the encapsulated ICMP message

    optLen   = ipHdrLen  - sizeof( ipv4Hdr_t ) ; // The minimup IP header is 20 bytes
    nextHdr  = (void *) ( (uint8_t *) q + ipHdrLen ) ;

    switch ( q->ip_proto )
    {
        case PROTO_ICMP: 
            printf( "%-8s " , "ICMP" ) ;
            // Print IP header length and numBytes of the options
            printf("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
            printICMPinfo((icmpHdr_t *) nextHdr);
            // Compute 'dataLen' : the length of the data section inside the ICMP message
            unsigned icmpHdrLen = 8;
            dataLen = ipPayLen - icmpHdrLen;
            break ;

        case PROTO_TCP: 
            printf( "%-8s " , "TCP" ) ;
            // Print IP header length and numBytes of the options
            printf("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
            // Call printTCPinfo
            const tcpHdr_t *p = (tcpHdr_t *) nextHdr;
            printTCPinfo(p);
            unsigned tcpHdrLen = ((p->tcp_hlen_res_flags[0] & 0xF0) >> 4) * 4;
            dataLen = ipPayLen - tcpHdrLen;
            break ;

        case PROTO_UDP: 
            printf( "%-8s " , "UDP" ) ; 
            // Print IP header length and numBytes of the options
            printf("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
            // Leave dataLen as Zero for now
            // Call printUDPinfo
            printUDPinfo((udpHdr_t *) nextHdr);
            unsigned udpHdrLen = 8;
            dataLen = ipPayLen - udpHdrLen;
            break ;

        default:    
            printf( "%8x %s" , q->ip_proto , "Protocol is Not Supported Yet" ) ;
            return ;
    }

    printf(" AppData=%5u" , dataLen ) ;

}

/*-------------------------------------------------------------------------*/
/* Print the ICMP info 
   Recall that all multi-byte data is in Network-Byte-Ordering
   Returns length of the ICMP header in bytes  
*/

unsigned printICMPinfo( const icmpHdr_t *p ) 
{
    unsigned icmpHdrLen = sizeof( icmpHdr_t ) ;
    uint16_t    id , seqNum ;
    
    id     =     (uint16_t) ((p->icmp_line2[0] << 8) | p->icmp_line2[1]);
    seqNum =     (uint16_t) ((p->icmp_line2[2] << 8) | p->icmp_line2[3]);

    printf(" ICMP_HDR{ "  ) ;

    switch ( p->icmp_type )
    {
      case ICMP_ECHO_REPLY: 
        if (p->icmp_code == 0) {
            printf("Echo Reply   :id=%5d, seq=%5d", id, seqNum);
        } else {
            printf("Echo Reply   : %19s %3d" , "INVALID Code:" , p->icmp_code);
        }
        break ;
    
      case ICMP_ECHO_REQUEST:
       if (p->icmp_code == 0) {
        printf("Echo Request :id=%5d, seq=%5d", id, seqNum);
       } else {
        printf("Echo Request : %19s %3d" , "INVALID Code:" , p->icmp_code);
       }
        break ;
    
      default:
        printf("Type  %3d , code %3d Not Yet Supported" , p->icmp_type, p->icmp_code);
    }
    printf( "}" );

    
    return icmpHdrLen ;
}


unsigned printTCPinfo(const tcpHdr_t *p) {
    // TCP Header Length in bytes, and how many of these bytes are TCP header options.
    int tcp_size = (p->tcp_hlen_res_flags[0] & 0xF0) >> 4;
    tcp_size *= 4;
    int tcp_options = tcp_size - 20;
    printf(" TCPhdr=%d (Options %2d bytes) ", tcp_size, tcp_options);

    // Source & Destination ports numerical & names as described  in UDP above.
    uint16_t src = ntohs(p->tcp_source);
    struct servent *src_struct = getservbyport(htons(src), NULL);
    if (src_struct == NULL) {
        printf("Port %5u (   *** ) -> ", src);
    } else {
        printf("Port %5u (%7s) -> ", src, src_struct->s_name);
    }
    uint16_t dest = ntohs(p->tcp_dest);
    struct servent *dest_struct = getservbyport(htons(dest), NULL);
    if (dest_struct == NULL) {
        printf("%5u (   *** ) ", dest);
    } else{
        printf("%5u (%7s) ", dest, dest_struct->s_name);
    }

    // Flags as "[SYN PSH ACK FIN RST ]" in that order. If a flag is not set, print 4 spaces instead as in [SYN ____ACK FIN ____] .
    char *urg_str, *ack_str, *psh_str, *rst_str, *syn_str, *fin_str;
    bool ack_set = false;
    // ACK Check
    if (p->tcp_hlen_res_flags[1] & 0x10) {
        ack_str = "ACK ";
        ack_set = true;
    } else {
        ack_str = "    ";
    }
    // PSH Check
    if (p->tcp_hlen_res_flags[1] & 0x08) {
        psh_str = "PSH ";
    } else {
        psh_str = "    ";
    }
    // RST Check
    if (p->tcp_hlen_res_flags[1] & 0x04) {
        rst_str = "RST ";
    } else {
        rst_str = "    ";
    }
    // SYN Check
    if (p->tcp_hlen_res_flags[1] & 0x02) {
        syn_str = "SYN ";
    } else {
        syn_str = "    ";
    }
    // FIN Check
    if (p->tcp_hlen_res_flags[1] & 0x01) {
        fin_str = "FIN ";
    } else {
        fin_str = "    ";
    }
    printf("[%s%s%s%s%s]", syn_str, psh_str, ack_str, fin_str, rst_str);
    
    // Sequence number using "%10u".
    uint32_t sequence = ntohl(p->tcp_sequence_num);
    printf(" Seq=%10u ", sequence);
    
    // When applicable, the Acknowledgement number using "%10u". Otherwise, print 15 spaces.
    if (ack_set) {
        uint32_t ack_num = ntohl(p->tcp_ack_num);
        printf("Ack=%10u ", ack_num);
    } else {
        printf("               ");
    }
    
    // The receive window size using "%5hu".
    uint16_t window = ntohs(p->tcp_window);
    printf("Rwnd=%5hu", window);
    return 0;
}


unsigned printUDPinfo(const udpHdr_t *p) {
    // Total Length of the UDP datagram in bytes.
    uint16_t len = ntohs(p->udp_len);
    printf(" UDP %5d Bytes. ", len);

    // Source and Destination ports in numeric using "%5u"  .
    uint16_t src = ntohs(p->udp_source);
    struct servent *src_struct = getservbyport(htons(src), NULL);
    if (src_struct == NULL) {
        printf("Port %5u (   *** ) -> ", src);
    } else {
        printf("Port %5u (%7s) -> ", src, src_struct->s_name);
    }
    uint16_t dest = ntohs(p->udp_dest);
    struct servent *dest_struct = getservbyport(htons(dest), NULL);
    if (dest_struct == NULL) {
        printf("%5u (   *** ) ", dest);
    } else{
        printf("%5u (%7s) ", dest, dest_struct->s_name);
    }

    // Source and Destination port names using "(%7s)" format, or "(   *** )"   if port has no standard name.
    // Should expect any of the many many service names, so use a library function to convert port numbers into service names.
    return 0;
}
/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/

/* Convert IPv4 address 'ip' into a dotted-decimal string in 'ipBuf'. 
   Returns 'ipBuf'  */
 
char * ipToStr( const IPv4addr ip , char *ipBuf )
{
    snprintf(ipBuf, 16, "%d.%d.%d.%d", ip.byte[0], ip.byte[1], ip.byte[2], ip.byte[3]);
    return ipBuf;
}

/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx 
    in the caller-provided 'buf' whose maximum 'size' is given
    Do not overflow this buffer
    Returns 'buf'  */

char *macToStr( const uint8_t *p , char *buf )
{
    // Visit each byte and extract chars
    size_t bytes_in_mac = 6;
    int buf_index = 0;
    for (int i = 0; i < bytes_in_mac; i++) {
        uint8_t current_byte = p[i];

        // Convert hex to char
        uint8_t first_digit = (current_byte >> 4) & 0xF;
        if (first_digit >= 10) {
            first_digit += 'a' - 10;
        } else {
            first_digit += '0';
        }
        uint8_t second_digit = current_byte & 0xF;
        if (second_digit >= 10) {
            second_digit += 'a' - 10;
        } else {
            second_digit += '0';
        }

        // Insert chars into buf; add colon
        buf[buf_index] = first_digit;
        buf_index++;
        buf[buf_index] = second_digit;
        buf_index++;
        buf[buf_index] = ':';
        buf_index++;
    }
    // Replace last colon with null term
    buf[buf_index - 1] = '\0';

    // Return buf
    return buf;
}

