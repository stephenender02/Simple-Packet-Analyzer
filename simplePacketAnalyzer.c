/* ------------------------------------------------------------------------
    CS-455 Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By: Dr. Mohamed Aboutabl (c) 2020, 2025
    
    Implemented By:     Stephen Ender
    File Name:          simplePacketAnalyzer.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-------------------------------------------------------------------------*/
void usage(char *cmd)
{
    printf("Usage: %s fileName\n" , cmd);
}

/*-------------------------------------------------------------------------*/
int main( int argc , char *argv[] )
{
	char       *pcapIn ;
	pcap_hdr_t  pcapHdr ;
	packetHdr_t pktHdr ;
	uint8_t     ethFrame[MAXFRAMESZ] ;
	etherHdr_t *frameHdrPtr = (etherHdr_t *) ethFrame ;

    if ( argc < 2 )
    {
        usage( argv[0] ) ;
        exit ( EXIT_FAILURE ) ;
    }

    pcapIn = argv[1] ;
    
    printf("\nProcessing PCAP file '%s'\n\n" , pcapIn ) ;

    // Read the global header of the pcapInput file
    // By calling readPCAPhdr().
    // If error occured, call errorExit("Failed to read global header from the PCAP file " )
    if (readPCAPhdr(pcapIn, &pcapHdr) == -1) {
        errorExit("Failed to read global header from the PCAP file");
    }


    // Print the global header of the pcap filer
    printPCAPhdr(&pcapHdr);


    // Print labels before any packets are printed
    puts("") ;
    printf("%6s %14s %11s %-20s %-20s %8s %s\n" ,
           "PktNum" , "Time Stamp" , "OrgLen / Captrd"  , 
           "Source" , "Destination" , "Protocol" , "info");

    uint32_t serialNo = 1 ;

    // Read one packet at a time
    while (getNextPacket(&pktHdr, ethFrame))
    {
        printf("%6u " , serialNo++ ) ;

        // Use packetMetaDataPrint() to print the packet header data;
        // Time is printed relative to the 1st packet's time
        printPacketMetaData(&pktHdr);
        
        // Use packetPrint( ) to print the actual content of the packet starting at the
        // ethernet level and up
        printPacket(frameHdrPtr);

        puts("");       
    }
    
    printf("\nReached end of PCAP file '%s'\n" , pcapIn ) ;
    cleanUp() ;    
}
