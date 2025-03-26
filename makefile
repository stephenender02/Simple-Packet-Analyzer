all:  
	gcc mypcap.c simplePacketAnalyzer.c -o simplePacketAnalyzer
   
clean:
	rm -f simplePacketAnalyzer *.txt
