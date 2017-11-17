#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netinet/in.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>

#include<linux/if_ether.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/time.h>


#define HEADER_SIZE 14


#define MY_DEST_MAC0	0xFF
#define MY_DEST_MAC1	0xFF
#define MY_DEST_MAC2	0xFF
#define MY_DEST_MAC3	0xFF
#define MY_DEST_MAC4	0xFF
#define MY_DEST_MAC5	0xFF



char *time_stamp();



int main() {

	int sockIP, nIP;
	printf("\n Enteing application");
	char bufferIP[2048];
	struct sockaddr_ll src_addr;
	struct sockaddr_ll src_addrIP;
	socklen_t addr_len = sizeof src_addr;
	int flagIP = 0;
	char recvOnEtherPortIP[5];
	char*  ctrlInterface  = "eth0";
	char*  ctrlIFName  = "eth0";

	printf("\n Creating a socket");
	//  socklen_t addr_lenIP = sizeof(src_addrIP);
	socklen_t addr_lenIP = sizeof(src_addrIP);

	printf("\n Entering loop \n");
	//sleep(10);


	// Creating the MNLR IP SOCKET HERE
	if ((sockIP = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("ERROR: IP Socket ");
		printf("\n ERROR: IP Socket ");

	}

	int count = 0;
	time_t start_t, end_t;

	while (1) {


		//printf("\n Created a socket");
		//printf("\n Entering looping  \n");
		nIP = recvfrom(sockIP, bufferIP, 2048, MSG_DONTWAIT,
					   (struct sockaddr *) &src_addrIP, &addr_lenIP);
		//printf("\n recieved from sockip\n:");
		if (flagIP == 0) { //if message is recived from socket flagIP remains 0 and we enter the loop

			unsigned int tcIP = src_addrIP.sll_ifindex;

			if_indextoname(tcIP, recvOnEtherPortIP);

			if ((strcmp(recvOnEtherPortIP, ctrlInterface) == 0) || nIP == -1) {
				continue;
			}
			//printf("\n checking 1 is done\n");
			if ((strncmp(recvOnEtherPortIP, ctrlIFName, strlen(ctrlIFName))
				 != 0)) {

				if(count == 0)
					time(&start_t);


				//printf("\nmessage recived on interface %s\n",recvOnEtherPortIP);
				unsigned char *ipHeadWithPayload;

				//print_hex(bufferIP,nIP);

				int ipPacketSize = nIP - 14;
				// printf("\n ipPacketsize = %d\n",ipPacketSize);
				ipHeadWithPayload = (unsigned char *) malloc(ipPacketSize);
				memset(ipHeadWithPayload, '\0', ipPacketSize);
				memcpy(ipHeadWithPayload, &bufferIP[14], ipPacketSize);
				//print_hex(ipHeadWithPayload,ipPacketSize);
				//printf("\n");
				/*  unsigned char ipDestTemp[7];
                  memset(ipDestTemp, '\0', 7);
                  sprintf(ipDestTemp, "%u.%u.%u.%u", ipHeadWithPayload[16],
                          ipHeadWithPayload[17], ipHeadWithPayload[18],
                          ipHeadWithPayload[19]);
                  printf("IP Destination : %s  \n", ipDestTemp);
                  unsigned char ipSourceTemp[7];
                  memset(ipSourceTemp, '\0', 7);
                  sprintf(ipSourceTemp, "%u.%u.%u.%u", ipHeadWithPayload[12],
                          ipHeadWithPayload[13], ipHeadWithPayload[14],
                          ipHeadWithPayload[15]);

                  printf("IP Source  : %s  \n", ipSourceTemp);
          */
				uint8_t  message[500];
				memset(message,'\0',500);
				memcpy(message,ipHeadWithPayload,ipPacketSize);
				int i;
				//for (i=0; i<ipPacketSize; i++) printf("\n i = %d  %02x:\n",i, ipHeadWithPayload[i]);


				printf("\n MessageCount=%d  ",++count);
				printf("MessageTime=%s  ",message);
				char* temp = time_stamp();

				struct timeval currentTime;
				gettimeofday(&currentTime, NULL);
				unsigned long int timel = currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;

				printf("CurrentTimeStamp=%lu", timel);
				time(&end_t);
				double diff = difftime(end_t,start_t);
				//printf("Time Elapsed = %f\n", diff);
				//printf("Time Elapsed = %lu\n", diff/1000000);

			}


		}
	}

}

char* time_stamp(){

	char *timestamp = (char *)malloc(sizeof(char) * 16);
	time_t ltime;
	ltime=time(NULL);
	struct tm *tm;
	tm=localtime(&ltime);
	timestamp = asctime(tm);
//sprintf(timestamp,"%04d%02d%02d%02d%02d%02d", tm->tm_year+1900, tm->tm_mon,
	//  tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
	return timestamp;
}

void print_hex(const char *s,int size)
{
	printf("\n HEX FORMAT size is %d\n",size);
	int i =0;
	while(i<size){
		printf("%02x", (unsigned char) *(s+i));
		i++;}

	printf("\n");
}
