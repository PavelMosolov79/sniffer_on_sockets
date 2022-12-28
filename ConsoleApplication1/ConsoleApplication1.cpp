#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <WinSock2.h>
#include <mstcpip.h>
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")


struct sockaddr_in dest, sourse;


typedef struct ip_hdr
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;

	unsigned char ip_frag_offset : 5;

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1;

	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;
} IPV4_HDR;


IPV4_HDR* iphdr;

int main() {
	//Инициализировать Winsock////////
	WSADATA WinSockInitialising;	//
	//////////////////////////////////


	//Создать сокет TCP///
	SOCKET NewSocket;	//
	//////////////////////
	

	//IPv4////////////////////
	struct in_addr addr {};	//
	//////////////////////////

	printf("*----------------------------------------*\n");

	// 1 | Проверка на инициализацию WinSock//////////////////////////
	printf("|%40s|\n", "Initialising Winsock...");					//
																	//
	if (WSAStartup(MAKEWORD(2, 2), &WinSockInitialising) != 0) {	//
		printf("Failed. Error Code: %d", WSAGetLastError());		//
		return 1;													//
	}																//
																	//
	printf("|%40s|\n", "Initialised!");								//
	//////////////////////////////////////////////////////////////////

	printf("|----------------------------------------|\n");

	// 2 | Проверка на создание Socket////////////////////////////////////////////////////
	printf("|%40s|\n", "Creating socket...");											//
																						//
	NewSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);									//
																						//
	if (NewSocket == INVALID_SOCKET) {													//	AF_INET - IPv4 семейство адрессов
		printf("Failed. Error Code: %d", WSAGetLastError());							//	SOCK_STREAM - TCP тип протокола
		return 2;																		//	IPPROTO_IP - протокол
	}																					//
																						//
	printf("|%40s|\n", "Socket created!");												//
	//////////////////////////////////////////////////////////////////////////////////////

	printf("|----------------------------------------|\n");

	// 3 | Получение локального имени/////////////////////////////////////////
	printf("|%40s|\n", "Geting hostname...");								//
																			//
	char HostName[20];														//
																			//
	if (gethostname(HostName, sizeof(HostName)) == SOCKET_ERROR) {			//
		printf("Failed. Error Code: %d", WSAGetLastError());				//
		return 3;															//
	}																		//
																			//
	printf("|%40s|\n", "Hostname receives!");								//
	//////////////////////////////////////////////////////////////////////////

	printf("|----------------------------------------|\n");

	// 4 | Получение доступных IP-адресов/////////////////////////////////////////
	printf("|%40s|\n", "Getting Ip-addresses...");								//
																				//
	struct hostent* LocalAdres;													//
																				//
	LocalAdres = gethostbyname(HostName);										//
	if (LocalAdres == NULL) {													//
		printf("Failed. Error Code: %d", WSAGetLastError());					//
		return 4;																//
	}																			//
																				//
	for (int i = 0; LocalAdres->h_addr_list[i] != 0; ++i)						//
	{																			//
		memcpy(&addr, LocalAdres->h_addr_list[i], sizeof(struct in_addr));		//
	}																			//
																				//
	int NumOfInterface = 0;														//
																				//
	printf("|%40s|\n", "IP addresses received!");								//
	//////////////////////////////////////////////////////////////////////////////

	printf("|----------------------------------------|\n");

	// 5 | Привязка сокета к локальной системе и нулевому порту///////////////////////////////////////////////////
	printf("|%40s|\n", "Binding socket...");																	//
																												//
	memset(&dest, 0, sizeof(dest));																				//
	memcpy(&dest.sin_addr.s_addr, LocalAdres->h_addr_list[NumOfInterface], sizeof(dest.sin_addr.s_addr));		//
	dest.sin_family = AF_INET;																					//
	dest.sin_port = 0;																							//
																												//
	if (bind(NewSocket, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {								//
		printf("Failed. Error Code: %s", inet_ntoa(addr));														//
		return 5;																								//
	}																											//
																												//
	printf("|%40s|\n", "Bind socket successful!");																//
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////

	printf("|----------------------------------------|\n");

	// 6 | Настройка сокета под снифер////////////////////////////////////////////////////////////////////////////////////////////////////////
	printf("|%40s|\n", "Setting socket to snifer...");																						//
																																			//
	int lpv_cb_Buffer = 1;																													//
																																			//
	if (WSAIoctl(NewSocket, SIO_RCVALL, &lpv_cb_Buffer, sizeof(lpv_cb_Buffer), 0, 0, (LPDWORD) &NumOfInterface, 0, 0) == SOCKET_ERROR) {	//
		printf("\nWSAIoctl() failed");																										//
		return 6;																															//
	}																																		//
																																			//
	printf("|%40s|\n", "Settings successful!");																								//
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	printf("|----------------------------------------|\n");

	// 7 | Получение сообщений из сокета//////////////////////////////////////////////////////////////////////////////////////////
	printf("|%40s|\n", "Receiving messages from a socket...");																	//
	printf("|                                        *----------------------------------------*\n");							//
																																//
	char *BufRec = (char *)malloc(65536);																						//
	int message = 1;																											//
	int TotalProtocol = 0;																										//
																																//
	if (BufRec == NULL)																											//
	{																															//
		printf("Malloc() failed.\n");																							//
		return 7;																												//
	}																															//
																																//
	printf("|%10s|%20s|%20s|%4s|%10s|%10s|\n","Protocol", "Source IP", "Destination IP", "TTL", "Total Length", "Checksum");	//
																																//
	while (!_kbhit()) {																											//
		message = recvfrom(NewSocket, BufRec, 65536, 0, 0, 0);																	//
																																//
		if (message == 0) {																										//
			printf("\nReceiving messages from a socket failed");																//
		}																														//
		else {																													//
			iphdr = (IPV4_HDR*)BufRec;																							//
			++TotalProtocol;																									//
																																//
			int chek = iphdr->ip_protocol;																						//
																																//
			if (chek == 1) {																									//
				memset(&sourse, 0, sizeof(sourse));																				//
				sourse.sin_addr.s_addr = iphdr->ip_srcaddr;																		//
																																//
				memset(&sourse, 0, sizeof(sourse));																				//
				sourse.sin_addr.s_addr = iphdr->ip_destaddr;																	//
																																//
				printf("|%10s|%20s|%20s|%4d|%10d|%10d|\n", "ICMP", inet_ntoa(sourse.sin_addr), inet_ntoa(dest.sin_addr),		//
					(unsigned int)iphdr->ip_ttl, ntohs(iphdr->ip_total_length), ntohs(iphdr->ip_checksum) );					//
			}																													//
			else if (chek == 6) {																								//
				memset(&sourse, 0, sizeof(sourse));																				//
				sourse.sin_addr.s_addr = iphdr->ip_srcaddr;																		//
																																//
				memset(&sourse, 0, sizeof(sourse));																				//
				sourse.sin_addr.s_addr = iphdr->ip_destaddr;																	//
																																//
				printf("|%10s|%20s|%20s|%4d|%12d|%10d|\n", "TCP", inet_ntoa(sourse.sin_addr), inet_ntoa(dest.sin_addr),			//
					(unsigned int)iphdr->ip_ttl, ntohs(iphdr->ip_total_length), ntohs(iphdr->ip_checksum));						//
			}																													//
			else if (chek == 17) {																								//
				memset(&sourse, 0, sizeof(sourse));																				//
				sourse.sin_addr.s_addr = iphdr->ip_srcaddr;																		//
																																//
				memset(&sourse, 0, sizeof(sourse));																				//
				sourse.sin_addr.s_addr = iphdr->ip_destaddr;																	//
																																//
				printf("|%10s|%20s|%20s|%4d|%12d|%10d|\n", "UDP", inet_ntoa(sourse.sin_addr), inet_ntoa(dest.sin_addr),			//
					(unsigned int)iphdr->ip_ttl, ntohs(iphdr->ip_total_length), ntohs(iphdr->ip_checksum));						//
			}																													//
			else {																												//
				memset(&sourse, 0, sizeof(sourse));																				//
				sourse.sin_addr.s_addr = iphdr->ip_srcaddr;																		//
																																//
				memset(&sourse, 0, sizeof(sourse));																				//
				sourse.sin_addr.s_addr = iphdr->ip_destaddr;																	//
																																//
				printf("|%10s|%20s|%20s|%4d|%12d|%10d|\n", "ELSE", inet_ntoa(sourse.sin_addr), inet_ntoa(dest.sin_addr),		//
					(unsigned int)iphdr->ip_ttl, ntohs(iphdr->ip_total_length), ntohs(iphdr->ip_checksum));						//
			}																													//
		}																														//
	}																															//
																																//
	printf("|                                        *----------------------------------------*\n");							//
	printf("|%40s|\n", "Receiving messages is finished!");																		//
	printf("|%35s:%4d|\n", "Total Protocol", TotalProtocol);																	//
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	printf("|----------------------------------------|\n");

	// 8 | Очистка буфера, сокета и библиотеки////////////////////////////////
	printf("|%40s|\n", "Clearing the buffer, socket...");					//
																			//
	free(BufRec);															//
	closesocket(NewSocket);													//
	WSACleanup();															//
																			//
	printf("|%40s|\n", "Cleaning is finished!");							//
	//////////////////////////////////////////////////////////////////////////

	printf("*----------------------------------------*\n");


	return 0;
}