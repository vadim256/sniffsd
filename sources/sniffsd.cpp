#include "../headers/coloroutput.h"
#include "../headers/sniffsd.h"

static char devs[N][M];
static sig_atomic_t statusLoop = 0, statusPrev = 0;
int main(void){

	pid_t pid = fork();

	if(pid == -1){
		fprintf(stderr, AC_RED"[error] failed to create process\n"AC_RESET);
		exit(1);
	}
	if(pid == 0){
		chdir(ROOT_DIR);
		setsid();		
		Daemon();
	}
	return 0;
}

void Daemon(void) { 
	
	SavePid();
	CountDevices();
	
	signal(SIGUSR1, StopLoopHandler);

	int master = SocketSettings();
	if(master == -1){
		return;
	}
	
	static char buffer[BSIZE];
	pcap_t * handler = 0;
	while(1){
		int slave = accept(master, NULL, NULL);
		ssize_t bytes = recv(slave, buffer, BSIZE, MSG_NOSIGNAL);
		if(bytes > 0)
			buffer[bytes] = '\0';
			char * str = strtok(buffer, " ");
		if(strcmp(str, START) == 0){
			handler = JoinInterface(NETHERNET);
			if(!handler){
				fprintf(stderr, AC_RED"Unable to join the interface\n"AC_RESET);
				return;
			}
			statusLoop = 1;
			
		} else if(strcmp(str, STAT) == 0){
			char buffer[BSIZE];
			if(strcmp(buffer, STAT) == 0)
			if(statusPrev == 1)
				statusLoop = 1;		
		}	


		u_char * packet = 0;
		struct pcap_pkthdr header;
	
		for(;statusLoop;){
			
			bytes = recv(slave, buffer, BSIZE, MSG_NOSIGNAL);
			if(bytes > 0){
				buffer[bytes] = '\0';
				char * str = strtok(buffer, " ");
				if(strcmp(str, STOP) == 0){
					statusLoop = 0;
				}
			}

			packet = (u_char*) pcap_next(handler, &header);		
			if(!packet) continue;

			const struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			int size_ip = IP_HL(ip)*4;
			if (size_ip < 20) continue;

		}
	}
}

void CountDevices() {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t * alldevsp;

	if(pcap_findalldevs(&alldevsp, errbuf)){
		perror(AC_RED"pcap_findalldevs");
		fprintf(stderr,""AC_RESET);
		return;
	}

	pcap_if_t * device = NULL;
	int count = 0;

	FILE * devices = fopen("/.listdevices.txt", "w+");
	bool flag = true;
	if(!devices) flag = false;
	
	for(device = alldevsp; device; device = device->next, ++count){
		if(device->name != NULL && count < N)
			strcpy(devs[count], device->name);
		if(flag) fprintf(devices, "%s\n", devs[count]);
	}
	if(flag) fclose(devices);
}

int SocketSettings(void){
	int master = socket(AF_INET, SOCK_STREAM , IPPROTO_TCP);
	if(master == -1){
		perror(AC_RED"socket");
		printf(""AC_RESET);
		return -1;
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(12345);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(master, (struct sockaddr *)&addr, sizeof(addr)) == -1){
		perror(AC_RED"bind");
		printf(""AC_RESET);
		return -1;
	}
	if(listen(master, SOMAXCONN) == -1){
		perror(AC_RED"listen");
		printf(""AC_RESET);				
		return -1;
	}
	//set_nonblock(master);
	int optval = 1;
	if(setsockopt(master, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1){
		perror(AC_RED"setsockopt");
		printf(""AC_RESET);				
		return -1;
	}
	return master;
}

void DefineCommand(char * command, int slave, pcap_t * handler) {
		
	 /*else if(strcmp(str, SELECT) == 0){
		int i;
		for(i = 0; str[i] == command[i]; ++i)
			;
		pcap_t * tmph = JoinInterface(command+i+1);
		if(!handler){
			fprintf(stderr, AC_RED"Unable to join the interface\n"AC_RESET);
			statusLoop = 1;
			return;
		}
		handler = tmph;
		statusLoop = 1;
		int x;
		if((x = SearchDName(command+i+1)) == -1){
			strcpy(dname[currindex], command+i+1);
			currindex = maxindex;
			maxindex++;
		} else currindex = x;
		
		statusLoop = 1;
		SniffsPackets(handler);

	}  else if(strcmp(str, SHOW) == 0){
		int i;
		for(i = 0; str[i] == command[i]; ++i)
			;
		Data d;
		strcpy(d.address_ip, command+i+1);
		d.count_ip = 1;
		for(int i = 0; i < maxindex; ++i){
			node * tmp = root[i];
			node * f = NULL;
			if((f = search(tmp, d)) != NULL){
				char sb[BSIZE];
				sprintf(sb,"Device: %s, IP: %s, Count: %d", dname[i], f->key.address_ip, f->key.count_ip);
				send(slave, sb, strlen(sb), MSG_NOSIGNAL);
			}
		}
		statusLoop = 1;
		SniffsPackets(handler);
	}
	*/
}

pcap_t *JoinInterface(const char * interface){
	pcap_t * handler = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	bool isOk = false;
	for(int i = 0; i < N; ++i)
		if(strcmp(devs[i], interface) == 0){
			handler = pcap_open_live(interface, BUFSIZ, 1, 10000, errbuf);
			isOk = true;
			break;
		}
	if(!isOk) handler = pcap_open_live(devs[0], BUFSIZ, 1, 10000, errbuf);
	
	return handler;
}


void StopLoopHandler(int val){
	statusPrev = statusLoop;
	statusLoop = 0;
}

int set_nonblock(int fd){
	int flags;
#if defined(O_NONBLOCK)
	if((flags = fcntl(fd, F_GETFL,0)) == -1)
		flags = 0;
	return fcntl(fd, F_SETFL, flags|O_NONBLOCK);
#else 
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

int SavePid(void) {
	static int once_file = 0;
	if(once_file == 0){
		FILE * tmp = fopen("/.pid_daemon.txt", "w+");
		if(tmp != NULL) {
			fprintf(tmp,"%d", getpid());
			++once_file;
			fclose(tmp);
			return 0;
		} else return -1;
	}
}
