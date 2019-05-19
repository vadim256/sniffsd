#include "../headers/coloroutput.h"
#include "../headers/sniffsd.h"

void NetData::AddPacket(const std::string & address_ip){
	auto search = packets_m.find(address_ip);
	if(search != packets_m.end()){
		packets_m[address_ip] += 1;
	} else {
		packets_m.insert(std::pair<std::string, std::size_t>(address_ip, 1));
	}
}

int NetData::FindPacket(const std::string & address_ip){
	auto it = packets_m.find(address_ip);
	if(it != packets_m.end()){
		return (int)it->second;
	}
	return -1;
}
NetData::Packets  NetData::GetPackets() const { return packets_m; }

void NetData::InsertPacket(const NetData::Packet & packets){
	packets_m.insert(packets);
}

static int statusLoop = 0;
static std::string currname;

int main(void){

	pid_t pid = fork();

	if(pid == -1){
		fprintf(stderr, "[error] failed to create process\n");
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
	
	NameDevices devs;
	CountDevices(devs);
	currname = devs.front();
	int master = SocketSettings();
	if(master == -1){
		return;
	}
	Slaves SlaveSockets;
	NetDevices Devices;

	static char buffer[BSIZE];
	pcap_t * handler = 0;
	
	while(1){
		
		fd_set Set;
		FD_ZERO(&Set);
		FD_SET(master, &Set);

		for(auto Iter = SlaveSockets.begin(); Iter != SlaveSockets.end(); ++Iter){
			FD_SET(*Iter, &Set);
		}

		int Max = std::max(master, *std::max_element(SlaveSockets.begin(), SlaveSockets.end()));
		select(Max+1, &Set,NULL,NULL,NULL);

		for(auto Iter = SlaveSockets.begin(); Iter != SlaveSockets.end(); ++Iter){
			if(FD_ISSET(*Iter, &Set)){
				int RecvSize = recv(*Iter, buffer, BSIZE, MSG_NOSIGNAL);
				if(RecvSize == 0 && errno != EAGAIN){
					shutdown(*Iter, SHUT_RDWR);
					close(*Iter);	
					SlaveSockets.erase(Iter);
				} else if(RecvSize != 0){

						buffer[RecvSize] = '\0';
						char * str = strtok(buffer, " ");

						if(strcmp(str, START) == 0){
							handler = JoinInterface(devs, NETHERNET);
							if(!handler){
								fprintf(stderr,"Unable to join the interface\n");					
								return;
							}
							statusLoop = 1;

						} else if(strcmp(str, STAT) == 0){
							if(strcmp(buffer, STAT) == 0){
								for(auto d : Devices){
									sprintf(buffer, "Device: %s\n IP Addresses\tCounts\n", d.first.c_str());
									send(*Iter, buffer, strlen(buffer)+1, MSG_NOSIGNAL);
									for(auto it : d.second.GetPackets()){
										sprintf(buffer, "%s : %zd", it.first.c_str(), it.second);
										send(*Iter, buffer, strlen(buffer)+1, MSG_NOSIGNAL);
									}
								}
								shutdown(*Iter, SHUT_RDWR);
								close(*Iter);
								SlaveSockets.erase(Iter);	
							} else {
								int i;
								for(i = 0; buffer[i] == str[i] && str[i] != '\0'; ++i)
									;
								std::string str_name = buffer+i+1;
								auto now = Devices.find(str_name);
								if(now != Devices.end()){
									sprintf(buffer, "Device: %s\n IP Addresses\tCounts\n", str_name.c_str());
									send(*Iter, buffer, strlen(buffer)+1, MSG_NOSIGNAL);
									for(auto it : Devices[str_name].GetPackets()){
										sprintf(buffer, "%s : %zd", it.first.c_str(), it.second);
										send(*Iter, buffer, strlen(buffer)+1, MSG_NOSIGNAL);
									}
									shutdown(*Iter, SHUT_RDWR);
									close(*Iter);
									SlaveSockets.erase(Iter);							
								}
							}							
						} else if(strcmp(str, STOP) == 0){							
							statusLoop = 0;
						} else if(strcmp(str, SELECT) == 0){
							int i;
							for(i = 0; buffer[i] == str[i] && str[i] != '\0'; ++i)
								;
							std::string str_name = buffer+i+1;
							handler = JoinInterface(devs, str_name.c_str());
							if(!handler){
								fprintf(stderr, "Unable to join the interface\n");
							} 
						} else if(strcmp(str, SHOW) == 0){
							int i;
							for(i = 0; buffer[i] == str[i] && str[i] != '\0'; ++i)
								;
							std::string str_ip = buffer+i+1;
							int tmp;
							std::string dname;
							bool isFind = false;
							for(auto it : Devices){
								tmp = it.second.FindPacket(str_ip);
								if(tmp > 0){
									dname = it.first;
									isFind = true;
									break;
								}
							}
							if(isFind){
								sprintf(buffer, "Devices %s, IP  %s, Count = %d\n",dname.c_str(), str_ip.c_str(), tmp);
								send(*Iter, buffer, strlen(buffer)+1, MSG_NOSIGNAL);
							} else {
								sprintf(buffer, "This IP %s, not found\n", str_ip.c_str());
								send(*Iter, buffer, strlen(buffer)+1, MSG_NOSIGNAL);
							}
							shutdown(*Iter, SHUT_RDWR);
							close(*Iter);
							SlaveSockets.erase(Iter);							
						}
				}	
			}
		}
		if(FD_ISSET(master, &Set)){
			int slave = accept(master, 0,0);
			SlaveSockets.insert(slave);
		}
		if(statusLoop){
		
			struct pcap_pkthdr header;
		
			u_char *packet = (u_char*) pcap_next(handler, &header);		
			if(!packet){
				;
			} else {
				const struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
				int size_ip = IP_HL(ip)*4;
				if (size_ip < 20) ;
				else Devices[currname].AddPacket(inet_ntoa(ip->ip_src));
			}
		}
	}
}

void CountDevices(NameDevices & devs) {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t * alldevsp;
	if(pcap_findalldevs(&alldevsp, errbuf)){
		perror("pcap_findalldevs");		
		return;
	}
	pcap_if_t * device = NULL;
	for(device = alldevsp; device; device = device->next)
		if(device->name != NULL)
			devs.push_back(device->name);
}

int SocketSettings(void){
	int master = socket(AF_INET, SOCK_STREAM , IPPROTO_TCP);
	if(master == -1){
		perror("socket");
		return -1;
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(12345);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(master, (struct sockaddr *)&addr, sizeof(addr)) == -1){
		perror("bind");		
		return -1;
	}
	if(listen(master, SOMAXCONN) == -1){
		perror("listen");		
		return -1;
	}
	set_nonblock(master);
	int optval = 1;
	if(setsockopt(master, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1){
		perror("setsockopt");		
		return -1;
	}
	return master;
}

pcap_t *JoinInterface(NameDevices & devs, const char * interface){
	pcap_t * handler = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	bool isOk = false;
	for(auto it : devs)
		if(it == interface){
			currname = interface;
			handler = pcap_open_live(interface, BUFSIZ, 1, 10000, errbuf);
			isOk = true;
			break;
		}
	if(!isOk){
		 handler = pcap_open_live(currname.c_str(), BUFSIZ, 1, 10000, errbuf);
	}
	
	return handler;
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