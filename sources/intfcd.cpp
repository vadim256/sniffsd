
#include "../headers/intfcd.h"
#include "../headers/coloroutput.h"

static int master = 0;
int main(int argc, char ** argv){
	const struct option daemon_opts[] = {
        	{"start", no_argument, NULL, 'r'},
	 		{"stop", no_argument, NULL, 'p'},
	    	{"show", required_argument, NULL, 'w'},
	    	{"select", required_argument, NULL, 's'},
	    	{"stat", optional_argument, NULL, 't'},
	    	{"help", no_argument, NULL, 'h'},
			{"go", no_argument, NULL, 'g'},
	    	{NULL, 0, NULL, 0}
	};

	
	int current_option;
	while((current_option = getopt_long(argc, argv, "grpw:s:t:h", daemon_opts, NULL)) != -1){
		switch(current_option){			
			case 'r':					
				return StartDaemon();				
			case 'p':
				return StopDaemon();				
			case 'w':
				return ShowPacketsIPDaemon(optarg);
			case 's':
				return SelectDeviceDaemon(optarg);				
			case 't':
				return StatDaemon(optarg);				
			case 'h':
				PrintOptionsInfo();
				return 0;
			case 'g': 
				return CreateDaemon();
			case '?':
				PrintOptionsInfo();
				return 3;
		}
	}
    return 0;
}

int CreateDaemon(){
	int exit_status;
	int pid = fork();
	if(pid == -1){
		perror(AC_RED"fork");
		printf(""AC_RESET);
		return pid;
	}
	if(!pid){
		execl("./sniffsd","sniffsd", NULL);
		fprintf (stderr, AC_RED"Exec error\n"AC_RESET);
		return 1;
	} else {
		int childpid = wait(&exit_status);
		if (WIFEXITED (exit_status)) {
			printf(AC_GREEN "process started " AC_RED"[sniffsd]" AC_RESET AC_GREEN" with %d has exited with code=%d\n"AC_RESET,
					childpid+1, WEXITSTATUS (exit_status));
		}
		return 0;
	}	
}

int StopDaemon() {
	/*int pid = FindPidDaemon();
	if(pid > 0)
			kill(pid, SIGUSR1);
	else fprintf(stderr, AC_RED"Don`t find pid daemon\n"AC_RESET);*/
	if(!master){
		if(EstablishToConnection(&master) == -1){
			return -1;
		}
	}
	const char * stop = "stop";
	SendDaemonCommand(stop, NULL);

}

int StartDaemon() {
	if(!master){
		if(EstablishToConnection(&master) == -1){
			return -1;
		}
	}
	const char * start = "start eth0";
	SendDaemonCommand(start, NULL);
	return 0;
}

int StatDaemon(const char * device) {
	if(!master){
		if(EstablishToConnection(&master) == -1){
			return -1;
		}
	}
	int pid = FindPidDaemon();
		if(pid > 0)
			kill(pid, SIGUSR1);
	else fprintf(stderr, AC_RED"Don`t find pid daemon\n"AC_RESET);
	const char *stat = "stat ";
	SendDaemonCommand(stat, device);
	
	static char buffer[BUF_SIZE];
	ssize_t bytes;
	while((bytes = recv(master, buffer, BUF_SIZE, MSG_NOSIGNAL)) > 0){
		buffer[bytes] = '\0';
		fprintf(stdout, AC_GREEN "%s\n" AC_RESET, buffer);
	}		
	return 0;
}

int ShowPacketsIPDaemon(const char * ip) {
	if(!master){
		if(EstablishToConnection(&master) == -1){
			return -1;
		}
	}
	if(ip == NULL){
		fprintf(stderr, AC_RED"IP address not entered\n" AC_RESET);		
		return 4;
	}
	int pid = FindPidDaemon();
		if(pid > 0)
			kill(pid, SIGUSR1);
	else fprintf(stderr, AC_RED"Don`t find pid daemon\n"AC_RESET);

	const char * show = "show ";
	SendDaemonCommand(show, ip);
	static char buffer[BUF_SIZE];
	ssize_t bytes = recv(master, buffer, BUF_SIZE, MSG_NOSIGNAL);
	buffer[bytes] = '\0';
	fprintf(stdout, AC_GREEN"%s\n" AC_RESET, buffer);
	return 0;
}

int SelectDeviceDaemon(const char * device) {
	if(!master){
		if(EstablishToConnection(&master) == -1){
			return -1;
		}
	}

	if(device == NULL){
		fprintf(stderr, AC_RED"Device name not entered\n" AC_RESET);		
		return 5;
	}
	int pid = FindPidDaemon();
		if(pid > 0)
			kill(pid, SIGUSR1);
	else fprintf(stderr, AC_RED"Don`t find pid daemon\n"AC_RESET);
	
	const char * select = "select ";
	SendDaemonCommand(select, device);
	return 0;
}

void PrintOptionsInfo(void) {
		fprintf(stderr, AC_GREEN "%s" AC_RESET, help_str);
		return;
}

int SendDaemonCommand(const char * command, const char * opt){

	char buffer[BUF_SIZE];
	strcpy(buffer, command);
	if(opt)
		strcat(buffer, opt);
	return send(master, buffer, strlen(buffer), MSG_NOSIGNAL);
}

int EstablishToConnection(int * master){
	*master = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(*master == -1){
		perror(AC_RED"socket");
		printf(""AC_RESET);
		return -1;
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(12345);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(connect(*master, (struct sockaddr *) &addr, sizeof(addr)) == -1){
		perror(AC_RED"connect");
		printf(""AC_RESET);
		return -1;
	}
	return 0;
}
int FindPidDaemon(void) {
		FILE * tmp = fopen("/.pid_daemon.txt", "r+");
		if(tmp == NULL){
			perror("fopen");
			return -1;
		}
		char buffer[128];
		fgets(buffer, 128, tmp);
		fclose(tmp);

		int daemon_pid = atoi(buffer);
		if(daemon_pid <= 0)
			return -1;
		else return daemon_pid;
}