
#include "headers/intfcd.h"
#include "headers/coloroutput.h"



int main(int argc, char ** argv){
	const struct option daemon_opts[] = {
        	{"start", no_argument, NULL, 'r'},
	 	{"stop", no_argument, NULL, 'p'},
	    	{"show", required_argument, NULL, 'w'},
	    	{"select", required_argument, NULL, 's'},
	    	{"stat", required_argument, NULL, 't'},
	    	{"help", no_argument, NULL, 'h'},
	    	{NULL, 0, NULL, 0}
	};

	int current_option;
	while((current_option = getopt_long(argc, argv, "r:pw:s:t:h", daemon_opts, NULL)) != -1){
		switch(current_option){			
			case 'r':					
				StartDaemon();
				return 0;
			case 'p':
				StopDaemon();
				return 0;
			case 'w':
				ShowPacketsIPDaemon(optarg);
				return 0;
			case 's':
				SelectDeviceDaemon(optarg);
				return 0;
			case 't':
				StatDaemon(optarg);
				return 0;
			case 'h':
				PrintOptionsInfo();
				return 0;
			case '?':
				PrintOptionsInfo();
				return 3;
		}
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

void StopDaemon(void) {
		int pid = FindPidDaemon();
		if(pid > 0)
			kill(pid, SIGUSR1);
		else fprintf(stderr, "Don`t find pid daemon\n");

}

void StartDaemon(void) {
		int pid = FindPidDaemon();
		if(pid > 0)
				kill(pid, SIGUSR2);
		else fprintf(stderr, "Don`t find pid daemon\n");
}

void StatDaemon(const char * device) {
	int pid = FindPidDaemon();
	if(pid > 0)
		kill(pid, SIGHUP);
	else fprintf(stderr, "Don`t find pid daemon\n");

	sleep(1);
	FILE * stat = fopen("/.stat.txt", "r+");
	if(stat == NULL){
		perror("fopen");
		return;
	}
	char buffer[1024];
	int i = 0;
	while(fgets(buffer, 1023, stat) != NULL){
		if(i == 1)
			fprintf(stdout, AC_RED "IP Address\t  Count Packets\n" AC_RESET);
		fprintf(stdout, AC_YELLOW"%s", buffer);
		++i;
	}
	fprintf(stdout, "" AC_RESET);
	fclose(stat);
}

void ShowPacketsIPDaemon(const char * ip) {
	if(ip == NULL){
		fprintf(stderr, AC_RED"IP address not entered\n" AC_RESET);		
		return;
	}
	int pid = FindPidDaemon();
	if(pid > 0)
		kill(pid, SIGHUP);
	else fprintf(stderr, "Don`t find pid daemon\n");

	sleep(1);
	FILE * stat = fopen("/.stat.txt", "r+");
	if(stat == NULL){
		perror("fopen");
		return;
	}
	char buffer[1024];
	int i = 0;
	while(fgets(buffer, 1023, stat) != NULL){
		if(i == 1)
			fprintf(stdout, AC_RED "IP Address\t  Count Packets\n" AC_RESET);
		if(strstr(buffer, ip) != NULL)
			fprintf(stdout, AC_BLUE"%s", buffer);
		++i;
	}
	fprintf(stdout, "" AC_RESET);
	fclose(stat);
}

void SelectDeviceDaemon(const char * device) {

}

void PrintOptionsInfo(void) {
		fprintf(stderr, AC_GREEN "%s", help_str);
		fprintf(stdout, ""AC_RESET);
		return;
}