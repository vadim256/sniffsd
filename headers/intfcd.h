#ifndef INTFCD_H_
#define INTFCD_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include <signal.h>

extern char * optarg;
extern int optind;
#define BUF_SIZE 1024

static const char * const help_str = 
          "Usage: intfcd [options]...\n"
          "Options: \n"
          "--go, -g                   run the background process [sniffsd]\n"
          "--start, -r                packets are being sniffed from now on from default iface(eth0)\n"
          "--stop, -p                 packets are not sniffed\n"
          "--show, -w [ip]            count print number of packets received from ip address\n"
          "--select, -s [iface]       select interface for sniffing eth0, wlan0, ethN, wlanN...\n"
          "--stat, -t [iface]         show all collected statistics for particular interface,\n"
          "                           if iface omitted - for all interfaces\n"
          "--help, -h                 show usage information\n";
 

int StopDaemon();
int StartDaemon();

int StatDaemon(const char *);
int ShowPacketsIPDaemon(const char *);
int SelectDeviceDaemon(const char *);

void PrintOptionsInfo(void);
int SendDaemonCommand(const char *, const char*);
int EstablishToConnection(int *);
int CreateDaemon(void);
int FindPidDaemon(void);

#endif