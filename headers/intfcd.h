#ifndef INTFCD_H_
#define INTFCD_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <signal.h>

#include <getopt.h>
extern char * optarg;
extern int optind;

static const char * const help_str = 
          "Usage: cli_process [options]...\n"
          "Options: \n"
          "--start, -r                packets are being sniffed from now on from default iface(eth0)\n"
          "--stop, -p                 packets are not sniffed\n"
          "--show, -w [ip]            count print number of packets received from ip address\n"
          "--select, -s [iface]       select interface for sniffing eth0, wlan0, ethN, wlanN...\n"
          "--stat, -t [iface]         show all collected statistics for particular interface,\n"
          "                           if iface omitted - for all interfaces\n"
          "--help, -h                 show usage information\n";
 

int FindPidDaemon(void);
void StopDaemon(void);
void StartDaemon(void);
void StatDaemon(const char *);
void ShowPacketsIPDaemon(const char *);
void SelectDeviceDaemon(const char *);
void PrintOptionsInfo(void);

#endif