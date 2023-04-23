// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */

#include <linux/err.h>
#include <test_progs.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf_bbr.skel.h"
#include "bpf_cubic.skel.h"
#include <stdio.h>  
#include <stdlib.h>  
#include <fcntl.h>  
#include <string.h> 
#include <errno.h>
#include <unistd.h>  
#include <sys/types.h>  
#include <sys/ipc.h>  
#include <sys/msg.h> 

#define min(a, b) ((a) < (b) ? (a) : (b))
#define MAX_TEXT 512  
#define BUFSIZE BUFSIZ  
//static const unsigned int total_bytes = 10 * 1024 * 1024;
//static const struct timeval timeo_sec = { .tv_sec = 10 };
//static const size_t timeo_optlen = sizeof(timeo_sec);
//static int expected_stg = 0xeB9F;
//static int stop;
static int duration;
struct bpf_cubic *cubic_skel;
struct bpf_bbr *bbr_skel;
struct msg_st {  
     long num;  
     char mtext[BUFSIZ];  
};  
struct flow_param{
	long target_rate;
	int player_type; 
	int mode;
};


static void splict(int *result, char* str){
	char *param = NULL;
	char d[]="#";
	param = strtok(str, d);
	int count=0;
	while( param != NULL && count<3)
	{
		printf( "result is \"%s\" count:%d \n", param ,count);
		result[count] = atoi(param);
		param = strtok( NULL, d);
		count++;
	}
}

static void do_mytest(){
	int result = system("sysctl -p");
	CHECK(result==0, "system","err:%d \n", result);
	int count=0;
	while(1){
	 	int msgid1;  
        struct msg_st recv_data;  
        int msg_to_recevie = 0;  
        if((msgid1= msgget((key_t)1,0666|IPC_CREAT)) == -1)  
        {  
            perror("msgget");  
            exit(EXIT_FAILURE);  
        }         
        if(msgrcv(msgid1,(void *) &recv_data, BUFSIZ, msg_to_recevie , 0) == -1)  
        {  
            perror("msgrcv");  
            exit(EXIT_FAILURE);  
        } 

        printf("recevier mssage : %s, type= %ld;\n", recv_data.mtext, recv_data.num);  
		int param[]={0,0,0};
		splict(param, recv_data.mtext);
		printf("1:%d,2:%d ,3:%d",param[0],param[1],param[2]);
	  
        if(msgctl(msgid1,IPC_RMID,0) == -1)  
        {  
            fprintf(stderr,"msgctl(IPC_RMID) failed \n");  
            exit(EXIT_FAILURE);  
        }
		
	}
}

static void test_bbr(void)
{
	
	struct bpf_link *link;

	bbr_skel = bpf_bbr__open_and_load();
	if (CHECK(!bbr_skel, "bpf_dctcp__open_and_load", "failed\n"))
		return;

	link = bpf_map__attach_struct_ops(bbr_skel->maps.bbr);
	if (CHECK(IS_ERR(link), "bpf_map__attach_struct_ops", "err:%ld\n",
		  PTR_ERR(link))) {
		bpf_bbr__destroy(bbr_skel);
		return;
	}

	do_mytest();

	bpf_link__destroy(link);
	bpf_bbr__destroy(bbr_skel);
}

void test_bpf_tcp_ca(void)
{
	CHECK(false,"enter test_bpf_tcp_ca","next test_bpf_tcp_ca");

	if (test__start_subtest("bbr"))
		test_bbr();
	
}
