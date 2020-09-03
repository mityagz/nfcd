#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <locale.h>
#include <wait.h>
#include <sys/prctl.h>
#include "nfc.h"

#define SIZE_FLOW	48
#define SIZE_HEADER	24
#define SIZE_COUNT	4


main(int argc, char **argv) {
// 1 ip_address 2 portnum 3 table
   int f_dom, bd, i_port = 9991, rc = 0, nsid, rec, flag = 0, len = 30, i, j, cmd, addr_len, stat, all = 0, strn = 0;
   struct sockaddr_in *addr;
   struct sockaddr_in *rmt_addr;
   struct in_addr *b_addr;
   char *i_addr = "127.0.0.1";
   fd_set select_set;
   struct timeval timeRec;
   char *buf,*buf1,*buf_send;
   char *send_buf = "Hello it's UDP server\n";
   char *base_buffer,*log, *table = *(argv + 3);
   time_t time_log;
   struct tm *time_log_tm = (struct tm *)malloc(sizeof(struct tm));
   count_entry = 0, count_entry1 = 0, count_entry2 = 0, cnt_data = 0, count_end = 0, count_all = 0;
   setlocale(LC_CTYPE,"C");
   time_log = time(NULL);
   time_log_tm = localtime(&time_log);
   LogMessage("nfcd", "Starting collector ... Time: %d:%d:%d %d-%d-%d",
	time_log_tm->tm_hour, time_log_tm->tm_min, time_log_tm->tm_sec,
        time_log_tm->tm_mday, time_log_tm->tm_mon + 1, time_log_tm->tm_year+1900);
   LogMessage("nfcd", "PID: %d  UID: %d", getpid(), getuid());
   
   flush = 0;
   if(daemon(0,1) == 1){
   	printf("Fault to background\n");
   };
   signal(SIGALRM, sig_proc);
   alarm(1800);
      printf("%d\n",flush);
   b_addr = (struct in_addr *)malloc(sizeof(struct in_addr));
   addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
   rmt_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
   buf = (char *)malloc(2000*sizeof(char));
   buf_send = (char *)malloc(2000*sizeof(char));
   bzero(addr, sizeof(struct sockaddr_in));
   printf("Address %d  %s %d\n", inet_aton(i_addr, b_addr), i_addr, b_addr);
   addr->sin_family = AF_INET;  
   addr->sin_port = htons(i_port);
	printf("Addr: %s\n", i_addr);
   addr->sin_addr.s_addr = b_addr->s_addr;
   //memcpy(&(addr->sin_addr), b_addr, sizeof(struct in_addr *));
   f_dom=socket(AF_INET, SOCK_DGRAM, 0);
   if(f_dom == -1) {
     printf("Connect Failed\n");
     printf("%s\n",strerror(errno));
   } else {
     printf("Connect Ok, ");
     printf("Sid = %d\n", f_dom);
   }
  //for(i = i_port; i <= 65535; i++){
  //  addr->sin_port = htons(i_port + i);
	printf("Port: %d\n", (int)atoi(*(argv + 2)));
    addr->sin_port = htons((int)atoi(*(argv + 2)));
  if((bd = bind(f_dom, (struct sockaddr *)addr, sizeof(struct sockaddr))) >= 0) {
     printf("Bind Ok  %d\n", bd);
     printf("Port %d\n", i_port + i);
     //break;
   } else if(bd < 0) {
	printf("Bind ret: %d\n", bd);
     printf("Bind failed, ");
     printf("%s\n", strerror(errno));
   }
 //}

		if(data_collection==NULL)
			if((data_collection=(struct data_v5 **)malloc(200000*sizeof(struct data_v5 *)))==NULL){
			     printf("Error malloc\n");
			     exit(1);
		}
			 
      pid_t cpid, w;
      int wstatus;
   for(;;) {
      timeRec.tv_sec = 1;
      timeRec.tv_usec = 0;
      FD_ZERO(&select_set);
      FD_SET(f_dom, &select_set);
       rc = select(FD_SETSIZE,&select_set, 0, 0, &timeRec);
         if(rc > 0 && FD_ISSET(f_dom, &select_set)) {
	    addr_len = sizeof(struct sockaddr*);
	       while((stat=recvfrom(f_dom, buf, 2000, MSG_WAITALL, (struct sockaddr*) rmt_addr, &addr_len)) > 0 ) {
		  all += stat;
		  printf("Всего: %d байт\n", all);
		  head = (struct header *) malloc(sizeof(struct header));
		  head = head_parser(stat,buf, head);
		  printf("Версия NetFlow:  %d\n", head->version.b1);
		  printf("Число экспортированных потоков: %d\n", head->count.b1);
		  //Выделение памяти для каждого потока
		     data = (struct data_v5 **) malloc((head->count.b1) * sizeof(struct data_v5 *));
			for(i = 0; i < (head->count.b1); i++){
				*(data+i) = (struct data_v5 *) malloc(sizeof(struct data_v5));
				bzero(*(data + i), sizeof(struct data_v5));
			}
		  // Вычисление адресов начала блоков данных buf базовый адрес
		  // заголовок head 24 байта
		  // блок данных 48 байт
		      base_buffer = buf + SIZE_HEADER * sizeof(char);  // Пропускаем заголовок
		  //Вычисление адресов потоков
		      for(i = 0; i < (head->count.b1); i++) {
		         data_parser(base_buffer, *(data+i), i);
			 base_buffer += SIZE_FLOW * sizeof(char);
		      }
		      // Обработка входной стуктуры
		      //       analyzer_data_v5(data, data_collection);
		  
		  printf("Flush: %d\n", flush);
		  //count_entry += head->count.b1;
		  count_all += head->count.b1;
		  count_entry2 += head->count.b1;
		  //Копируем в коллектор
		  copy_to_collector(data_collection, data,head);
		  //Вывод 
	          //SQL
		  if(flush) {
		      flush=0;
		      cpid = fork();
		      if(cpid ==  -1) {
			perror("fork");
			exit(EXIT_FAILURE);
		      }
		      if(cpid == 0) {
			prctl(PR_SET_NAME, "nfcd: write log to DB\0", NULL, NULL, NULL);
		      LogMessage("nfcd", "Export entries ...");
		      tosql(data_collection, head, count_entry, table);
		      printf("Count_entry %d\n", count_entry);
		      LogMessage("nfcd", "Exported entries:");
		      LogMessage("nfcd", "into base: %d", count_entry);
		      LogMessage("nfcd", "from cisco device's: %d", count_entry2);
		      LogMessage("nfcd", "from cisco device's all's: %d", count_all);
       		      LogMessage("nfcd", "compressed: %.2f %%", (float) count_entry/(float) count_entry2);
		     {   i = 0;
			  printf("Trap_free\n");
			while(i < count_entry) {
		           free(*(data_collection + i));
			   i++;
		       }
		       printf("Trap_free1\n");
		       count_entry1 = 0;
		       count_entry = 0;
		       count_entry2 = 0;
		     }
		      printf("FLUSH\n");
		      flush=0;
		      exit(0);
		      } else {
		     	{   i = 0;
				  printf("Trap_free\n");
				while(i < count_entry) {
		           	 free(*(data_collection + i));
			   	 i++;
		       	        }
		       		printf("Trap_free1\n");
		       		count_entry1 = 0;
		       		count_entry = 0;
		       		count_entry2 = 0;
		      }
		      }
		   }
      		   waitpid(-1, &wstatus, WNOHANG);
		  //tosql(data_collection, head); 
		  //tosql(data, head);
		  //stdout
		  printf("Src\tDst\tNextHop\n");
		      for(i = 0;i < (head->count).b1; i++){
  printf("%d.%d.%d.%d \t%d.%d.%d.%d \t%d.%d.%d.%d \t  %d \t%d %d \t%d %d \t %d %d\n",
 (*(data + i))->srcaddr.b0,
 (*(data + i))->srcaddr.b1,
 (*(data + i))->srcaddr.b2,
 (*(data + i))->srcaddr.b3, (*(data + i))->dstaddr.b0,
			 (*(data + i))->dstaddr.b1,
			 (*(data + i))->dstaddr.b2,
			 (*(data + i))->dstaddr.b3, (*(data + i))->nexthop.b0,
			                            (*(data + i))->nexthop.b1,
						    (*(data + i))->nexthop.b2,
						    (*(data + i))->nexthop.b3, //(*(data + i))->dOctets.b0,
						                         //(*(data + i))->dOctets.b1,
									 //(*(data + i))->dOctets.b2,
									 //(*(data + i))->dOctets.b3,
									 (*(data + i))->dOctets.summ,
										         (*(data + i))->src_mask.b0,
											 (*(data + i))->dst_mask.b0, (*(data + i))->prot.b0,(*(data + i))->tos.b0,
											 (*(data + i))->input.i_snmp,
											 (*(data + i))->output.o_snmp);
		      }
 printf("Кол-во экспорт записей %d  Ковл-во %d Всего %d\n",count_entry2,count_entry,count_all);
	        for(i = 0;i < (head->count.b1); i++) {
	          free(*(data + i)); //Освобождение памяти
	        }
		  free(data);
		  free(head);
	       }
	       close(nsid); 
	    }
	 }
   }
