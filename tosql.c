#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>
#include "nfc.h"

void get_date(void) {
    time_t t=time(NULL);
      times=localtime(&t);
}

char * date_sql(struct tm *t) {
  sprintf(date_s,"'%d-%d-%d'",(t->tm_mon)+1, t->tm_mday, (t->tm_year)+1900);
	return date_s;
}
char *time_sql(struct tm *t) {
  sprintf(time_s,"'%d:%d:%d'",t->tm_hour,t->tm_min,t->tm_sec);
	return time_s;
}


void tosql(struct data_v5 **data_collection, struct header *head, int cnt, char *table) {
	    const char  *pghost="127.0.0.1",
			*pgport="5432",
			*pgoptions=NULL,
			*pgtty=NULL,
			*dbName="nfc",
			*login="nfc",
			*pwd="nfc";

PGconn *conn;
PGresult *res;
int nf, i, j;
char *ins=(char *)malloc(1000*sizeof(char));
char *src_addr;
char *dst_addr;
char *nexthop_addr;
   conn = PQsetdbLogin(pghost, pgport, pgoptions, pgtty, dbName, login, pwd);
   if(PQstatus(conn) == CONNECTION_BAD) {
      fprintf(stderr, "Connection to database '%s' failed.\n", dbName);
      fprintf(stderr, "%s", PQerrorMessage(conn));
   } else {
#ifdef DEBUG
      fprintf(stderr, "Connection to database '%s' Ok.\n", dbName);
#endif
   } 
   //Выделяем память дата/время
   date_s = (char *)malloc(10 * sizeof(char));
   time_s = (char *)malloc(10 * sizeof(char));
#ifdef DEBUG
   printf("Trap_to_sql\n");
#endif
    for(i = 0; i < cnt; i++){
	//Получаем дату
	get_date();
	//Выделяем адреса
	src_addr = (char *)malloc(17 * sizeof(char));
	dst_addr = (char *)malloc(17 * sizeof(char));
	nexthop_addr = (char *)malloc(17 * sizeof(char));
	//Вычисляем адреса
	sprintf(src_addr, "'%d.%d.%d.%d'",
		(*(data_collection + i))->srcaddr.b0,
		(*(data_collection + i))->srcaddr.b1,
		(*(data_collection + i))->srcaddr.b2,
		(*(data_collection + i))->srcaddr.b3);
	sprintf(dst_addr, "'%d.%d.%d.%d'",
	        (*(data_collection + i))->dstaddr.b0,
		(*(data_collection + i))->dstaddr.b1,
		(*(data_collection + i))->dstaddr.b2,
		(*(data_collection + i))->dstaddr.b3);
	sprintf(nexthop_addr, "'%d.%d.%d.%d'",
		(*(data_collection + i))->nexthop.b0,
		(*(data_collection + i))->nexthop.b1,
		(*(data_collection + i))->nexthop.b2,
		(*(data_collection + i))->nexthop.b3);
	sprintf(ins, "INSERT INTO %s (exporter_id, srcaddr, dstaddr, nexthop, input, output, dPkts, dOctets, First, Last, srcport, dstport, tcp_flags, prot, tos, src_as, dst_as, src_mask, dst_mask, dates, times) VALUES(%d,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s)", table, (*(data_collection+i))->exporter.id, src_addr, dst_addr, nexthop_addr, (*(data_collection+i))->input.b1, (*(data_collection+i))->output.b1, (*(data_collection+i))->dPkts.summ_pack, (*(data_collection+i))->dOctets.summ, (*(data_collection+i))->First.b0, (*(data_collection+i))->Last.b0, (*(data_collection+i))->srcport.port, (*(data_collection+i))->dstport.port, (*(data_collection+i))->tcp_flags.b0, (*(data_collection+i))->prot.b0, (*(data_collection+i))->tos.b0, (*(data_collection+i))->src_as.s_as, (*(data_collection+i))->dst_as.d_as, (*(data_collection+i))->src_mask.b0, (*(data_collection+i))->dst_mask.b0, date_sql(times), time_sql(times)); 
		  
		  res = PQexec(conn, ins);
#ifdef DEBUG
		  printf("%s\n", ins);
#endif
		    free(nexthop_addr);
		    free(dst_addr);
		    free(src_addr);
		  if(PQresultStatus(res) != PGRES_COMMAND_OK) {
		     fprintf(stderr, "INSERT command failed\n");
		     PQclear(res);
		     //exit_nicely(conn);
		     PQfinish(conn);
		     LogMessage("Row inserts error!\n", "nfcd");
		  }
	       if(res!=NULL)
		  PQclear(res);
    }
    free(time_s);
    free(date_s);
  PQfinish(conn);
  free(ins);
}  

