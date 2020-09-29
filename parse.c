#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nfc.h"

int htoi(char *buf) {
	int i = 0;
	sscanf(buf,"%x",&i);
	return i;
}
  
int pow(int x, int y) {
		int i,res = 1;
		    for(i = 1;i <= y; ++i){
                    res = res*x;
		    }
		return res;
}
 
int btod(int bin) {
     int temp, base = 2, mask = 1, i = 0, sum = 0, tmp_mask = 1;
     while(i <= 7){
	 temp=((mask << i) & bin);
	 if(temp != 0){
		sum += pow(base, i);
	 }
	   i++;
     }
			     
     return sum;
}
 
int u_btod(int bin, int n_byte) {
     int temp, base = 2, mask = 1, i = 0, sum = 0, tmp_mask = 1, j = 8;
     while(i <= 7){
	 temp=((mask << i) & bin);
	 if(temp!=0){
		sum += pow(base, i + j * n_byte);
	 }
	   i++;
     }
			     
     return sum;
}
 
void copy_to_collector(struct data_v5 **data_collection, struct data_v5 **data, struct header *head) {
int i, j;
 if(*(data_collection) == NULL) {
    for(i=0; i < head->count.b1; i++) {
             *(data_collection + i) = (struct data_v5 *)malloc(sizeof(struct data_v5));
                 bzero(*(data_collection + i), sizeof(struct data_v5));
    }
   for(i = 0, j = 0; i < head->count.b1; i++, j++) {
     copy_data_v5(*(data + j),*(data_collection + i));
     count_entry = head->count.b1;
   }
 } else {
	for(i = 0; i < head->count.b1; i++) { 
		flag=0;
		for(j=0; j < count_entry; j++) {
			if(eq_data_v5(*(data + i), *(data_collection + j))) {
				append_data_v5(*(data_collection+j),*(data+i));
			  flag = 1;
#ifdef DEBUG
			  printf("Append %d\n",count_entry);
#endif
			  break;
		   }
		}
	     if(!flag){	
	        *(data_collection + count_entry) = (struct data_v5 *)malloc(sizeof(struct data_v5));
	        copy_data_v5(*(data + i), *(data_collection + count_entry));
		count_entry++;
#ifdef DEBUG
		printf("Parser %d",count_entry);
#endif
	     }
	}
 }
}

void append_data_v5(struct data_v5 *dest, struct data_v5 *source) {
    (dest->dPkts.b0) += (source->dPkts.b0);
    (dest->dPkts.b1) += (source->dPkts.b1);
    (dest->dPkts.b2) += (source->dPkts.b2);
    (dest->dPkts.b3) += (source->dPkts.b3);
    (dest->dPkts.summ_pack) += (source->dPkts.summ_pack);
    (dest->dOctets.b0) += (source->dOctets.b0);
    (dest->dOctets.b1) += (source->dOctets.b1);
    (dest->dOctets.b2) += (source->dOctets.b2);
    (dest->dOctets.b3) += (source->dOctets.b3);
    (dest->dOctets.summ) += (source->dOctets.summ);
}



int copy_data_v5(struct data_v5 *source,struct data_v5 *dest) {
	if(memcpy(dest,source,sizeof(*source)) != NULL){
		return 1;
	}
	else{
		return 0;
	}
}

int eq_data_v5(struct data_v5 *source, struct data_v5 *dest) {
 if(dest->exporter.id == source->exporter.id &&
    dest->srcaddr.b0 == source->srcaddr.b0 &&
    dest->srcaddr.b1 == source->srcaddr.b1 &&
    dest->srcaddr.b2 == source->srcaddr.b2 &&
    dest->srcaddr.b3 == source->srcaddr.b3 &&
    dest->dstaddr.b0 == source->dstaddr.b0 &&
    dest->dstaddr.b1 == source->dstaddr.b1 &&
    dest->dstaddr.b2 == source->dstaddr.b2 &&
    dest->dstaddr.b3 == source->dstaddr.b3 &&
    dest->nexthop.b0 == source->nexthop.b0 &&
    dest->nexthop.b1 == source->nexthop.b1 &&
    dest->nexthop.b2 == source->nexthop.b2 &&
    dest->nexthop.b3 == source->nexthop.b3 &&
    dest->input.b0 == source->input.b0 &&
    dest->input.b1 == source->input.b1 &&
    dest->input.i_snmp == source->input.i_snmp &&
    dest->output.b0 == source->output.b0 &&
    dest->output.b1 == source->output.b1 &&
    dest->output.o_snmp == source->output.o_snmp &&
    //dest->Last.b3 == sourc e->First.b3 &&          !?!?!?!?!?
    dest->srcport.b0 == source->srcport.b0 &&
    dest->srcport.b1 == source->srcport.b1 &&
    dest->srcport.port == source->srcport.port &&
    dest->dstport.b0 == source->dstport.b0 &&
    dest->dstport.b1 == source->dstport.b1 &&
    dest->dstport.port == source->dstport.port &&
    dest->tcp_flags.b0 == source->tcp_flags.b0 &&
    dest->prot.b0 == source->prot.b0 &&
    dest->tos.b0 == source->tos.b0 &&
    dest->src_as.b0 == source->src_as.b0 &&
    dest->src_as.b1 == source->src_as.b1 &&
    dest->src_as.s_as == source->src_as.s_as &&
    dest->dst_as.b0 == source->dst_as.b0 &&
    dest->dst_as.b1 == source->dst_as.b1 &&
    dest->dst_as.d_as == source->dst_as.d_as &&
    dest->src_mask.b0 == source->src_mask.b0 &&
    dest->dst_mask.b0 == source->dst_mask.b0) {
     return 1;
    } else {
     return 0;
    }
}

struct header*
       head_parser(int summary_bytes, char *buffer, struct header *head) {
	head->version.b0 = btod(*(buffer + 0));
	head->version.b1 = btod(*(buffer + 1));
	head->count.b0 = btod(*(buffer + 2));
	head->count.b1 = btod(*(buffer + 3));
	head->SysUptime.b0 = btod(*(buffer + 4));
	head->SysUptime.b1 = btod(*(buffer + 5));
	head->SysUptime.b2 = btod(*(buffer + 6));
	head->SysUptime.b3 = btod(*(buffer + 7));
	head->unix_secs.b0 = btod(*(buffer + 8));
	head->unix_secs.b1 = btod(*(buffer + 9));
	head->unix_secs.b2 = btod(*(buffer + 10));
	head->unix_secs.b3 = btod(*(buffer + 11));
	head->unix_nsecs.b0 = btod(*(buffer + 12));
	head->unix_nsecs.b1 = btod(*(buffer + 13));
	head->unix_nsecs.b2 = btod(*(buffer + 14));
	head->unix_nsecs.b3 = btod(*(buffer + 15));
	head->flow_sequence.b0 = btod(*(buffer + 16));
	head->flow_sequence.b1 = btod(*(buffer + 17));
	head->flow_sequence.b2 = btod(*(buffer + 18));
	head->flow_sequence.b3 = btod(*(buffer + 19));
	head->engine_type.b0 = btod(*(buffer + 20));
	head->engine_id.b0 = btod(*(buffer + 21));
	head->reserved.b0 = btod(*(buffer + 22));
	head->reserved.b1 = btod(*(buffer + 23));
	return head;
  }
struct data_v5 * 
 data_parser(char *base_data, struct data_v5 *data, int cnt, int exporter_id) {
    data->exporter.id = exporter_id;
    data->srcaddr.b0 = btod(*(base_data + 0));
    data->srcaddr.b1 = btod(*(base_data + 1));
    data->srcaddr.b2 = btod(*(base_data + 2));
    data->srcaddr.b3 = btod(*(base_data + 3));
    data->dstaddr.b0 = btod(*(base_data + 4));
    data->dstaddr.b1 = btod(*(base_data + 5));
    data->dstaddr.b2 = btod(*(base_data + 6));
    data->dstaddr.b3 = btod(*(base_data + 7));
    data->nexthop.b0 = btod(*(base_data + 8));
    data->nexthop.b1 = btod(*(base_data + 9));
    data->nexthop.b2 = btod(*(base_data + 10));
    data->nexthop.b3 = btod(*(base_data + 11));
    data->input.b0 = btod(*(base_data + 12));
    data->input.b1 = btod(*(base_data + 13));
    data->input.i_snmp = u_btod(*(base_data + 13), 0) +
		       u_btod(*(base_data + 12), 1);
    data->output.b0 = btod(*(base_data + 14));
    data->output.b1 = btod(*(base_data + 15));
    data->output.o_snmp = u_btod(*(base_data + 15), 0) +
			u_btod(*(base_data + 14), 1);
    data->dPkts.b0 = btod(*(base_data + 16));
    data->dPkts.b1 = btod(*(base_data + 17));
    data->dPkts.b2 = btod(*(base_data + 18));
    data->dPkts.b3 = btod(*(base_data + 19));
    data->dPkts.summ_pack = u_btod(*(base_data + 19), 0) +
			  u_btod(*(base_data+18), 1) +
			  u_btod(*(base_data+17), 2) +
			  u_btod(*(base_data+16), 3);
    data->dOctets.b0 = btod(*(base_data + 20));
    data->dOctets.b1 = btod(*(base_data + 21));
    data->dOctets.b2 = btod(*(base_data + 22));
    data->dOctets.b3 = btod(*(base_data + 23));
    data->dOctets.summ = u_btod(*(base_data + 23), 0) +
                     u_btod(*(base_data + 22), 1) +
                     u_btod(*(base_data + 21), 2) +
                     u_btod(*(base_data + 20), 3);
    data->First.b0 = btod(*(base_data + 24));
    data->First.b1 = btod(*(base_data + 25));
    data->First.b2 = btod(*(base_data + 26));
    data->First.b3 = btod(*(base_data + 27));
    data->Last.b0 = btod(*(base_data + 28));
    data->Last.b1 = btod(*(base_data + 29));
    data->Last.b2 = btod(*(base_data + 30));
    data->Last.b3 = btod(*(base_data + 31));
    data->srcport.b0 = btod(*(base_data + 32));
    data->srcport.b1 = btod(*(base_data + 33));
    data->srcport.port = u_btod(*(base_data + 33), 0) +
		       u_btod(*(base_data+32), 1);
    
    data->dstport.b0 = btod(*(base_data + 34));
    data->dstport.b1 = btod(*(base_data + 35));
    data->dstport.port = u_btod(*(base_data + 35), 0) +
		       u_btod(*(base_data + 34), 1);
    
    data->pad1.b0 = btod(*(base_data + 36));
    data->tcp_flags.b0 = btod(*(base_data + 37));
    data->prot.b0 = btod(*(base_data + 38));
    data->tos.b0 = btod(*(base_data + 39));
    data->src_as.b0 = btod(*(base_data + 40));
    data->src_as.b1 = btod(*(base_data+41));
    data->src_as.s_as = u_btod(*(base_data + 41), 0) +
		      u_btod(*(base_data + 40), 1);
    data->dst_as.b0 = btod(*(base_data + 42));
    data->dst_as.b1 = btod(*(base_data + 43));
    data->dst_as.d_as = u_btod(*(base_data + 43), 0) +
		      u_btod(*(base_data + 42), 1);
    data->src_mask.b0 = btod(*(base_data + 44));
    data->dst_mask.b0 = btod(*(base_data + 45));
    data->pad2.b0 = btod(*(base_data + 46));
    data->pad2.b1 = btod(*(base_data + 47));
    return data;
  }
