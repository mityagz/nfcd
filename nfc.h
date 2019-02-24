#include <time.h>

int count_entry, count_entry1, count_entry2, cnt_data, flag, count_end, count_all;
struct data_v5 **data_collection, **data_col;
struct data_v5 **data;
struct header *head;
struct tm *times;
time_t * tim;
char   * date_s;
char   * time_s;
int    flush;
void   analyzer_data_v5(struct data_v5**, struct data_v5**);
void   sig_proc(int);
int    copy_data_v5(struct data_v5 *, struct data_v5 *);
void   append_data_v5(struct data_v5 *, struct data_v5 *);
void   copy_to_collector(struct data_v5 **, struct data_v5**, struct header *);
struct header * head_parser(int, char *, struct header *);
struct data_v5 * data_parser(char *, struct data_v5 *, int);
int eq_data_v5(struct data_v5 *source, struct data_v5 *dest);
void   LogMessage(char *, char *,...);
void tosql(struct data_v5 **, struct header *, int, char *);

struct header {
	 struct version {		//
			int b0;		// byte0
			int b1;		// byte1
			int ver;	//
	 } version;

	 struct count {		//
			int b0;		// byte2
			int b1;		// byte3
		 	int cnt_flow;	//
	 } count;		

	 struct SysUptime {		//
			int b0;		// byte4
			int b1;		// byte5
			int b2;		// byte6
			int b3;		// byte7
			int sys_up;	//
	 } SysUptime;

	 struct unix_secs {		//
			int b0;		// byte8
			int b1;		// byte9
			int b2;		// byte10
			int b3;		// byte11
			int un_sec;	//
	 } unix_secs;

	 struct unix_nsecs {		//
			int b0;		// byte12
			int b1;		// byte13
			int b2;		// byte14
			int b3;		// byte15
			int un_nsec;	//
	 } unix_nsecs;

	 struct flow_sequence {		//
			int b0;		// byte16
			int b1;		// byte17
			int b2;		// byte18
			int b3;		// byte19
			int cnt_packet;	//
	 } flow_sequence;

	 struct engine_type {		//
			int b0;		// byte20
	 } engine_type;  

	 struct engine_id {		//
			int b0;		// byte21
	 } engine_id;

	 struct reserved {		// Резерв
			int b0;		// byte22
			int b1;		// byte23
	 } reserved;
  };
  
struct data_v5{
	 struct srcaddr{		//
			int b0;		// byte0
			int b1;		// byte1
			int b2;		// byte2
			int b3;		// byte3
	 } srcaddr;

	 struct dstaddr{		//
			int b0;		// byte4
			int b1;		// byte5
			int b2;		// byte6
			int b3;		// byte7
	 } dstaddr;

	 struct nexthop{		//
			int b0;		// byte8
			int b1;		// byte9
			int b2;		// byte10
			int b3;		// byte11
	 } nexthop;

	 struct input {			//
			int b0;		// byte12
			int b1;		// byte13
			int i_snmp;	//
	 } input;

	 struct output {		//
			int b0;		// byte14
			int b1;		// byte15
			int o_snmp;	//
	 } output;

	 struct dPkts {			//
			int b0;		// byte16
			int b1;		// byte17
			int b2;		// byte18
			int b3;		// byte19
			int summ_pack;	// Всего пакетов
	 } dPkts;

	 struct dOctets {		//
			int b0;		// byte20
			int b1;		// byte21
			int b2;		// byte22
			int b3;		// byte23
			int summ;	// сумма
	 } dOctets;

	 struct First {			//
			int b0;		// byte24
			int b1;		// byte25
			int b2;		// byte26
			int b3;		// byte27
	 } First;

	 struct Last {			//
			int b0;		// byte28
			int b1;		// byte29
			int b2;		// byte30
			int b3;		// byte31
	 } Last;

	 struct srcport {		//
			int b0;		// byte32
			int b1;		// byte33
			int port;	// 
	 } srcport;

	 struct dstport {		//
			int b0;		// byte34
			int b1;		// byte35
			int port;	//
	 } dstport;

	 struct pad1 {			//
			int b0;		// byte36
	 } pad1;

	 struct tcp_flags {		//
			int b0;		// byte37
	 } tcp_flags;

	 struct prot {			//
			int b0;		// byte38
	 } prot;

	 struct tos {			//
			int b0;		// byte39
	 } tos;

	 struct src_as {		//
			int b0;		// byte40
			int b1;		// byte41
			int s_as;	// 
	 } src_as;

	 struct dst_as {		//
			int b0;		// byte42
			int b1;		// byte43
			int d_as;	//
	 } dst_as;

	 struct src_mask {		//
			int b0;		// byte44
	 } src_mask;

	 struct dst_mask {		//
			int b0;		// byte45
	 } dst_mask;

	 struct pad2 {			//
			int b0;		// byte46
			int b1;		// byte47
	 } pad2;
  };
