#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>
#include "nfc.h"

GHashTable *exportersTable;

int get_exporter_id(char *ip) {
 gpointer gexporter = NULL;
 gexporter = g_hash_table_lookup(exportersTable, ip);
 if(gexporter == NULL)
  return 0;
 int exporter_id = atoi((char*)gexporter);
 return exporter_id;
}

void get_exporters(void) {
	exportersTable = g_hash_table_new (g_str_hash, g_str_equal);

	const char  *pghost="127.0.0.1",
				*pgport="5432",
				*pgoptions=NULL,
				*pgtty=NULL,
				*dbName="nfc",
				*login="nfc",
				*pwd="nfc";
	PGconn *conn = NULL;
	PGresult *res = NULL;
	char *ins = (char *)malloc(1000 * sizeof(char));
	char *src_addr;
	char *dst_addr;
	char *nexthop_addr;
	conn = PQsetdbLogin(pghost, pgport, pgoptions, pgtty, dbName, login, pwd);
	if(PQstatus(conn) == CONNECTION_BAD) {
		fprintf(stderr, "Connection to database '%s' failed.\n", dbName);
		fprintf(stderr, "%s", PQerrorMessage(conn));
	}
   
	sprintf(ins, "SELECT id, ip_addr FROM devices WHERE isactive=1");
	res = PQexec(conn, ins);

	if(PQresultStatus(res) == PGRES_TUPLES_OK) {
		int nrows = PQntuples(res);
		int ncols = PQnfields(res);

    for(int i = 0; i < nrows; i++) {
        char* id = PQgetvalue(res, i, 0);
        char* exporter = PQgetvalue(res, i, 1);
		g_hash_table_insert(exportersTable, g_strdup(exporter), g_strdup(id));
	}


		PQclear(res);
	}
	
	PQfinish(conn);
	free(ins);
}
