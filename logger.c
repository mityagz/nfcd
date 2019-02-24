#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdarg.h>

void LogMessage(char *arg,char *mesg,...) {
      char *to_log=(char*)malloc(128);
      va_list ap;
      va_start(ap,mesg);
      (void)vsprintf(to_log,mesg,ap);
      va_end(ap);	
	 openlog(arg,LOG_PID | LOG_NDELAY,LOG_LOCAL3);
	  syslog(LOG_INFO,to_log);
         closelog();
      free(to_log);
}

