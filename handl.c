#include <wait.h>

void ch_handler(int signum) {
    pid_t childpid;
    int childstatus;
    while ((childpid = waitpid( -1, &childstatus, WNOHANG)) > 0) {
    }
   signal(SIGCHLD, ch_handler);
}
