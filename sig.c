#include <stdio.h>
#include <stdlib.h>
#include "nfc.h"

void sig_proc(int sig_num) {
int i;
  signal(sig_num,sig_proc);
  alarm(1800);
  printf("alarm\n");
  flush=1;
}

