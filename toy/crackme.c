#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char** argv) {

  if (argc < 2) {
    printf("USAGE %s [answer]\n", argv[0]);
    return 1;
  }

  int sum = 0;
  int len = strlen(argv[1]);
  char* buf = (char*)malloc(strlen(argv[1]));

  // Hook on return from malloc (BB), capture buf
  for (int i=0; i < len; i++) {
    buf[i] = argv[1][i];
  }

  printf("Buffer contains: %s\n", buf);
  //Angr should start from after this print
  for (int i=0; i < len; i++) {
    sum += (int)buf[i];
  }

  if (sum == 0x108) { // 'BBBB' is valid
    printf("Success :)\n");
  }else{
    printf("Failure :(\n");
  }

  return 0;
}
