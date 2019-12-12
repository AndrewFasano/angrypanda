#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int enc(char c) {
  return (int)c-3;
}


int main(int argc, char** argv) {

  if (argc < 2) {
    printf("USAGE %s [answer]\n", argv[0]);
    return 1;
  }

  int sum = 0;
  int len = strlen(argv[1]);
  char* buf = (char*)malloc(strlen(argv[1]));

  // Hook on return from malloc, capture buf
  for (int i=0; i < len; i++) {
    buf[i] = argv[1][i];
  }

  printf("Buffer contains: %s\n", buf);
  //Angr should start here
  for (int i=0; i < len; i++) {
    sum += enc(buf[i]);
  }

  if (sum == 0x108) { // 'EEEE' is valid
    printf("Success :)\n");
  }else{
    printf("Failure :(\n");
  }

  return 0;
}
