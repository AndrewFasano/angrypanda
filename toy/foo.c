#include <stdio.h>
#include <stdlib.h>


int main(int argc, char** argv) {

  char* buf = (char*)malloc(4); // Allocate 4 bytes of junk data
  buf[0] = (char)0x41;
  buf[1] = (char)0x41;
  buf[2] = (char)0x41;
  buf[3] = (char)0x41;
  // Initialize to AAAA

  //printf("Buffer is at %p\n", &buf);

  //XXX Here we need to run with symbolic buffer
  __asm("nop");

  int sum = 0;
  for (int i=0; i < 4; i++) {
    sum += (int)buf[i];
  }

  //printf("Sum is %d\n", sum);
  if (sum == 0x42*4) {
    return 1;
  }

  return 0;
}
