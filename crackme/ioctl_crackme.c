#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

int main() {
    int rv = ioctl(0, 0x123456);

    if (rv < 0) {
      puts("NEG");
    }else if (rv == 0) {
      puts("ZERO");
    }else {
      puts("OTHER");
    }

    return 0;
}
