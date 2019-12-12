all: crackme

CFLAGS += -m32 -g -DHAVE_CONFIG_H -I. -gdwarf-2 -O0 -fno-stack-protector

%.o : %.c
	$(CC) $(CFLAGS) -c $<  -o $@  

crackme: crackme.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f crackme
