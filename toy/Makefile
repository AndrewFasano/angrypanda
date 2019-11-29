all: toy foo

CFLAGS += -m32 -g -DHAVE_CONFIG_H -I. -gdwarf-2 -O0 -fno-stack-protector

%.o : %.c
	$(CC) $(CFLAGS) -c $<  -o $@  

toy: toy.c
	$(CC) $(CFLAGS) -o $@ $<

foo: foo.c
	$(CC) $(CFLAGS) -o $@ $<

install:
	mkdir -p lava-install/bin
	cp toy lava-install/bin

clean:
	rm -f toy foo
