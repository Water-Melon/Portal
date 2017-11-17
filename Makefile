# 
# Copyright (C) Niklaus F.Schen.
# 
CC		= cc
FLAGS		= -c -Wall -ggdb -Werror -O3 -I./melon/include -Iinclude
PORTAL		= portal
OBJS		= \
		objs/message.o \
		objs/portal.o \
		objs/connection.o \
		objs/server.o \
		objs/client.o \
		objs/proxy.o \
		objs/broadcaster.o
.PHONY :	compile install clean
compile: build $(OBJS) $(PORTAL)
clean:
	rm -fr objs $(PORTAL) lib melon Melon
build :
	bash build.sh
$(PORTAL) : $(OBJS) melon/lib/libmelon.so
	$(CC) -o $@ $(OBJS) -ggdb -Wall -lmelon -Llib/ -lpthread -lc
install:
	test -d /usr/local/portal || mkdir -p /usr/local/portal
	cp $(PORTAL) /usr/local/portal/
objs/message.o :include/message.h src/message.c include/portal.h
	$(CC) $(FLAGS) -o $@ src/message.c 
objs/portal.o : include/portal.h include/message.h include/client.h include/server.h include/connection.h src/portal.c include/proxy.h include/broadcaster.h
	$(CC) $(FLAGS) -o $@ src/portal.c
objs/connection.o : include/message.h include/connection.h include/portal.h src/connection.c include/portal.h
	$(CC) $(FLAGS) -o $@ src/connection.c
objs/server.o : include/server.h include/portal.h include/message.h include/connection.h src/server.c
	$(CC) $(FLAGS) -o $@ src/server.c
objs/client.o : include/client.h include/portal.h include/message.h include/connection.h src/client.c
	$(CC) $(FLAGS) -o $@ src/client.c
objs/proxy.o : include/proxy.h include/portal.h include/message.h include/connection.h src/proxy.c
	$(CC) $(FLAGS) -o $@ src/proxy.c
objs/broadcaster.o : include/broadcaster.h include/portal.h include/message.h include/connection.h src/broadcaster.c
	$(CC) $(FLAGS) -o $@ src/broadcaster.c
