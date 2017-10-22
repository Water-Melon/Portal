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
		objs/client.o
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
objs/message.o :include/message.h src/message.c
	$(CC) $(FLAGS) -o $@ src/message.c 
objs/portal.o : include/portal.h include/message.h include/client.h include/server.h include/connection.h src/portal.c
	$(CC) $(FLAGS) -o $@ src/portal.c
objs/connection.o : include/message.h include/connection.h include/portal.h src/connection.c
	$(CC) $(FLAGS) -o $@ src/connection.c
objs/server.o : include/server.h include/portal.h include/message.h include/connection.h src/server.c
	$(CC) $(FLAGS) -o $@ src/server.c
objs/client.o : include/client.h include/portal.h include/message.h include/connection.h src/client.c
	$(CC) $(FLAGS) -o $@ src/client.c
