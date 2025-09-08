
cmt: cmt.c debug.o ram_map.o secret.o tests.o utils.o
	$(CC) $(CFLAGS) -o cmt $^

%.o: %.c
	$(CC) -c $<

clean:
	rm -f cmt *.o
