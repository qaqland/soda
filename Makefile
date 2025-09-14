
soda: soda.c
	gcc -g $< -o $@
	chmod u+s $@

install: soda
	install -m 755 -o root soda /usr/local/bin/
	chmod u+s /usr/local/bin/soda
