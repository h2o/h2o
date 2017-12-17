ALL:
	cmake .
	make all
	make check
	sudo make check-as-root
