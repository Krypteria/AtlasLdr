MAKEFLAGS += -s

x64:
	echo [*] Compiling Atlas Loader (x64)
	cd src && $(MAKE) x64
	echo [*] Atlas Loader compiled in /bin
