MAKEFLAGS += -s

x64:
	echo [*] Compiling Atlas Loader (x64)
	cd AtlasLdr && $(MAKE) x64
	echo [*] Compiling Atlas Patcher (x64)
	cd AtlasPatcher && $(MAKE) x64
	echo [*] Atlas Loader and Atlas Patcher compiled in AtlasLdr/bin
