MAKEFLAGS += -s

FLAGS = -s -masm=intel -static-libgcc -static-libstdc++ -static -shared
INCLUDE = -I ./include 
SOURCE = $(wildcard ./src/*.cpp)

EXECUTABLE = atlas_patcher.dll

x64:
	x86_64-w64-mingw32-g++ -w  $(SOURCE) $(INCLUDE) $(FLAGS) -o ../AtlasLdr/bin/$(EXECUTABLE)