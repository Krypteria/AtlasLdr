MAKEFLAGS += -s

FLAGS = -s -masm=intel -lwinhttp -static-libstdc++ -static-libgcc -static
INCLUDE = -I ./include 
SOURCE = $(wildcard ./src/*.cpp)

EXECUTABLE = atlas_x64.exe

x64:
	x86_64-w64-mingw32-g++ -w  $(SOURCE) $(INCLUDE) $(FLAGS) -o ./bin/$(EXECUTABLE)