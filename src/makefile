MAKEFLAGS += -s

FLAGS = -s -masm=intel -lwinhttp -static-libstdc++ -static-libgcc --static
INCLUDE = -I ../include 
SOURCE = $(wildcard ./*.cpp)

EXECUTABLE = atlas_x64.exe

x64:
	nasm -f win64 ./syscalls.s -o syscalls.o
	x86_64-w64-mingw32-g++ -w ./syscalls.o $(SOURCE) $(INCLUDE) $(FLAGS) -o ../bin/$(EXECUTABLE)