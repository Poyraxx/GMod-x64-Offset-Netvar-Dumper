#include "GModOffsetDumper.h"
#include <iostream>
#include <string>

int main() {
    std::cout << "GMOD Full Offset Dumper v3.0" << std::endl;
    std::cout << "============================" << std::endl;
    
    GModOffsetDumper dumper;
    
    if (!dumper.Initialize()) {
        std::cout << "Failed to initialize dumper!" << std::endl;
        std::cout << "Press Enter to exit..." << std::endl;
        std::cin.get();
        return 1;
    }
    
    dumper.PrintProcessInfo();
    dumper.DumpAllOffsets();
    dumper.SaveCppHeader("gmod_offsets.hpp");

    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
