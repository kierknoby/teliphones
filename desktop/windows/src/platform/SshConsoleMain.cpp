#include "Ssh.h"
#include "Win.h"
#include <shellapi.h>

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> arguments;
    for (int i = 1; i < argc; ++i) arguments.push_back(tlp::win::Narrow(argv[i]));
    return tlp::win::RunSshConsole(arguments);
}
