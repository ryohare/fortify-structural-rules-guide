#include<iostream>
#include<cstring>

using namespace std;

class Response {
    public:
        std::string data;
};

// Get Private Data
extern std::string GetPrivateData();

// Send a response
extern void SendResponse(Response);

int main(int argc, char** argv){
    auto r = Response();
    r.data = GetPrivateData();
    SendResponse(r);
    return 0;
}
