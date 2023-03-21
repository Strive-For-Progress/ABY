#include <iostream>
#include <sstream>
#include <string.h>
#include <iomanip>
using namespace std;
string to_zero_lead(const string value, const unsigned precision)
{
    ostringstream oss;
    oss << setw(precision) << setfill('0') << value;
    return oss.str();
}
int main() {
    string str;
    stringstream stream;
    cin >> str;
    int len = str.length()+128;
    if(len % 2) {
        cout << "error\n";
        return 0;
    } else 
    {
        len *= 4;
    }
    cout << "bit_len : " << len << endl;
    stream << std::hex << len;
    
    str.append("80");
    while(str.length() % (512/4) != (448/4) ) {
        str.append("00");
    }
    cout << str.append( to_zero_lead(stream.str(), 64/4)) << endl;
    cout <<"process block " <<str.length()*4/512 << " times"<<endl;
}