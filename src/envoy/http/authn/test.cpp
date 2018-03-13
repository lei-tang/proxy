#include <iostream>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <functional>

using namespace std;

function<void()> cb;

void createFilter() {
    shared_ptr<map<int, set<string>>> ptr = make_shared<map<int, set<string>>>();
    ptr->insert(pair<int, set<string>>(10, set<string>()));
    ptr->at(10).insert("hello");
    cout<<ptr->at(10).size()<<endl;
    cb=[ptr]()->void {
        cout<<ptr->at(10).size()<<endl;
    };
}

int main() {
    createFilter();
    cb();
    return 0;
}
