#include <algorithm>
#include <cmath>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
struct LogEntry {
    std::string ip,timestamp,method,path;
    int status=0;
    long long bytes=0;
    std::time_t epoch=0;
};
static std::string jsonEscape(const std::string&s){
    std::ostringstream o;
    for(unsigned char c:s) {
        if(c=='"'||c=='\\')o<<'\\'<<c;
        else if(c=='\n')o<<"\\n";
        else if(c=='\r')o<<"\\r";
        else if(c=='\t')o<<"\\t";
        else if(c<32)o<<' ';
        else o<<c;
    }
    return o.str();
}
static std::string q(const std::string&s){
    return "\""+jsonEscape(s)+"\"";
}
class LogParser {
public:
     std::vector<LogEntry> parse(const std::string&file, int&bad) const{
        std::ifstream in(file.c_str());
        if(!in)throw std::runtime_error("Unable to read uploaded log file");
        const std::regex re(R"(^([0-9A-Fa-f:.]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)\s+HTTP/[0-9.]+"\s+(\d{3})\s+(\d+|-).*$)");
        std::vector<LogEntry> out;
        std::string line;
        while(std::getline(in, line)){
            std::smatch m;
            if(!std::regex_match(line, m, re)){
                ++bad;
                continue;
            }
            try{
                LogEntry e;
                e.ip=m[1];
                e.timestamp=m[2];
                e.method=m[3];
                e.path=m[4];
                e.status=std::stoi(m[5]);
                e.bytes=m[6]=="-"?0:std::stoll(m[6]);
                std::tm t={
                };
                std::istringstream ts(e.timestamp.substr(0, 20));
                ts>>std::get_time(&t, "%d/%b/%Y:%H:%M:%S");
                if(ts.fail()){
                    ++bad;
                    continue;
                }
                e.epoch=std::mktime(&t);
                out.push_back(e);
            }
            catch(...){
                ++bad;
            }
        }
        return out;
    }
};
struct IPStats {
    std::vector<const LogEntry*> rows;
    std::map<int,int> statuses;
};
struct Finding {
    std::string ip,type,severity,reason,evidence,firstSeen,lastSeen;
    int count=0;
    double rate=0;
};
class AttackDetector {
public:
    virtual ~AttackDetector(){
    }
    virtual std::vector<Finding> analyze(const std::unordered_map<std::string, IPStats>&, int, int, double)const=0;
};
static std::pair<const LogEntry*,const LogEntry*> bounds(const std::vector<const LogEntry*>&v) {
    auto mm=std::minmax_element(v.begin(), v.end(), [](auto a, auto b){ return a->epoch<b->epoch; });
    return {
        *mm.first,*mm.second
    };
}
class BruteForceDetector:public AttackDetector {
public:
    std::vector<Finding> analyze(const std::unordered_map<std::string, IPStats>&ips, int threshold, int window, double)const override{
        std::vector<Finding> out;
        for(auto&p:ips){
            std::vector<const LogEntry*> v;
            for(auto e:p.second.rows) if(e->status==401)v.push_back(e);
            std::sort(v.begin(), v.end(), [](auto a, auto b) { return a->epoch<b->epoch; });
            size_t l=0,bestL=0,bestR=0;
            for(size_t r=0; r<v.size(); r++) {
                while(v[r]->epoch-v[l]->epoch>window)++l;
                if(r-l+1>bestR-bestL){
                    bestL=l;
                    bestR=r+1;
                }
            }
            int n=(int)(bestR-bestL);
            if(n>=threshold){
                Finding f;
                f.ip=p.first;
                f.type="Brute Force Activity";
                f.severity=n>=threshold*2?"CRITICAL":"HIGH";
                f.count=n;
                f.firstSeen=v[bestL]->timestamp;
                f.lastSeen=v[bestR-1]->timestamp;
                f.evidence=v[bestL]->path;
                f.reason=std::to_string(n)+" HTTP 401 authentication responses in "+std::to_string((long long)(v[bestR-1]->epoch-v[bestL]->epoch))+" seconds (threshold "+std::to_string(threshold)+" per "+std::to_string(window)+" seconds).";
                out.push_back(f);
            }
        }
        return out;
    }
};
class TrafficDetector:public AttackDetector {
public:
    std::vector<Finding> analyze(const std::unordered_map<std::string, IPStats>&ips, int, int window, double threshold)const override{
        std::vector<Finding> out;
        for(auto&p:ips){
            auto v=p.second.rows;
            if(v.size()<2)continue;
            std::sort(v.begin(), v.end(), [](auto a, auto b) { return a->epoch<b->epoch; });
            size_t l=0,bl=0,br=0;
            for(size_t r=0; r<v.size(); r++) {
                while(l<r&&v[r]->epoch-v[l]->epoch>window)++l;
                if(r-l+1>br-bl){
                    bl=l;
                    br=r+1;
                }
            }
            if(br>bl){
                long long dur=v[br-1]->epoch-v[bl]->epoch;
                double peak=double(br-bl)/std::max<long long>(dur, 1);
                if(peak>=threshold){
                    Finding f;
                    f.ip=p.first;
                    f.type="Traffic Spike";
                    f.count=(int)(br-bl);
                    f.rate=peak;
                    f.severity=peak>=threshold*2?"CRITICAL":"HIGH";
                    f.firstSeen=v[bl]->timestamp;
                    f.lastSeen=v[br-1]->timestamp;
                    f.evidence=std::to_string(f.count)+" requests";
                    std::ostringstream msg;
                    msg<<f.count<<" requests; peak "<<std::fixed<<std::setprecision(1)<<peak<<" requests/sec over "<<dur<<" seconds (threshold "<<threshold<<" requests/sec).";
                    f.reason=msg.str();
                    out.push_back(f);
                }
            }
        }
        return out;
    }
};
class HttpErrorDetector:public AttackDetector {
public:
    std::vector<Finding> analyze(const std::unordered_map<std::string, IPStats>&ips, int, int, double)const override{
        std::vector<Finding>out;
        for(auto&p:ips)for(int code:{ 403, 404}){
            int n=p.second.statuses.count(code)?p.second.statuses.at(code):0;
            if(n>=5){
                Finding f;
                f.ip=p.first;
                f.type="Repeated HTTP Errors";
                f.count=n;
                f.severity=n>=20?"HIGH":"MEDIUM";
                auto b=bounds(p.second.rows);
                f.firstSeen=b.first->timestamp;
                f.lastSeen=b.second->timestamp;
                f.reason=std::to_string(n)+" HTTP "+std::to_string(code)+" responses.";
                f.evidence="HTTP "+std::to_string(code);
                out.push_back(f);
            }
        }
        return out;
    }
};
class SQLInjectionDetector:public AttackDetector {
public:
    std::vector<Finding> analyze(const std::unordered_map<std::string, IPStats>&ips, int, int, double)const override{
        return pattern(ips, false);
    }
    static std::vector<Finding> pattern(const std::unordered_map<std::string, IPStats>&ips, bool trav){
        std::vector<Finding> out;
        const std::regex sql(R"((union(%20|\+|\s)+select)|(\bor(%20|\+|\s)*1(%20|\+|\s)*=(%20|\+|\s)*1\b)|((%27|')[^&]*(%20|\+|\s)+(or|and)(%20|\+|\s)+[^&]*=)|(%27(%20|\+|\s)*or))", std::regex::icase),tr(R"((\.\./)|(\.\.\\)|(%2e%2e(%2f|%5c)))", std::regex::icase);
        for(auto&p:ips){
            std::vector<const LogEntry*> found;
            for(auto e:p.second.rows)if(std::regex_search(e->path, trav?tr:sql))found.push_back(e);
            if(!found.empty()){
                Finding f;
                f.ip=p.first;
                f.type=trav?"Directory Traversal Indicator":"SQL Injection Indicator";
                f.count=(int)found.size();
                f.severity="MEDIUM";
                f.firstSeen=bounds(found).first->timestamp;
                f.lastSeen=bounds(found).second->timestamp;
                f.evidence=found.front()->path;
                f.reason=std::to_string(found.size())+" request target(s) matched a rule-based indicator. Representative target: "+f.evidence;
                out.push_back(f);
            }
        }
        return out;
    }
};
class DirectoryTraversalDetector:public AttackDetector{
public:
    std::vector<Finding>analyze(const std::unordered_map<std::string, IPStats>&ips, int, int, double)const override{
        return SQLInjectionDetector::pattern(ips, true);
    }
};
class AnomalyEngine {
    std::vector<LogEntry> entries;
    std::unordered_map<std::string,IPStats>ips;
public:
    explicit AnomalyEngine(std::vector<LogEntry>v):entries(std::move(v)){
        for(auto&e:entries){
            ips[e.ip].rows.push_back(&e);
            ips[e.ip].statuses[e.status]++;
        }
    }
    std::string report(int fail, int window, double rps, int malformed)const{
        std::vector<std::unique_ptr<AttackDetector>> ds;
        ds.emplace_back(new BruteForceDetector);
        ds.emplace_back(new TrafficDetector);
        ds.emplace_back(new HttpErrorDetector);
        ds.emplace_back(new SQLInjectionDetector);
        ds.emplace_back(new DirectoryTraversalDetector);
        std::vector<Finding> fs;
        for(auto&d:ds){
            auto x=d->analyze(ips, fail, window, rps);
            fs.insert(fs.end(), x.begin(), x.end());
        }
        std::time_t lo=entries[0].epoch,hi=lo;
        for(auto&e:entries){
            lo=std::min(lo, e.epoch);
            hi=std::max(hi, e.epoch);
        }
        std::map<std::string,std::map<int,int>>eps;
        for(auto&e:entries)eps[e.path][e.status]++;
        std::ostringstream o;
        o<<"{\"summary\":{\"totalEntries\":"<<entries.size()<<",\"validEntries\":"<<entries.size()<<",\"malformedLinesSkipped\":"<<malformed<<",\"uniqueIPs\":"<<ips.size()<<",\"findings\":"<<fs.size()<<",\"suspiciousIPs\":";
        std::set<std::string>bad;
        for(auto&f:fs)bad.insert(f.ip);
        o<<bad.size()<<",\"firstSeen\":"<<q(bounds([&](){ std::vector<const LogEntry*>v; for(auto&e:entries)v.push_back(&e); return v; }()).first->timestamp)<<",\"lastSeen\":"<<q(bounds([&](){ std::vector<const LogEntry*>v; for(auto&e:entries)v.push_back(&e); return v; }()).second->timestamp)<<"},\"supported\":{\"portScan\":false,\"reason\":\"Access logs do not contain destination-port fields.\"},\"findings\":[";
        for(size_t i=0; i<fs.size(); i++){
            auto&f=fs[i];
            if(i)o<<',';
            o<<"{\"ip\":"<<q(f.ip)<<",\"type\":"<<q(f.type)<<",\"severity\":"<<q(f.severity)<<",\"count\":"<<f.count<<",\"rate\":"<<f.rate<<",\"firstSeen\":"<<q(f.firstSeen)<<",\"lastSeen\":"<<q(f.lastSeen)<<",\"evidence\":"<<q(f.evidence)<<",\"reason\":"<<q(f.reason)<<"}";
        }
        o<<"],\"endpoints\":[";
        bool first=true;
        for(auto&p:eps){
            if(!first)o<<',';
            first=false;
            o<<"{\"endpoint\":"<<q(p.first)<<",\"requests\":";
            int n=0;
            for(auto x:p.second)n+=x.second;
            o<<n<<",\"401\":"<<p.second[401]<<",\"403\":"<<p.second[403]<<",\"404\":"<<p.second[404]<<"}";
        }
        o<<"],\"ips\":[";
        first=true;
        for(auto&p:ips){
            if(!first)o<<',';
            first=false;
            auto&s=p.second;
            auto b=bounds(s.rows);
            std::vector<std::time_t>t;
            for(auto e:s.rows)t.push_back(e->epoch);
            std::sort(t.begin(), t.end());
            double peak=0;
            size_t l=0;
            for(size_t r=0; r<t.size(); r++){
                while(l<r&&t[r]-t[l]>window)++l;
                peak=std::max(peak, double(r-l+1)/std::max<long long>(t[r]-t[l], 1));
            }
            o<<"{\"ip\":"<<q(p.first)<<",\"totalRequests\":"<<s.rows.size()<<",\"auth401Responses\":"<<(s.statuses.count(401)?s.statuses.at(401):0)<<",\"authEndpoint401\":";
            int ae=0;
            for(auto e:s.rows)if(e->status==401&&std::regex_search(e->path, std::regex(R"((/login|/signin|/auth)(/|\?|$))", std::regex::icase)))ae++;
            o<<ae<<",\"peakRps\":"<<peak<<",\"firstSeen\":"<<q(b.first->timestamp)<<",\"lastSeen\":"<<q(b.second->timestamp)<<",\"statuses\":{";
            bool f=true;
            for(auto x:s.statuses){
                if(!f)o<<',';
                f=false;
                o<<q(std::to_string(x.first))<<':'<<x.second;
            }
            o<<"},\"timeline\":[";
            for(size_t j=0; j<s.rows.size(); j++){
                if(j)o<<',';
                auto e=s.rows[j];
                o<<"{\"timestamp\":"<<q(e->timestamp)<<",\"method\":"<<q(e->method)<<",\"endpoint\":"<<q(e->path)<<",\"status\":"<<e->status<<"}";
            }
            o<<"]}";
        }
        o<<"]}";
        return o.str();
    }
};
int main(int argc, char**argv){
    try{
        if(argc!=5)throw std::runtime_error("Usage: engine <log-file> <failed-threshold> <window-seconds> <requests-per-second>");
        int fail=std::stoi(argv[2]),window=std::stoi(argv[3]);
        double rate=std::stod(argv[4]);
        if(fail<1||window<1||!std::isfinite(rate)||rate<=0||fail>1000000||window>86400||rate>1000000)throw std::runtime_error("Threshold outside allowed range");
        int malformed=0;
        LogParser p;
        auto v=p.parse(argv[1], malformed);
        if(v.empty())throw std::runtime_error("No valid access-log entries found");
        AnomalyEngine e(std::move(v));
        std::cout<<e.report(fail, window, rate, malformed)<<"\n";
        return 0;
    }
    catch(const std::exception&e){
        std::cerr<<e.what()<<"\n";
        return 2;
    }
}
