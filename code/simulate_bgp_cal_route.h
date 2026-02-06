
// bgp_sim_fast.cpp 
// Extremely optimized multi-threaded BGP hijack simulator. 
// Uses mmap(24GB), AVX2 bitsets(700MB), and LMDB lookup (40 shards). 
// Compile: 
// g++ -O3 -march=native -std=c++17 -pthread bgp_sim_fast.cpp -o bgp_sim 
#include <bits/stdc++.h> 
#include <sys/mman.h> 
#include <sys/stat.h> 
#include <fcntl.h> 
#include <unistd.h> 
#include <arpa/inet.h> 
#include <atomic> 
#include <immintrin.h> 
#include <omp.h> 
#include <lmdb.h> 
#include <thread>
#include <unordered_set>

using namespace std; 

struct MMapFile {
    int fd;
    size_t size;
    void* ptr = nullptr; 
    ~MMapFile() { 
        if (ptr) munmap(ptr, size); 
        if (fd >= 0) close(fd); 
    } 
};

MMapFile mmap_file_rw(const std::string &fn, size_t filesize);

MMapFile mmap_file_ro(const string &fn, size_t expected);

vector<uint32_t> read_asns_bin(const string &fn);

vector<vector<pair<uint32_t,int>>> read_graph_txt(const string &fn, const unordered_map<uint32_t,uint32_t> &asn2id);

void CalRouteInfoMatrixPerOrigin(uint32_t origin, const vector<vector<pair<uint32_t,int>>> &G, 
                                uint32_t N,  uint32_t *matrix_u32, uint32_t W=0, 
                                uint64_t *reach_matrix=nullptr, const string type="routeinfo");

//因为compete需要提速，这里单开一个函数，不再跟CalRouteInfoMatrixPerOrigin()混用
int CompeteRouteInfoMatrixPerOrigin(uint32_t victim, uint32_t hijacker, uint32_t N, uint32_t W, 
                                const vector<vector<pair<uint32_t,int>>> &G, const uint32_t *prev_priority, 
                                vector<char> &is_transit, vector<uint32_t> &priority, uint64_t* equal_pref_asns);
                                