
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
#include "simulate_bgp_cal_route.h"
#include <chrono>

using namespace std; 

using u32 = uint32_t; 
using u64 = uint64_t; 

static const uint8_t allow[3][3] = {
    // rel: 0(customer), 1(peer), 2(provider)
    {1,1,1}, // sel_from_rel=0 (来自customer，可继续到任何邻居)
    {1,0,0}, // sel_from_rel=1 (来自peer，只能传给customer)
    {1,0,0}  // sel_from_rel=2 (来自provider，只能传给customer)
};

MMapFile mmap_file_rw(const std::string &fn, size_t filesize) {
    MMapFile mf;

    // 打开文件（rw）
    mf.fd = open(fn.c_str(), O_RDWR | O_CREAT, 0666);
    if (mf.fd < 0) throw std::runtime_error("open failed");

    // 确保文件大小足够（没有则扩展）
    if (ftruncate(mf.fd, filesize) != 0)
        throw std::runtime_error("ftruncate failed");

    mf.size = filesize;

    // 映射为可读可写共享映射
    mf.ptr = mmap(nullptr, mf.size, PROT_READ | PROT_WRITE, MAP_SHARED, mf.fd, 0);
    if (mf.ptr == MAP_FAILED)
        throw std::runtime_error("mmap failed");

    return mf;
}

MMapFile mmap_file_ro(const string &fn, size_t expected) { 
    MMapFile mf; 
    mf.fd = open(fn.c_str(), O_RDONLY); 
    if (mf.fd < 0) throw runtime_error("open matrix"); 
    
    struct stat st; 
    if (fstat(mf.fd, &st) != 0) throw runtime_error("fstat matrix"); 
    
    mf.size = st.st_size; 
    mf.ptr = mmap(nullptr, mf.size, PROT_READ, MAP_SHARED, mf.fd, 0); 
    if (mf.ptr == MAP_FAILED) throw runtime_error("mmap failed"); 
    
    if (mf.size != expected)
        cerr << "Warning: file size " << mf.size << " expected " << expected << "\n";     
    return mf; 
} 

static inline u32 be32_to_host(u32 x) { 
    return ntohl(x); 
} 

vector<u32> read_asns_bin(const string &fn) { 
    struct stat st; 
    if (stat(fn.c_str(), &st) != 0) throw runtime_error("stat failed"); 
    if (st.st_size % 4 != 0) throw runtime_error("asns.bin corrupt"); 
    
    size_t n = st.st_size / 4; 
    int fd = open(fn.c_str(), O_RDONLY); 
    if (fd < 0) throw runtime_error("open asns"); 
    
    vector<u32> tmp(n); 
    ssize_t r = read(fd, tmp.data(), st.st_size); 
    close(fd); 
    
    if (r != (ssize_t)st.st_size) throw runtime_error("read asns short"); 
    
    vector<u32> v; 
    v.reserve(n); 
    for (size_t i = 0; i < n; i++) v.push_back(be32_to_host(tmp[i])); 
    sort(v.begin(), v.end());
    return v; 
} 

// ------------------------------------------------------------- 
// Read AS graph (sim_graph_5_original.txt) 
// ------------------------------------------------------------- 
vector<vector<pair<u32,int>>> read_graph_txt(const string &fn, const unordered_map<uint32_t,uint32_t> &asn2id) { 
    ifstream ifs(fn); 
    if (!ifs) throw runtime_error("open graph"); 
    
    vector<vector<pair<u32,int>>> G(asn2id.size()); 
    string A,B,C; 
    while (ifs >> A >> B >> C) { 
        u32 as1 = stoul(A); 
        u32 as2 = stoul(B); 
        int rel = stoi(C)+1; // 0=customer,1=peer,2=provider
        auto it1 = asn2id.find(as1); 
        auto it2 = asn2id.find(as2); 
        if (it1 == asn2id.end() || it2 == asn2id.end()) continue; 
        G[it1->second].push_back({it2->second, rel}); 
    } 
    return G; 
} 

// ------------------------------------------------------------- 
// Route format: 
// bits 31..30 from_rel 
// bits 29..24 path length (6 bits) 
// bits 23..2 next hop (22 bits) 
// bits 1..0 last_rel 
// ------------------------------------------------------------- 
inline u32 extract_from_rel(u32 x){ return (x >> 30) & 0x3; } 
inline u32 extract_path_len(u32 x){ return (x >> 24) & 0x3F; } 
inline u32 extract_next_hop(u32 x){ return (x >> 2) & 0x3FFFFF; } 
inline u32 extract_last_rel(u32 x){ return x & 0x3; } 

const u32 PATHLEN_CAP = 0x3F; 

void CalRouteInfoMatrixPerOrigin(uint32_t origin, const vector<vector<pair<uint32_t,int>>> &G, uint32_t N,  uint32_t *matrix_u32, uint32_t W, uint64_t *reach_matrix, string type)
{
    vector<u32> priority(N, 3<<30);  // initial worst priority, indicate unreachable
    
    deque<u32> Q;
    vector<char> inQ(N, 0);
    priority[origin] = (0u << 30) | (0u << 24) | ((u32)origin << 2) | 0u;
    Q.push_back(origin);
    inQ[origin] = 1;

    while (!Q.empty()) {
        u32 u = Q.front();
        Q.pop_front();
        inQ[u] = 0;

        u32 best = priority[u];
        u32 sel_from_rel = extract_from_rel(best);
        u32 sel_path_len = extract_path_len(best);
        u32 sel_next_hop = extract_next_hop(best);
        u32 sel_last_rel = extract_last_rel(best);

        if (sel_path_len >= PATHLEN_CAP) continue;

        for (auto &pr : G[u]) {
            u32 v = pr.first;
            int rel_u_to_v = pr.second;
            if (v == sel_next_hop) continue;
            if (sel_from_rel != 0 && rel_u_to_v != 0) continue; //进、出口均非customer，不符合valley-free, 跳过

            int recv_from_rel = 2 - rel_u_to_v; // 例：v对u来说是provider, u对v来说就是customer
            u32 new_len = sel_path_len + 1;
            int last_rel_for_v = (u == origin) ? rel_u_to_v : sel_last_rel;

            u32 cand = ((u32)recv_from_rel << 30) | ((u32)new_len << 24) | ((u32)u << 2) | ((u32)last_rel_for_v);

            u32 old = priority[v];

            if ((cand & 0xFFFFFFFCu) < (old & 0xFFFFFFFCu)) {
                priority[v] = cand;
                if (!inQ[v]) {
                    Q.push_back(v);
                    inQ[v] = 1;
                }
            }
        }
    }

    if (type == "routeinfo") {
        u32* rowptr = &matrix_u32[(size_t)origin * N];
        memcpy(rowptr, priority.data(), N * sizeof(u32));
    }
    else if (type == "reach") {
        uint64_t *rowptr = reach_matrix + (size_t)origin * W;
        memset(rowptr, 0, W * sizeof(uint64_t));
        for (size_t i = 0; i < N; ++i) {
            if (extract_from_rel(priority[i]) == 3) continue;  //不可达
            rowptr[i >> 6] |= (1ULL << (i & 63));
        }
    }
}

void CalReach(string flag) {
    string asns_fn = "../sample_input/asns.bin"; 
    string reach_matrix_fn = "../sample_output/new_reach_matrix_" + flag + ".bin";
    int num_threads = 40; 
    double t0 = omp_get_wtime(); 

    // read asns and build idx map 
    auto asns = read_asns_bin(asns_fn); 
    sort(asns.begin(), asns.end()); 
    size_t N = asns.size(); 
    size_t W = (N + 63) / 64; 
    unordered_map<u32,u32> asn2id; 
    asn2id.reserve(N); 
    for (size_t i = 0; i < N; ++i) asn2id[asns[i]] = (u32)i;    
    // mmap 文件
    const size_t reach_matrix_fn_size = N * W * sizeof(uint64_t);
    MMapFile mf = mmap_file_rw(reach_matrix_fn, reach_matrix_fn_size);
    uint64_t *reach_matrix = reinterpret_cast<uint64_t*>(mf.ptr);
    memset(reach_matrix, 0, reach_matrix_fn_size);
    
    vector<atomic<u32>> infection_counts(N);
    
    // load graph 
    auto G = read_graph_txt("../sample_output/sim_graph_" + flag + ".txt", asn2id); 
    cerr << "Graphs loaded\n"; 

    // thread running
    vector<thread> threads; 
    for (int t = 0; t < num_threads; ++t) { 
        threads.emplace_back([N, W, num_threads, t, &G, reach_matrix, &infection_counts]() {
            for (size_t origin = 0; origin < N; ++origin) {
                if ((origin % num_threads) != t) continue;
                CalRouteInfoMatrixPerOrigin(origin, G, N, nullptr, W, reach_matrix, "reach");
                u32 c = 0;
                uint64_t *row = reach_matrix + (origin * W);
                for(size_t j = 0; j < W; ++j) c += __builtin_popcountll(row[j]);
                infection_counts[origin] = c;
            }
        });
    }
    for (auto &th : threads) th.join(); 
    // 4. 写回磁盘
    ofstream ofs("../sample_output/infection_stats_" + flag + ".csv");
    ofs << "origin_id,asn,impact_count\n";
    for (size_t i = 0; i < N; ++i) {
        ofs << i << "," << asns[i] << "," << infection_counts[i] << "\n";
    }
    ofs.close();

    msync(mf.ptr, mf.size, MS_SYNC);
    munmap(mf.ptr, mf.size);
    close(mf.fd);
    double t1 = omp_get_wtime(); 
    cout << "elapsed " << (t1 - t0) << " s\n"; 
}

int main(int argc, char **argv) {
    CalReach(argv[1]);
    return 0;
}
