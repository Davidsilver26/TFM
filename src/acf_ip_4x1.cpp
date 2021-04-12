#include "HTmap.hpp"
#include "utils.h"
#include <string.h>
#include <iostream>
#include <vector>
#include <map>

#include <fstream>
#include <chrono>
#include <stdarg.h>

bool quiet=false;
//int verbose=0; // define the debug level
int seed = 12342;

//d=4, b=1 (first variant)
int num_way=4;      //# of ways (hash functions)
int num_cells=1;  //# of slots in a rows
int ht_size=80000; //# of rows
int fingerprint_bits=12; //# of fingerprint bits
int fbhs=9;
int skewed=0;

int max_loop=1;    //num of trials
int load_factor=95;    //load factor
int AS=32;
int A=0;
//int npf=1000;
int npf=10;
int bhs=1;

//progress bar data
bool verbose_out = false; //verbose
const int prog_bar_size = 50;
string prog_bar;

int64_t tot_access=0;
int64_t tot_FF_FP=0;


map<int64_t,int> A_map;
vector<int64_t> A_ar;

//select the fingerprint function
//                                        16-bhs  
int fingerprint(int64_t key,int index,int a) {
    int s=bhs;
    int r=skewed;
    int range= (1<<(a-r+s))*((1<<r)-1); 
    int range2= 1<<(a-r);
    if  (index>0) range=range2;

    if (r==0) 
	    return hashg(key,20+index,1<<a); 
    else
        return hashg(key,20+index,range);
}


//read a complete file (skip empty lines)
vector<string> read_lines(ifstream & infile){

  //set offset to 0 and read lines
  infile.seekg(0);

  vector<string> lines;
  string line;

  while( getline(infile, line) ){
    if( !line.empty() ){
      lines.push_back(line);
    }
  }

  return lines;
}


// check if given string is a numeric string or not
bool is_number(const string& str){
    return !str.empty() && (str.find_first_not_of("[0123456789]") == string::npos);
}


//split string by a delimiter
vector<string> split_string(string input, char delim){

  size_t pos = 0;
  vector<string> list;
  string token;

  while ((pos = input.find(delim)) != string::npos) {
    token = input.substr(0, pos);
    list.push_back(token);
    input.erase(0, pos + 1);
  }
  token = input;
  list.push_back(token);

  return list;
}


//check if an IP has the correct format
bool valid_ip(string ip_string){ // valid format x.x.x.x (x: 0-255)

  vector<string> ip_vector = split_string(ip_string, '.');

  if(ip_vector.size() != 4) return false;

  for(string s : ip_vector){
    if( !is_number(s) || s.length() > 3 || stoi(s) < 0 || stoi(s) > 255 ) return false;
  }
  
  return true;
}


//obtain integer key value from an IP
int64_t ip_string_to_key(string input){ // required input format x.x.x.x (x: 0-255)

  int64_t key = 0; // output key format xxxx (x: 000-255)

  vector<string> ip_vector = split_string(input, '.');
  
  for(string s : ip_vector){
    key = key * 1000 + stoi(s);
  }

  return key;
}


//obtaion IP string from a key value
string ip_key_to_string(int64_t key){ // required key format xxxx (x: 000-255)
  
  string ip = ""; // IP output format x.x.x.x (x: 0-255)

  ip = to_string(key % 1000);
  key = key / 1000;
  ip = to_string(key % 1000) + "." + ip;
  key = key / 1000;
  ip = to_string(key % 1000) + "." + ip;
  key = key / 1000;
  ip = to_string(key % 1000) + "." + ip;

  return ip;
}


//print progress bar
void print_progress(int current, int total){
  if(current == 0){ //init progress bar
    prog_bar = string (prog_bar_size, ' ');
    cerr << "[" << prog_bar << "] " << "0%" << "\r";
  }else if(current == total-1){ //last one
    cerr << "[" << prog_bar << "] " << "100%" << "\n";
  }else if(current % (total / 100) == 0){
    int percent = current * 100 / total;
    prog_bar[current * prog_bar_size / total] = '=';
    cerr << "[" << prog_bar << "] " << percent << "%" << "\r";
  }
}


//fill IP key vector from IP list file
vector<int64_t> file_to_ip(string filename){

  vector<int64_t> ip_keys;

  ifstream infile(filename);

  if(infile.fail()){
    printf("Can not open file %s\n", filename.c_str());
    ip_keys.clear();
    return ip_keys;
  }

  vector<string> file_lines = read_lines(infile);
  infile.close();

  int invalid_ips = 0;

  printf("Reading %s\n", filename.c_str());

  for(uint i = 0; i < file_lines.size(); i++){
    
    //progress bar
    if(verbose_out) print_progress(i, file_lines.size());
    
    if( !valid_ip(file_lines[i]) ){
      printf("\nInvalid IP format <%s> in line %d\n", file_lines[i].c_str(), (i+1) );
      invalid_ips++;
    }else{
      ip_keys.push_back(ip_string_to_key(file_lines[i]));
    }
  }

  file_lines.clear();

  if(invalid_ips > 0){
    printf("The file %s contains errors\n", filename.c_str());
    ip_keys.clear();
    return ip_keys;
  }

  return ip_keys;
}


void print_usage() {
   printf("usage:\n");
   printf(" ***\n");
   printf(" -m tsize: Table size\n");
   printf(" -f f_bits: number of fingerprint bits\n");
   printf(" -b b_bits: number of selection bits\n");
   printf(" -k skewness: skewness factor\n");
   printf(" -n num_packets: number of packets for each flow \n");
   printf(" -a as_ratio: set the A/S ratio \n");
   printf(" -S seed: select random seed (for debug)\n");
   printf(" -L load_factor : set the ACF load factor \n");
   printf(" -v : verbose \n");
   printf(" -h print usage\n");
   printf(" -v verbose enabled\n");
}

int init(int argc, char* argv[])
{
    printf("\n===========================================\n");
    printf("Simulator for the Adaptive Cuckoo Filter with 4x1 tables\n");
    printf("Run %s -h for usage\n",argv[0]);
    printf("===========================================\n\n");



    //code_version();
    //print_hostname();
    //print_command_line(argc,argv); //print the command line with the option
    // Check for switches
    while (argc > 1 && argv[1][0] == '-'){
        argc--;
        argv++;
        int flag=0; //if flag 1 there is an argument after the switch
        int c = 0;
        while ((c = *++argv[0])){
            switch (c) {
                case 'q':
                    printf("\nQuiet enabled\n");
                    quiet=true;
                    break;
		case 'a':
                    flag=1;
                    AS=atoi(argv[1]);
                    argc--;
                    break;
                case 'k':
                    flag=1;
                    printf("Skewed enabled\n");
                    skewed=atoi(argv[1]);
                    argc--;
                    break;
                case 'b':
                    flag=1;
                    bhs=atoi(argv[1]);
                    argc--;
                    break;
                case 'm':
                    flag=1;
                    ht_size=atoi(argv[1]);
                    argc--;
                    break;
                case 'f':
                    flag=1;
                    fingerprint_bits=atoi(argv[1]);
                    argc--;
                    break;
                case 'S':
                    flag=1;
                    seed=atoi(argv[1]);
                    argc--;
                    break;
                case 'n':
                    flag=1;
                    npf=atoi(argv[1]);
                    argc--;
                    break;
                case 'L':
                    flag=1;
                    load_factor=atoi(argv[1]);
                    argc--;
                    break;
                case 'v':
                    printf("\nVerbose enabled\n");
                    verbose += 1;
                    break;
                case 'h':
                    print_usage();
                    exit(1);
                    break;
                default :
                    printf("Illegal option %c\n",c);
                    print_usage();
                    exit(1);
                    break;
            }
        }
        argv= argv + flag;
    }
    A=ht_size*num_way*num_cells*AS;
    fbhs=fingerprint_bits-bhs;
    //Print general parameters
    printf("general parameters: \n");
    if (skewed>0) {
        printf("Enable skewed fingerprint\n");
        printf("f0 range: %d/%d \n",(1<<skewed)-1,1<<skewed);
    }
    max_loop= 250*(1<<((fingerprint_bits-8)/2))/AS; 
    printf("seed: %d\n",seed);
    printf("way: %d\n",num_way);
    printf("num_cells: %d\n",num_cells);
    printf("Table size: %d\n",ht_size);
    printf("bhs: %d\n",bhs);
    printf("A size: %d\n",A);
    printf("iterations: %d\n",max_loop);
    printf("AS ratio: %d\n",AS);
    printf("npf: %d\n",npf);
    printf("---------------------------\n");

    return 0;
}


//program main
int main(int argc, char **argv){

    //srand(seed);

    if(init(argc,argv) != 0){
        //errors in init
        print_usage();
        return 1;
    }
    
    auto time_ini = chrono::system_clock::now();

    verbose_out = true; ////////////////////////////////////////////////

    printf("\n");
    
    //read blacklist
    vector<int64_t> ip_blacklist_keys = file_to_ip("blacklists/listed_ip_180.txt");

    if(ip_blacklist_keys.size() == 0){
        printf("Exiting...\n");
        return 1;
    }


    //read whitelist
    vector<int64_t> ip_whitelist_keys = file_to_ip("whitelists/100K_listed_ip_180.txt");

    if(ip_whitelist_keys.size() == 0){
        printf("Exiting...\n");
        return 1;
    }

    //Starting AFC
    printf("\nStarting the Adaptive Cuckoo Filter 2x4\n");
    //Print general parameters
    printf("general parameters:\n");
    printf("way: %d\n", num_way);
    printf("cells: %d\n", num_cells);
    printf("Table size: %d\n", ht_size);
    printf("Buckets: %d\n", num_way * num_cells * ht_size);
    printf("Fingerprint bits: %d\n", fingerprint_bits); ///////////////////////////////////////
    printf("Fingerprint (bhs) bits: %d\n",fbhs);
    printf("Rotate fingerprint bits: %d\n", bhs);
    printf("Blacklist IPs: %ld\n", ip_blacklist_keys.size());
    printf("Whitelist IPs: %ld\n", ip_whitelist_keys.size());
    printf("\n");
    
    
    //Create Cuckoo table
    HTmap<int64_t,int> cuckoo(num_way,num_cells,ht_size,1000);
    cuckoo.clear();

    //Create ACF
    pair<int,int>** FF= new pair<int,int>*[num_way];
    for (int i = 0;  i < num_way;  i++) {
        FF[i]= new pair<int,int>[ht_size];

        //Clean ACF
        for (int ii = 0;  ii < ht_size;  ii++){
            FF[i][ii] = make_pair(0,-1);
        }
    }

    map<int64_t,int> S_map;
    S_map.clear();
    int num_fails = 0;

    for(int64_t key : ip_blacklist_keys){

        if( S_map.count(key) > 0 ){
            printf("Value %ld already exists\n", key);
        }else{
            S_map[key] = 5;

            if( !cuckoo.insert(key,5) ){
                printf("Table full (key: %ld)\n", key);
                num_fails++;
            }
        }
    }

    if(num_fails > 0){
        printf("Exiting...\n");
        return 1;
    }


    printf("Cuckoo table statistics\n");
    printf("items: %d\n", cuckoo.get_nitem());
    printf("load: %f\n", cuckoo.get_nitem()/(0.0+cuckoo.get_size()) );
    printf("total size: %d\n", cuckoo.get_size());
    printf("\n");
    cuckoo.stat();

    for (auto x: S_map){

        //Insert in ACF
        auto res= cuckoo.fullquery(x.first);
        FF[std::get<1>(res)][std::get<3>(res)]=make_pair(0,fingerprint(x.first,0,fbhs));
    }


    int total_swaps = 0; //total number of swaps

    printf("Removing FPs\n");
    //////////////////////////////////////////////////////////////iterations
    //Remove false positives
    for(int iter = 0; iter < (int)ip_whitelist_keys.size(); iter++){

        //progress bar
        if(verbose_out) print_progress(iter, (int)ip_whitelist_keys.size());

        bool false_FF = false;
        int false_i = -1;

        int64_t ip_key = ip_whitelist_keys.at(iter);

        for (int i = 0; i < num_way; i++) {
            int p = myhash<int64_t>(ip_key, i, ht_size);
            int ii=FF[i][p].first;
            if (fingerprint(ip_key, ii, fbhs) == FF[i][p].second) {
                false_FF = true;
                false_i = i;
                break;
            }
        }

        //SWAP
        if(false_FF){
            total_swaps++;

            int p = myhash<int64_t>(ip_key, false_i, ht_size);
            int64_t key1 = cuckoo.get_key(false_i,0,p);

            if (skewed>0){
                FF[false_i][p].first = (FF[false_i][p].first +1) % ((1<<bhs)+1);
            }else{
                FF[false_i][p].first = (FF[false_i][p].first +1) % (1<<bhs);
            }

            FF[false_i][p].second = fingerprint(key1,FF[false_i][p].first,fbhs);
        }
    }
    

    //Verify again all the IPs
    printf("\nStarting final verification...\n");
    int final_fp = 0; //number of false positive

    for(int iter = 0; iter < (int)ip_whitelist_keys.size(); iter++){

        //progress bar
        if(verbose_out) print_progress(iter, (int)ip_whitelist_keys.size());

        int64_t ip_key = ip_whitelist_keys.at(iter);
        
        for (int i = 0;  i < num_way;  i++) {
            int p = myhash<int64_t>(ip_key, i, ht_size);
            int ii=FF[i][p].first;
            if(fingerprint(ip_key, ii, fbhs) == FF[i][p].second){
                final_fp++;
            }
        }
    }

    printf("Verification completed successfully\n");

    printf("\nAdaptive Cuckoo Filter statistics:\n");
    printf("Total FP: %d\n", final_fp);
    printf("Total SWAPS: %d\n", total_swaps);


    auto time_end = chrono::system_clock::now();
    auto execution_seconds = chrono::duration_cast<chrono::seconds>(time_end-time_ini).count();
    printf("Execution time: %ld seconds\n", execution_seconds);

    //fini

    return 0;
}