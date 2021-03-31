#include "HTmap.hpp"
#include "utils.h"
#include <string.h>
#include <iostream>
#include <vector>
#include <map>
#include <time.h>
#include <limits.h>
#include <random>
#include <algorithm>

#include <fstream>
#include <chrono>

using namespace std;

const int num_way=2;      //# of ways (hash functions)
const int num_cells=4;  //# of slots in a rows

int ht_size=40000; //# of rows
int f=10; //# of fingerprint bits

const bool allow_fp = true; //allow false positives
const int restart_limit = 2; //max restart value

string file_blacklist;
string file_whitelist;

int seed = 12342; //random seed


//generate a fingerprint
int fingerprint(int64_t key,int index,int f) {
    return hashg(key,20+index,1<<f);
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
    return !str.empty() && (str.find_first_not_of("[0123456789]") == std::string::npos);
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


//program usage
void print_usage() {
   printf("Usage:\n");
   printf(" *** MANDATORY ***\n");
   printf(" -b blacklist: input blacklist file\n");
   printf(" -w whitelist: input whitelist file\n");
   printf(" *** OPTIONAL ***\n");
   printf(" -m tsize: Table size\n");
   printf(" -f f_bits: number of fingerprint bits\n");
   printf(" -h print usage\n");
   /*printf(" -a as_ratio: set the A/S ratio \n");
   printf(" -S seed: select random seed (for debug)\n");
   printf(" -L load_factor : set the ACF load factor \n");
   printf(" -v : verbose \n");
   printf(" -v verbose enabled\n");*/
}


//initialize
int init(int argc, char* argv[]){

  int args_processed = 0;

  //program name
  args_processed++;

  //read arguments
  while(args_processed < argc){
    
    string option_type(argv[args_processed]);
    args_processed++;

    if(option_type.length() == 2 && option_type.at(0) == '-'){

      char option = option_type.at(1);

      switch (option){
        case 'm':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(is_number(option_value)){
              ht_size = stoi(option_value);
            }else{
              cerr << "Option -" << option << " " << option_value << " is not a number" << endl;
              return 1;
            }
          }else{
            cerr << "Option -" << option << " need a value" << endl;
            return 1;
          }
          break;

        case 'f':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(is_number(option_value)){
              f = stoi(option_value);
            }else{
              cerr << "Option -" << option << " " << option_value << " is not a number" << endl;
              return 1;
            }
          }else{
            cerr << "Option -" << option << " need a value" << endl;
            return 1;
          }
          break;

        case 'b':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(option_value.length() > 0){
              file_blacklist = option_value;
            }
            
          }else{
            cerr << "Option -" << option << " need a value" << endl;
            return 1;
          }
          break;

        case 'w':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(option_value.length() > 0){
              file_whitelist = option_value;
            }
            
          }else{
            cerr << "Option -" << option << " need a value" << endl;
            return 1;
          }
          break;

        /*case 'h':
          if(is_number(option_value)){
            f = stoi(option_value);
          }else{
            cerr << "Option -" << option << " " << option_value << " is not a number" << endl;
            return 1;
          }
          break;*/
      
        default:
          cerr << "Illegal option -" << option << endl;
          return 1;
          break;
      }
      
    }else{
      //invalid program call
      return 1;
    }
  }

  //check mandatory arguments filled
  if(file_blacklist.length() == 0 ||
     file_whitelist.length() == 0){
    cerr << "Mandatory options required" << endl;
    return 1;
  }

  return 0;
}


//program main
int main(int argc, char **argv) {

  srand(seed);

  if(init(argc, argv) == 1){
    //initialize errors
    print_usage();
    return 1;
  }

  auto time_ini = std::chrono::system_clock::now();

  //read blacklist
  ifstream infile_blacklist(file_blacklist);

  if(infile_blacklist.fail()){
    cerr << "Can not open file " << file_blacklist << endl;
    return 1;
  }

  vector<string> lines_blacklist = read_lines(infile_blacklist);

  printf("Total lines: %ld\n", lines_blacklist.size());
  
  infile_blacklist.close();

  vector<int64_t> ip_blacklist_keys;
  int invalid_ips = 0;

  for(uint i = 0; i < lines_blacklist.size(); i++){
    if( !valid_ip(lines_blacklist[i]) ){
      cerr << "Invalid IP format <" << lines_blacklist[i] << "> in line " << (i+1) << endl;
      invalid_ips++;
    }else{
      ip_blacklist_keys.push_back(ip_string_to_key(lines_blacklist[i]));
      //////////////////////cout << lines[i] << "\t" << ip_string_to_key(lines[i]) << endl;
    }
  }

  lines_blacklist.clear();

  if(invalid_ips > 0){
    cerr << "The file " << file_blacklist << " contains errors" << endl;
    cerr << "Exiting..." << endl;
    return 1;
  }


  //Create Cuckoo table
  HTmap<int64_t,int> cuckoo(num_way,num_cells,ht_size,1000);

  //Create ACF
  int*** FF= new int**[num_way];
  for (int i = 0;  i <num_way;  i++) {
      FF[i] = new int*[num_cells];
      for (int ii = 0;  ii <num_cells;  ii++){
          FF[i][ii]= new int[ht_size];

          //Clean ACF
          for (int iii = 0; iii <ht_size; iii++){
            FF[i][ii][iii] = -1;
          }
      }
  }

  map<int64_t,int> S_map;
  S_map.clear();
  int num_fails = 0;

  for(int64_t key : ip_blacklist_keys){

    //int itIP = ip_list[i];
    int64_t itIP = key;

    if( S_map.count(itIP) > 0 ){
      printf("Value %ld already exists\n", itIP);
    }else{
      //printf("Added %d to list\n", itIP);
      S_map[itIP] = 5;

      if( !cuckoo.insert(itIP,5) ){
        printf("Table full (key: %ld)\n",itIP);
        num_fails++;
      }
    }
  }

  if(num_fails > 0){
    printf("Exiting...");
    return 1;
  }
  
  printf("Total values of the list: %ld\n", S_map.size());

  printf("items= %d\n",cuckoo.get_nitem());
  printf("load: %f \n",cuckoo.get_nitem()/(0.0+cuckoo.get_size()));
  printf("Total size: %d\n", cuckoo.get_size());
  cuckoo.stat();

  for( auto x: S_map){

    //printf("value %ld - %d\n", x.first, x.second);

    //Insert in ACF
    auto res = cuckoo.fullquery(x.first);
    FF[std::get<1>(res)][std::get<2>(res)][std::get<3>(res)]=fingerprint(x.first,std::get<2>(res),f);

  }


  //read whitelist
  ifstream infile_whitelist(file_whitelist);

  if(infile_whitelist.fail()){
    cerr << "Can not open file " << file_whitelist << endl;
    return 1;
  }

  vector<string> lines_whitelist = read_lines(infile_whitelist);

  printf("Total lines good ips: %ld\n", lines_whitelist.size());
  
  infile_whitelist.close();

  vector<int64_t> ip_whitelist_keys;
  invalid_ips = 0;

  for(uint i = 0; i < lines_whitelist.size(); i++){
    if( !valid_ip(lines_whitelist[i]) ){
      cerr << "Invalid IP format <" << lines_whitelist[i] << "> in line " << (i+1) << endl;
      invalid_ips++;
    }else{
      ip_whitelist_keys.push_back(ip_string_to_key(lines_whitelist[i]));
      //////////////////////cout << lines[i] << "\t" << ip_string_to_key(lines[i]) << endl;
    }
  }

  if(invalid_ips > 0){
    cerr << "The file " << file_whitelist << " contains errors" << endl;
    cerr << "Exiting..." << endl;
    return 1;
  }

  
  int final_fp = 0; //number of false positive
  
  int cont_swaps = 0; //number of swaps
  int reswap_attempts = 0; //number of reswaps (in the same key)
  int total_reswaps_attempts = 0; //number of reswaps total
  int64_t key_last_swap = -1;

  const int reswap_limit = 100;

  bool restart = false; //restart remove fp indicator
  int cont_restart = 0; //number of restarts

  int max_iter = 0;

  //Remove false positives
  for(int iter = 0; iter < (int)ip_whitelist_keys.size(); iter++){

    if(iter > max_iter) max_iter = iter;

    if(iter%250000 == 0) cout << "Tested " << iter << " IPs" << endl;

    bool false_FF = false;
    int false_i = -1;
    int false_ii = -1;

    int64_t ip_key = ip_whitelist_keys.at(iter);
    
    for (int i = 0;  i <num_way;  i++) {
      int p = hashg(ip_key, i, ht_size);
      for (int ii = 0;  ii <num_cells;  ii++){
        if(fingerprint(ip_key, ii, f) == FF[i][ii][p]){
          //cout << "FALSE POSITIVE with IP " << ip_key <<endl;

          false_FF = true;
          false_i = i;
          false_ii = ii;
          break;
        }
      }

      if(false_FF) break;
    }

    //SWAP
    //continue;
    if(false_FF){

      restart = true;
      bool skip_swap = false;

      //manage SWAP block
      if(key_last_swap == ip_key){
        
        if(reswap_attempts >= reswap_limit){
          cout << "SWAP BLOCKED by IP - " << ip_key << " with " << reswap_attempts << " attempts" << endl;
          //cout << "Exiting..." << endl;
          //skip swapping this key
          skip_swap = true;
          continue;
          //break;
          //return 1;
        }else{
          reswap_attempts++;
          total_reswaps_attempts++;
        }
        
      }else{
        reswap_attempts = 0;
      }

      key_last_swap = ip_key;

      if(!skip_swap){
        //DO SWAP
        cont_swaps++;

        int p = hashg(ip_key, false_i, ht_size);

        int64_t key1= cuckoo.get_key(false_i,false_ii,p);
        int value1 = cuckoo.query(key1);

        int new_ii=false_ii;
        while (new_ii==false_ii) new_ii=rand()%num_cells;

        int64_t key2 = cuckoo.get_key(false_i,new_ii,p);
        int value2 = cuckoo.query(key2);

        //cout << "FALSE POSITIVE with IP - " << key1 << " FF[" << false_i << "][" << false_ii << "][" << p << "] = " << FF[false_i][false_ii][p] <<endl;
        //cout << "SWAP with IP " << key2 << " FF[" << false_i << "][" << new_ii << "][" << p << "] = " << FF[false_i][new_ii][p] <<endl;

        if(!cuckoo.remove(key1)){
          cerr << "PANIC! Error during SWAP" << endl;
        }

        if(!cuckoo.remove(key2)){ // the position of new_ii was free
          FF[false_i][false_ii][p]=-1;
        }else{
          cuckoo.direct_insert(key2, value2, false_i, false_ii);
          FF[false_i][false_ii][p] = fingerprint(key2, false_ii, f);
        }

        cuckoo.direct_insert(key1, value1, false_i, new_ii);
        FF[false_i][new_ii][p] = fingerprint(key1,new_ii,f);
        
        //cout << "NEW VALUES with IP - " << key1 << " FF[" << false_i << "][" << new_ii << "][" << p << "] = " << FF[false_i][new_ii][p] <<endl;
        //cout << "NEW VALUES with IP - " << key2 << " FF[" << false_i << "][" << false_ii << "][" << p << "] = " << FF[false_i][false_ii][p] <<endl;

        //check again this iteration
        iter--;
      }
    }

    //restart (check again all the list)
    if(iter == (int)ip_whitelist_keys.size() -1 && restart){
      if(allow_fp){
        /////////////////////////////////////////////////juntar en un if?
        //check for restart limit
        if(cont_restart < restart_limit){
          //restart limit not reached
          cout << "Total SWAPS " << cont_swaps << endl;
          cout << "restart again" << endl; 
          iter = -1;

          cont_restart++;
          restart = false;
        }else{
          cout << "limit reached" << endl;
        }
      }else{
        //force restart
        cout << "Total SWAPS " << cont_swaps << endl;
        cout << "restart again" << endl; 
        iter = -1;
        cont_restart++;
        restart = false;
      }
    }
  }


  //Verify again all the IPs
  cout << "Starting final verification..." << endl;
  for(int iter = 0; iter < (int)ip_whitelist_keys.size(); iter++){

    int64_t ip_key = ip_whitelist_keys.at(iter);
    
    for (int i = 0;  i <num_way;  i++) {
      int p = hashg(ip_key, i, ht_size);
      for (int ii = 0;  ii <num_cells;  ii++){
        if(fingerprint(ip_key, ii, f) == FF[i][ii][p]){
          final_fp++;
          /*cout << "False positive found!" << endl;
          cout << "Exiting..." << endl;
          return 1;*/
        }
      }
    }
  }

  cout << "Verification completed successfully" << endl;

  cout << "Total FP " << final_fp << endl; 
  cout << "Total SWAPS " << cont_swaps << endl;
  cout << "Total RE-SWAPS " << total_reswaps_attempts << endl;
  

  auto time_end = chrono::system_clock::now();
  auto execution_seconds = chrono::duration_cast<chrono::seconds>(time_end-time_ini).count();
  cout << "Execution time: " << execution_seconds << " seconds" << endl;

  return 0;
}
