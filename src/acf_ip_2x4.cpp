#include "HTmap.hpp"
#include "utils.h"
#include <string.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <map>

#include <fstream>
#include <chrono>
#include <stdarg.h>

using namespace std;

const int num_way=2;      //# of ways (hash functions)
const int num_cells=4;  //# of slots in a rows

int ht_size=40000; //# of rows
int fingerprint_bits=10; //# of fingerprint bits
const int seed = 12342; //random seed

bool allow_fp = true; //allow false positives
int restart_limit = 20; //max restart value

string file_blacklist;
string file_whitelist;

//output file
bool generate_output = false;
string file_output;
ofstream output;

//progress bar data
bool verbose_out = false; //verbose
const int prog_bar_size = 50;
string prog_bar;


//generate a fingerprint
int fingerprint(int64_t key,int index,int f) {
    return hashg(key,20+index,1<<f);
}


//printf and (if required) copy to file
void print_and_file(const char * format, ...){

  va_list args;
  va_start(args, format);

  ssize_t size = vsnprintf(NULL, 0, format, args);
  size ++; //to include '\0'
  char output_data[size];

  va_start(args, format); //reload arguments (printf clean arguments)
  vsnprintf(output_data, size, format, args);

  cout << output_data; //print in standard output
  if(generate_output) output << output_data; //print in output file

  va_end(args);
}


//get command line
string get_command_line(int argc, char* argv[]) {
  string command = "";
	char **currentArgv = argv;
	for (int i = 0; i < argc; i ++) {
    command += *currentArgv;
		currentArgv++; /* Next arg. */
	}
	return command + "\n";
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


//program usage
void print_usage() {
  print_and_file("\nUsage:\n");
  print_and_file(" *** MANDATORY ***\n");
  print_and_file(" -b blacklist: input blacklist file\n");
  print_and_file(" -w whitelist: input whitelist file\n");
  print_and_file(" *** OPTIONAL ***\n");
  print_and_file(" -m tsize: Table size (default: %d)\n", ht_size);
  print_and_file(" -f f_bits: number of fingerprint bits (default: %d)\n", fingerprint_bits);
  print_and_file(" -r restart_limit: reduce false positive max restarts (default: %d)\n", restart_limit);
  print_and_file(" -o output_file: name of the output file\n");
  print_and_file(" -v : verbose \n");
  print_and_file(" -h : print usage \n");
}


//initialize
int init(int argc, char* argv[]){

  cout << endl << get_command_line(argc, argv); //print the command line with the option

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

        case 'b':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(option_value.length() > 0){
              file_blacklist = option_value;
            }
            
          }else{
            print_and_file("Option -%c need a value\n", option);
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
            print_and_file("Option -%c need a value\n", option);
            return 1;
          }
          break;

        case 'm':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(is_number(option_value)){
              ht_size = stoi(option_value);
            }else{
              print_and_file("Option -%c %s is not a number\n", option, option_value.c_str());
              return 1;
            }
          }else{
            print_and_file("Option -%c need a value\n", option);
            return 1;
          }
          break;

        case 'f':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(is_number(option_value)){
              fingerprint_bits = stoi(option_value);
            }else{
              print_and_file("Option -%c %s is not a number\n", option, option_value.c_str());
              return 1;
            }
          }else{
            print_and_file("Option -%c need a value\n", option);
            return 1;
          }
          break;

        case 'r':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(is_number(option_value)){
              restart_limit = stoi(option_value);
            }else{
              print_and_file("Option -%c %s is not a number\n", option, option_value.c_str());
              return 1;
            }
          }else{
            print_and_file("Option -%c need a value\n", option);
            return 1;
          }
          break;

        case 'o':
          if(args_processed < argc){
            string option_value(argv[args_processed]);
            args_processed++;

            if(option_value.length() > 0){
              file_output = option_value;
              generate_output = true;
              //create output file
              output = ofstream (file_output);
              output << get_command_line(argc, argv);
            }
            
          }else{
            print_and_file("Option -%c need a value\n", option);
            return 1;
          }
          break;

        case 'v':
          verbose_out = true;
          break;

        case 'h':
          return 1;
          break;
      
        default:
          print_and_file("Illegal option -%c\n", option);
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
    print_and_file("Mandatory options required\n");
    return 1;
  }

  return 0;
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
    print_and_file("Can not open file %s\n", filename.c_str());
    ip_keys.clear();
    return ip_keys;
  }

  vector<string> file_lines = read_lines(infile);
  infile.close();

  int invalid_ips = 0;

  print_and_file("Reading %s\n", filename.c_str());

  for(uint i = 0; i < file_lines.size(); i++){
    
    //progress bar
    if(verbose_out) print_progress(i, file_lines.size());
    
    if( !valid_ip(file_lines[i]) ){
      print_and_file("\nInvalid IP format <%s> in line %d\n", file_lines[i].c_str(), (i+1) );
      invalid_ips++;
    }else{
      ip_keys.push_back(ip_string_to_key(file_lines[i]));
    }
  }

  file_lines.clear();

  if(invalid_ips > 0){
    print_and_file("The file %s contains errors\n", filename.c_str());
    ip_keys.clear();
    return ip_keys;
  }

  return ip_keys;
}


//program main
int main(int argc, char **argv) {

  srand(seed);

  if(init(argc, argv) != 0){
    //errors in init
    print_usage();
    return 1;
  }

  auto time_ini = chrono::system_clock::now();

  print_and_file("\n");

  //read blacklist
  vector<int64_t> ip_blacklist_keys = file_to_ip(file_blacklist);

  if(ip_blacklist_keys.size() == 0){
    print_and_file("Exiting...\n");
    return 1;
  }


  //read whitelist
  vector<int64_t> ip_whitelist_keys = file_to_ip(file_whitelist);

  if(ip_whitelist_keys.size() == 0){
    print_and_file("Exiting...\n");
    return 1;
  }


  //Starting AFC
  print_and_file("\nStarting the Adaptive Cuckoo Filter 2x4\n");
  //Print general parameters
  print_and_file("general parameters:\n");
  print_and_file("way: %d\n", num_way);
  print_and_file("cells: %d\n", num_cells);
  print_and_file("Table size: %d\n", ht_size);
  print_and_file("Buckets: %d\n", num_way * num_cells * ht_size);
  print_and_file("Fingerprint bits: %d\n", fingerprint_bits);
  print_and_file("Restart limit: %d\n", restart_limit);
  print_and_file("Blacklist IPs: %ld\n", ip_blacklist_keys.size());
  print_and_file("Whitelist IPs: %ld\n", ip_whitelist_keys.size());
  print_and_file("\n");


  //Create Cuckoo table
  HTmap<int64_t,int> cuckoo(num_way,num_cells,ht_size,1000);
  cuckoo.clear();

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

    if( S_map.count(key) > 0 ){
      print_and_file("Value %ld already exists\n", key);
    }else{
      S_map[key] = 5;

      if( !cuckoo.insert(key,5) ){
        print_and_file("Table full (key: %ld)\n", key);
        num_fails++;
      }
    }
  }

  if(num_fails > 0){
    print_and_file("Exiting...\n");
    return 1;
  }
  

  print_and_file("Cuckoo table statistics\n");
  print_and_file("items: %d\n", cuckoo.get_nitem());
  print_and_file("load: %f\n", cuckoo.get_nitem()/(0.0+cuckoo.get_size()) );
  print_and_file("total size: %d\n", cuckoo.get_size());
  print_and_file("\n");
  cuckoo.stat();

  for( auto x: S_map){

    //Insert in ACF
    auto res = cuckoo.fullquery(x.first);
    FF[get<1>(res)][get<2>(res)][get<3>(res)]=fingerprint(x.first,get<2>(res),fingerprint_bits);

  }

  
  int cont_swaps = 0; //number of swaps
  int total_swaps = 0; //total number of swaps
  int reswap_attempts = 0; //number of reswaps (in the same key)
  int total_reswaps_attempts = 0; //number of reswaps total
  const int reswap_limit = 100;

  int64_t key_last_swap = -1;

  bool restart = false; //restart remove fp indicator
  int cont_restart = 0; //number of restarts

  print_and_file("Removing FPs\n");

  //Remove false positives
  for(int iter = 0; iter < (int)ip_whitelist_keys.size(); iter++){

    //progress bar
    if(verbose_out) print_progress(iter, (int)ip_whitelist_keys.size());

    bool false_FF = false;
    int false_i = -1;
    int false_ii = -1;

    int64_t ip_key = ip_whitelist_keys.at(iter);
    
    for (int i = 0;  i <num_way;  i++) {
      int p = hashg(ip_key, i, ht_size);
      for (int ii = 0;  ii <num_cells;  ii++){
        if(fingerprint(ip_key, ii, fingerprint_bits) == FF[i][ii][p]){
          false_FF = true;
          false_i = i;
          false_ii = ii;
          break;
        }
      }

      if(false_FF) break;
    }

    //SWAP
    if(false_FF){

      restart = true;
      bool skip_swap = false;

      //manage SWAP block
      if(key_last_swap == ip_key){
        
        if(reswap_attempts >= reswap_limit){
          //print_and_file("\nSWAP BLOCKED by IP - %ld with %d attempts\n", ip_key, reswap_attempts);
          //skip swapping this key
          skip_swap = true;
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
        total_swaps++;
        cont_swaps++;

        int p = hashg(ip_key, false_i, ht_size);

        int64_t key1 = cuckoo.get_key(false_i,false_ii,p);
        int value1 = cuckoo.query(key1);

        int new_ii=false_ii;
        while (new_ii==false_ii) new_ii=rand()%num_cells;

        int64_t key2 = cuckoo.get_key(false_i,new_ii,p);
        int value2 = cuckoo.query(key2);

        if(!cuckoo.remove(key1)){
          print_and_file("\nPANIC! Error during SWAP\n");
        }

        if(!cuckoo.remove(key2)){ // the position of new_ii was free
          FF[false_i][false_ii][p] = -1;
        }else{
          cuckoo.direct_insert(key2, value2, false_i, false_ii);
          FF[false_i][false_ii][p] = fingerprint(key2, false_ii, fingerprint_bits);
        }

        cuckoo.direct_insert(key1, value1, false_i, new_ii);
        FF[false_i][new_ii][p] = fingerprint(key1, new_ii, fingerprint_bits);
        
        //check again this iteration
        iter--;
      }
    }

    //end of the list
    if(iter == (int)ip_whitelist_keys.size() -1){
      print_and_file("(%d new swaps)\n", cont_swaps);

      if(restart){ //restart (check again all the list)
      
        if(!allow_fp || cont_restart < restart_limit){
          //do restart
          print_and_file("Restart remove FPs (%d/%d)\n", cont_restart+1, restart_limit);
          iter = -1;
          cont_swaps = 0;
          cont_restart++;
          restart = false;
        }
      }
    }
  }


  //Verify again all the IPs
  print_and_file("\nStarting final verification...\n");
  int final_fp = 0; //number of false positive

  for(int iter = 0; iter < (int)ip_whitelist_keys.size(); iter++){

    //progress bar
    if(verbose_out) print_progress(iter, (int)ip_whitelist_keys.size());

    int64_t ip_key = ip_whitelist_keys.at(iter);
    
    for (int i = 0;  i < num_way;  i++) {
      int p = hashg(ip_key, i, ht_size);
      for (int ii = 0;  ii < num_cells;  ii++){
        if(fingerprint(ip_key, ii, fingerprint_bits) == FF[i][ii][p]){
          final_fp++;
        }
      }
    }
  }

  print_and_file("Verification completed successfully\n");

  print_and_file("\nAdaptive Cuckoo Filter statistics:\n");
  print_and_file("Total FP: %d\n", final_fp);
  print_and_file("Total SWAPS: %d\n", total_swaps);
  print_and_file("Total RE-SWAPS: %d\n", total_reswaps_attempts);
  

  auto time_end = chrono::system_clock::now();
  auto execution_seconds = chrono::duration_cast<chrono::seconds>(time_end-time_ini).count();
  print_and_file("Execution time: %ld seconds\n", execution_seconds);

  //fini
  if(generate_output) output.close();

  return 0;
}