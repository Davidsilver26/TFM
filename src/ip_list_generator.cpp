#include <random>
#include <iostream>
#include <string.h>
#include <fstream>
#include <vector>


using namespace std;

const int ip_range = 256;
const int64_t global_ips = 4294967296; //IPv4 address space


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


//program main
int main(int argc, char **argv){

  //check arguments
  if(argc != 4){ // program name + arguments
    cerr << "Invalid usage" << endl;
    cerr << "Usage: " << argv[0] << " <number IPs> <exclude list> <output file>" << endl;
    return 1;
  }

  //read arguments
  const string exclude_list = argv[2];
  const string output_file = argv[3];
  const int total_ips = stoi(argv[1]);

  //read exclude list file
  ifstream infile_exclude_list(exclude_list);

  if(infile_exclude_list.fail()){
    cerr << "Can not open file " << exclude_list << endl;
    return 1;
  }

  vector<string> lines_exclude_list = read_lines(infile_exclude_list);

  infile_exclude_list.close();

  vector<int64_t> ip_exclude_list_keys;
  int invalid_ips = 0;

  for(uint i = 0; i < lines_exclude_list.size(); i++){
    if( !valid_ip(lines_exclude_list[i]) ){
      cerr << "Invalid IP format <" << lines_exclude_list[i] << "> in line " << (i+1) << endl;
      invalid_ips++;
    }else{
      ip_exclude_list_keys.push_back(ip_string_to_key(lines_exclude_list[i]));
    }
  }

  lines_exclude_list.clear();

  if(invalid_ips > 0){
    cerr << "The file " << exclude_list << " contains errors" << endl;
    cerr << "Exiting..." << endl;
    return 1;
  }

  //generate random IP list
  const int max_jump = (global_ips / total_ips) * (2 * 0.9);
  ofstream outfile(output_file);

  int seed = 12342;
  srand(seed);

  int value1 = 0, value2 = 0, value3 = 0, value4 = 0;
  int exclude_iter = 0;
  int cont_ips = 0;

  while(cont_ips < total_ips){

    //generate ip
    int increment = 1 + (rand() % max_jump);
    value4 += increment;

    if(value4 >= ip_range){
      value3 += value4 / ip_range;
      value4 %= ip_range;

      if(value3 >= ip_range){
        value2 += value3 / ip_range;
        value3 %= ip_range;
      }

      if(value2 >= ip_range){
        value1 += value2 / ip_range;
        value2 %= ip_range;

        if(value1 >= ip_range){
          break;
        }
      }
    }

    string new_ip = to_string(value1) + ".";
    new_ip += to_string(value2) + ".";
    new_ip += to_string(value3) + ".";
    new_ip += to_string(value4);

    int64_t new_ip_key = ip_string_to_key(new_ip);
    int64_t exclude_ip_key = ip_exclude_list_keys.at(exclude_iter);

    //get next exclude IP grater than random IP
    while(new_ip_key > exclude_ip_key && exclude_iter < (int)ip_exclude_list_keys.size() - 1){
      exclude_iter++;
      exclude_ip_key = ip_exclude_list_keys.at(exclude_iter);
    }

    //cout << "compare " << new_ip << " == " << ip_key_to_string(exclude_ip_key) << endl;
    if(new_ip_key != exclude_ip_key){
      //add IP
      outfile << new_ip << endl;
      cont_ips++;
    }
    
  }

  outfile.close();

  if(cont_ips < total_ips){
    cerr << "Only " << cont_ips << "/" << total_ips << " IPs generated." << endl;
    return 1;
  }

  return 0;
}