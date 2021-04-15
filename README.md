# ACF for IPs

This repository contains the code to run the Adaptive Cuckoo Filter with IPs of IPv4. The code is base on Adaptive Cuckoo Filter simulator code (avaiable in https://github.com/pontarelli/ACF).

The code generate an ACF from an input IP blacklist file and checks the false positive rate with an input IP whitelist file. Code available for ACF 2x4 and 4x1.

# Getting Started

The code has been developed on Ubuntu 20.04.

# Building

Run the following commands in the ACF directory to build everything:

```
$ make
```

# Running

There are two executables for the ACF:

1. acf_ip_2x4
    Generates the ACF with 2 tables and 4 cells for bucket. The executable options available running:

```
$ ./acf_ip_2x4 -h 
```
    

2. acf_ip_4x1

    Generates the ACF with 4 tables and 1 cell for bucket. The executable options available running:

```
$ ./acf_ip_4x1 -h 
```


# Example

The following example generate an ACF with 301066 IPs blacklist and test the resulting filter with 500K IPs whitelist. The ACF 4x1 will use 9 bits (3 bits for selection and the remaining 6 bits for the hash function), a load of 95% and verbose mode.

```
$ ./acf_ip_4x1 -b blacklists/listed_ip_180.txt -w whitelists/500K_listed_ip_180.txt -f 9 -s 3 -l 95 -v
```

The following example generate an ACF with 301066 IPs blacklist and test the resulting filter with 500K IPs whitelist. The ACF 2x4 will use 9 bits for the fingerprint and table size of 43000.

```
$ ./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/500K_listed_ip_180.txt -f 9 -m 43000
```