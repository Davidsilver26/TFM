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
Output:
```
./acf_ip_4x1 -b blacklists/listed_ip_180.txt -w whitelists/500K_listed_ip_180.txt -f 9 -s 3 -l 95 -v -o aaa.txt 

Reading blacklists/listed_ip_180.txt
[==================================================] 100%
Reading whitelists/500K_listed_ip_180.txt
[==================================================] 100%

Starting the Adaptive Cuckoo Filter 2x4
general parameters:
way: 4
cells: 1
Table size: 79228
Buckets: 316912
Fingerprint bits: 9
Hash function bits: 6
Selection bits: 3
Blacklist IPs: 301066
Whitelist IPs: 500000

Cuckoo table statistics
items: 301066
load: 0.949999
total size: 316912

Removing FPs (1/8)
[==================================================] 100%
(28862 new swaps)
Removing FPs (2/8)
[==================================================] 100%
(2529 new swaps)
Removing FPs (3/8)
[==================================================] 100%
(164 new swaps)
Removing FPs (4/8)
[==================================================] 100%
(11 new swaps)
Removing FPs (5/8)
[==================================================] 100%
(2 new swaps)
Removing FPs (6/8)
[==================================================] 100%
(0 new swaps)

Starting final verification...
[==================================================] 100%
Verification completed successfully

Adaptive Cuckoo Filter statistics:
Total FP: 0
Total SWAPS: 31568
Execution time: 12 seconds
```

The following example generates an ACF with 301066 IPs blacklist and test the resulting filter with 500K IPs whitelist. The ACF 2x4 will use 9 bits for the fingerprint and table size of 43000.

```
$ ./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/500K_listed_ip_180.txt -f 9 -m 43000
```
Output:
```
./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/500K_listed_ip_180.txt -f 9 -m 43000 

Reading blacklists/listed_ip_180.txt
Reading whitelists/500K_listed_ip_180.txt

Starting the Adaptive Cuckoo Filter 2x4
general parameters:
way: 2
cells: 4
Table size: 43000
Buckets: 344000
Fingerprint bits: 9
Restart limit: 20
Blacklist IPs: 301066
Whitelist IPs: 500000

Cuckoo table statistics
items: 301066
load: 0.875192
total size: 344000

Removing FPs
(6911 new swaps)
Restart remove FPs (1/20)
(262 new swaps)
Restart remove FPs (2/20)
(37 new swaps)
Restart remove FPs (3/20)
(8 new swaps)
Restart remove FPs (4/20)
(2 new swaps)
Restart remove FPs (5/20)
(0 new swaps)

Starting final verification...
Verification completed successfully

Adaptive Cuckoo Filter statistics:
Total FP: 0
Total SWAPS: 7220
Total RE-SWAPS: 70
Execution time: 11 seconds
```