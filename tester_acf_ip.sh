#!/bin/bash

# 100K minimo 7
# 500K minimo 9
# 1M minimo 11

#./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/1M_listed_ip_180.txt -f 13 -v -r 40 -o tests/1M_listed_ip_180_f13.txt

#./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/1M_listed_ip_180.txt -f 12 -v -r 40 -o tests/1M_listed_ip_180_f12.txt

#./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/1M_listed_ip_180.txt -f 11 -v -r 40 -o tests/1M_listed_ip_180_f11.txt

#./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/1M_listed_ip_180.txt -f 10 -v -r 40 -o tests/1M_listed_ip_180_f10.txt

#./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/1M_listed_ip_180.txt -f 9 -v -r 40 -o tests/1M_listed_ip_180_f9.txt

#./acf_ip_2x4 -b blacklists/listed_ip_180.txt -w whitelists/1M_listed_ip_180.txt -f 8 -v -r 40 -o tests/1M_listed_ip_180_f8.txt

blacklist_name=listed_ip_180
whitelist_prefix=1M
dir_whitelist=$whitelist_prefix-$blacklist_name
extension=.txt

max_bits=12
min_bits=7

mkdir tests/$whitelist_prefix-$blacklist_name

for ((j = $max_bits; j >= $min_bits; j--)); do
    mkdir tests/$dir_whitelist/f$j
    for i in $(ls whitelists/$dir_whitelist); do
    ./acf_ip_2x4 -b blacklists/$blacklist_name$extension -w whitelists/$dir_whitelist/$i -f $j -r 30 -l 95 -v -o tests/$dir_whitelist/f$j/2x4-f$j-$i
    ./acf_ip_4x1 -b blacklists/$blacklist_name$extension -w whitelists/$dir_whitelist/$i -f $j -s 2 -l 95 -v -o tests/$dir_whitelist/f$j/4x1-f$j-s2-$i
    ./acf_ip_4x1 -b blacklists/$blacklist_name$extension -w whitelists/$dir_whitelist/$i -f $j -s 3 -l 95 -v -o tests/$dir_whitelist/f$j/4x1-f$j-s3-$i
    ./acf_ip_4x1 -b blacklists/$blacklist_name$extension -w whitelists/$dir_whitelist/$i -f $j -s 4 -l 95 -v -o tests/$dir_whitelist/f$j/4x1-f$j-s4-$i
    done
done