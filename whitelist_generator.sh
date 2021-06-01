#!/bin/bash

#./ip_list_generator 100000 blacklists/listed_ip_180.txt whitelists/100K_listed_ip_180.txt

#./ip_list_generator 500000 blacklists/listed_ip_180.txt whitelists/500K_listed_ip_180.txt

#./ip_list_generator 1000000 blacklists/listed_ip_180.txt whitelists/1M_listed_ip_180.txt

#./ip_list_generator 5000000 blacklists/listed_ip_180.txt whitelists/5M_listed_ip_180.txt

#./ip_list_generator 10000000 blacklists/listed_ip_180.txt whitelists/10M_listed_ip_180.txt

number_ips=1000000
blacklist_name=listed_ip_180
whitelist_prefix=1M
extension=.txt

mkdir whitelists/$whitelist_prefix-$blacklist_name

for ((i = 1; i <= 10; i++)); do
    ./ip_list_generator $number_ips blacklists/$blacklist_name$extension whitelists/$whitelist_prefix-$blacklist_name/$whitelist_prefix-$blacklist_name-$i$extension $i
done