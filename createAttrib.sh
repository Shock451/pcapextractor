#!/bin/bash

# Firstly sniff traffic data with tcpdump:

# tcpdump -w 20150122_1630.pcap -i wlp4s0


# Secondly compute the attributes which defines the connections, intrinsic attributes and content 
# attributes with bro-ids and running the darpa2gurekddcup.bro policy/script:

bro -r ./uploads/$1 darpa2gurekddcup.bro > conn.list


# For each connection the attributes of conn.list: num_conn, startTimet, orig_pt, resp_pt, orig_ht, 
# resp_ht, duration, protocol, resp_pt, flag, src_bytes, dst_bytes, land, wrong_fragment, urg, hot, 
# num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, 
# num_shells, num_access_files, num_outbound_cmds, is_hot_login, is_guest_login.


# Afterwards, sort the conn.list by the connection identifier number (num_conn) which orders the connections by starting time:


sort -n conn.list > conn_sort.list


# Finally, compile and run the trafAld.c C program to create traffic attributes:


gcc trafAld.c -o trafAld # compile. it arises some warnings


./trafAld conn_sort.list # it creates trafAld.list which includes the gureKDDCup99 attributes

mv trafAld.list static/$2

rm *.list *.log

# For each connection the attributes of trafAld.list: num_conn, startTimet, orig_pt, resp_pt, orig_ht, 
# resp_ht, duration, protocol, resp_pt, flag, src_bytes, dst_bytes, land, wrong_fragment, urg, hot, num_failed_logins, 
# logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, 
# num_shells, num_access_files, num_outbound_cmds, is_hot_login, is_guest_login, count_sec, srv_count_sec, 
# serror_rate_sec, srv_serror_rate_sec, rerror_rate_sec, srv_error_rate_sec, same_srv_rate_sec, 
# diff_srv_rate_sec, srv_diff_host_rate_sec, count_100, srv_count_100, same_srv_rate_100, diff_srv_rate_100, same_src_port_rate_100, 
# srv_diff_host_rate_100, serror_rate_100, srv_serror_rate_100, rerror_rate_100, srv_rerror_rate_100.

### CONVERT THE LIST TO A CSV/ARFF FORMAT ###