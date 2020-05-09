# @TEST-EXEC: zeek -C -r $TRACES/dns-2.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut orig_h resp_h resp_cc < known_outbound_services.log > known.tmp && mv known.tmp known_outbound_services.log
# @TEST-EXEC: btest-diff known_outbound_services.log

redef Site::local_nets += { [2001:400:0::]/32 };
redef Known::outbound_watch_countries += {"US"};

