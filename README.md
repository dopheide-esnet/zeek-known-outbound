# zeek-known-outbound

Requires zeek built against libmaxmind and GeoIP databases (typically GeoLite2)

This script provides the ability to track and alert on outbound service usage to a list of 'watched' countries.  It also adds the country codes for your orig
and resp in conn.log.  To help reduce repeated entries, it uses a persistent Broker data store. 

You may want to redefine the list of watched countries:
redef Known::outbound_watch_countries += {"XX","YY","ZZ"};

"Outbound" is determined by your Site::local_nets or networks.cfg.


