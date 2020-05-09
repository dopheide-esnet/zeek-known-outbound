# @TEST-EXEC: zeek -C -r $TRACES/nc-test.pcap %INPUT > stdout.txt
# @TEST-EXEC: btest-diff stdout.txt

event zeek_init(){
  local orig_loc = lookup_location(8.8.8.8);

  if(orig_loc?$country_code && orig_loc$country_code != "US"){
    print("GeoIP lookups appear to not be working");
  }else{
    print("GeoIP lookups are working");
  }
}
