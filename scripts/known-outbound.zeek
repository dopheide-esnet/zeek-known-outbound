##! This script provides the ability to track and alert on outbound service
##! usage to a list of 'watched' countries.  It also adds the country codes for
##! your orig and resp in conn.log.  To help reduce repeated entries, it uses a
##! persistent Broker data store.
##! This borrows heavily from the core known-services.zeek script.

@load base/utils/directions-and-hosts
@load base/frameworks/cluster
@load base/frameworks/notice

module Known;

export {
	redef enum Log::ID += { OUTBOUND_SERVICES_LOG };

	redef enum Notice::Type += {
		Suspicious_Outbound_Service
	};

	## The record type which contains the column fields for known_outbound_services.log
	type OutboundServicesInfo: record {
		## The time at which the service was detected.
		ts:             time            &log;
		## The orig host address.
		orig_h:	        addr            &log;
		## The resp host address on which the service is running.
		resp_h:         addr            &log;
		## The resp host country code
		resp_cc:        string          &log;
		## The port number on which the service is running.
		port_num:       port            &log;
		## The transport-layer protocol which the service uses.
		port_proto:     transport_proto &log;
		## A set of protocols that match the service's connection payloads.
		service:        set[string]     &log;
	};

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Zeek set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_outbound_store = T &redef;
	
	## Countries for which we track outbound service connections
	option outbound_watch_countries: set[string] = {"RU","RO"};

	type OutboundAddrPortServTriplet: record {
		host: addr;
		p: port;
		serv: string;
	};

	## Holds the set of all known services.  Keys in the store are
	## :zeek:type:`Known::OutboundAddrPortServTriplet` and their associated value is
	## always the boolean value of "true".
	global outbound_store: Cluster::StoreInfo;

	## The Broker topic name to use for :zeek:see:`Known::outbound_store`.
	const outbound_store_name = "zeek/known/outbound" &redef;

	## The expiry interval of new entries in :zeek:see:`Known::outbound_store`.
	## This also changes the interval at which services get logged.
	const outbound_store_expiry = 1day &redef;

	## The timeout interval to use for operations against
	## :zeek:see:`Known::outbound_store`.
	option outbound_store_timeout = 15sec;

	## Tracks the set of daily-detected services for preventing the logging
	## of duplicates, but can also be inspected by other scripts for
	## different purposes.
	##
	## In cluster operation, this table is uniformly distributed across
	## proxy nodes.
	##
	## This table is automatically populated and shouldn't be directly modified.
	global outbound_services: table[addr, port] of set[string] &create_expire=1day;

	## Event that can be handled to access the :zeek:type:`Known::OutboundServicesInfo`
	## record as it is sent on to the logging framework.
	global log_outbound_services: event(rec: OutboundServicesInfo);
}

redef record connection += {
	# This field is to indicate whether or not the processing for detecting 
	# and logging the service for this connection is complete.
	outbound_services_done: bool &default=F;
};

######################
# BEGIN SECTION: GeoIP
# This section builds the pieces to get GeoIP CC added to the connection record.
######################

redef record connection += {
        orig_cc: string &log &optional;
        resp_cc: string &log &optional;
};

redef record Conn::Info += {
        orig_cc: string &log &optional;
        resp_cc: string &log &optional;
};

# trying to get orig_cc much earlier so it can be used in other policies
# seems like a race, also this event only works for TCP connection
event connection_established(c: connection)
        {
        local orig_loc = lookup_location(c$id$orig_h);
        if ( orig_loc?$country_code )
                c$orig_cc = orig_loc$country_code;

        local resp_loc = lookup_location(c$id$resp_h);
        if ( resp_loc?$country_code )
                c$resp_cc = resp_loc$country_code;
}

event connection_state_remove(c: connection) &priority=5
        {
        if(c?$orig_cc)
                c$conn$orig_cc = c$orig_cc;
        if(c?$resp_cc)
                c$conn$resp_cc = c$resp_cc;
        if(!(c?$orig_cc || c?$resp_cc)){
                local orig_loc = lookup_location(c$id$orig_h);
                if ( orig_loc?$country_code )
                   c$conn$orig_cc = orig_loc$country_code;

                 local resp_loc = lookup_location(c$id$resp_h);
                 if ( resp_loc?$country_code )
                   c$conn$resp_cc = resp_loc$country_code;
        }
}

######################
# END SECTION: GeoIP
######################


# Check if the triplet (host,port_num,service) is already in Known::outbound_services
function check_outbound(info: OutboundServicesInfo) : bool
	{
	if ( [info$resp_h, info$port_num] !in Known::outbound_services )
		return F;

	for ( s in info$service )
		{
		if ( s !in Known::outbound_services[info$resp_h, info$port_num] )
			return F;
		}

	return T;
	}

event zeek_init()
	{
	if ( ! Known::use_outbound_store )
		return;

	# use a persistent store so known connections aren't re-flagged every restart.
	Known::outbound_store = Cluster::create_store(Known::outbound_store_name,T);
	}

event outbound_info_commit(info: OutboundServicesInfo, c: connection)
	{
	if ( ! Known::use_outbound_store )
		return;

	local tempservs = info$service;

	if(|tempservs| == 0){
		add tempservs[""];
	}


	for ( s in tempservs )
		{
		local key = OutboundAddrPortServTriplet($host = info$resp_h, $p = info$port_num, $serv = s);

		when ( local r = Broker::put_unique(Known::outbound_store$store, key,
		                                    T, Known::outbound_store_expiry) )
			{
			if ( r$status == Broker::SUCCESS )
				{
				if ( r$result as bool ) {
					info$service = set(s);	# log one service at the time if multiservice
					Log::write(Known::OUTBOUND_SERVICES_LOG, info);

# TODO.. perhaps don't need a notice for DNS services.
# It could also be a configurable option.
# Need more data from other users.

					NOTICE([$note=Known::Suspicious_Outbound_Service,
						    $msg=fmt("New connection to watched country %s",info$resp_cc),
						    $id=c$id]);
					}
				}
			else
				Reporter::error(fmt("%s: data store put_unique failure",
				                    Known::outbound_store_name));
			}
		timeout Known::outbound_store_timeout
			{
			Log::write(Known::OUTBOUND_SERVICES_LOG, info);
			NOTICE([$note=Known::Suspicious_Outbound_Service,
					$msg=fmt("New connection to watched country %s",info$resp_cc),
					$id=c$id]);
			}
		}
	}

event outbound_service_add(info: OutboundServicesInfo, c: connection)
	{
	if ( Known::use_outbound_store )
		return;

	if ( check_outbound(info) )
		return;

	if ( [info$resp_h, info$port_num] !in Known::outbound_services )
		Known::outbound_services[info$resp_h, info$port_num] = set();

	 # service to log can be a subset of info$service if some were already seen
	local info_to_log: OutboundServicesInfo;
	info_to_log$ts = info$ts;
	info_to_log$orig_h = info$orig_h;
	info_to_log$resp_h = info$resp_h;
	info_to_log$resp_cc = info$resp_cc;
	info_to_log$port_num = info$port_num;
	info_to_log$port_proto = info$port_proto;
	info_to_log$service = set();

	# Would "-" be better than ""?
	if(|info$service| == 0){
		add info$service[""];
	}

	for ( s in info$service )
		{
		if ( s !in Known::outbound_services[info$resp_h, info$port_num] )
			{
			add Known::outbound_services[info$resp_h, info$port_num][s];
			add info_to_log$service[s];
			}
		}

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::OUTBOUND_SERVICES_LOG, info_to_log);
		NOTICE([$note=Known::Suspicious_Outbound_Service,
				$msg=fmt("New connection to watched country %s",info$resp_cc),
				$id=c$id]);
	@endif

	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Known::use_outbound_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::outbound_services = table();
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Known::use_outbound_store )
		return;

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	Known::outbound_services = table();
	}

event outbound_info_commit(info: OutboundServicesInfo, c: connection)
	{
	if ( Known::use_outbound_store )
		return;

	if ( check_outbound(info) )
		return;

	local key = cat(info$resp_h, info$port_num);
	Cluster::publish_hrw(Cluster::proxy_pool, key, outbound_service_add, info);
	event outbound_service_add(info, c);
	}

function outbound_services_done(c: connection)
	{
	local id = c$id;
	c$outbound_services_done = T;

	if(c?$resp_cc && c$resp_cc !in outbound_watch_countries){
		return;
	}
	if(! c?$resp_cc){
		return;
	}
	if ( |c$service| == 1 )
		{
		if ( "ftp-data" in c$service )
			# Don't include ftp data sessions.
			return;

		if ( "DNS" in c$service && c$resp$size == 0 )
			# For dns, require that the server talks.
			return;
		}

	# Drop services starting with "-" (confirmed-but-then-violated protocol)
	local tempservs: set[string];
		for (s in c$service)
			if ( s[0] != "-" )
				add tempservs[s];

	local info = OutboundServicesInfo($ts = network_time(),
		                      $orig_h = id$orig_h, 
							  $resp_h = id$resp_h,
							  $resp_cc = c$resp_cc,
	                          $port_num = id$resp_p,
	                          $port_proto = get_port_transport_proto(id$resp_p),
	                          $service = tempservs);

	event outbound_info_commit(info, c);
}
	

## Remove this because we need conn state remove for the country codes to 
## be available.
#event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=-5
#	{
#	outbound_services_done(c);
#	}


# TODO:  For 3.1 we'll want to use the successful_connection_remove event instead
event connection_state_remove(c: connection)
	{
	if ( c$outbound_services_done )
		return;

	if ( ! id_matches_direction(c$id,OUTBOUND)){
		return;
	}

	# Base known-services doesn't include TCP_CLOSED, I think that may be an error.
	if ( c$resp$state != TCP_CLOSED && c$resp$state != TCP_ESTABLISHED && c$resp$state != UDP_ACTIVE )
		return;

	# this is not a reason to stop, another issue with known-services?
#	if ( |c$service| == 0 )
#		return;

	outbound_services_done(c);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Known::OUTBOUND_SERVICES_LOG, [$columns=OutboundServicesInfo,
	                                         $ev=log_outbound_services,
	                                         $path="known_outbound_services"]);
	}

