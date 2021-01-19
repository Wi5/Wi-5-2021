/*
 * OdinAgent.{cc,hh} -- An agent for the Odin system
 * Lalith Suresh <suresh.lalith@gmail.com>
 *
 * Copyright (c) 2012 Lalith Suresh
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */


#ifndef CLICK_ODINAGENT_HH
#define CLICK_ODINAGENT_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashtable.hh>
#include <click/ipaddress.hh>
#include <click/deque.hh>
#include <elements/wifi/availablerates.hh>

#include <clicknet/ether.h>

#include <click/bighashmap.hh>
#include <click/glue.hh>

#include <click/string.hh>

CLICK_DECLS

/*
=c
OdinAgent

=s basictransfer
No ports

=d
Acts as an agent for the Odin controller

=a
Whatever
*/

class OdinAgent : public Element {
public:
  OdinAgent();
  ~OdinAgent();

  // From Click
  const char *class_name() const	{ return "OdinAgent"; }
  const char *port_count() const  { return "3/5"; }
  const char *processing() const  { return PUSH; }
  int initialize(ErrorHandler *); // initialize element
  int configure(Vector<String> &, ErrorHandler *);
  void add_handlers();
  void run_timer(Timer *timer);
  void push(int, Packet *);

  /*Miscellaneous*/
  int convert_frequency_to__channel(int freq);
  int convert_channel_to_frequency(int chan);

  // Extend this struct to add
  // new per-sta VAP state
  class OdinStationState {
    public:
      //OdinStationState() {_vap_bssid = EtherAddress(); _sta_ip_addr_v4 = IPAddress(); _vap_ssid = String();}
      EtherAddress _vap_bssid;
      IPAddress _sta_ip_addr_v4; // Might need to change for v6
      Vector<String> _vap_ssids;
  };

  enum relation_t {
    EQUALS = 0,
    GREATER_THAN = 1,
    LESSER_THAN = 2,
  };

  class Subscription {
    public:
        long subscription_id;
        EtherAddress sta_addr;
        String statistic;
        relation_t rel;
        double val;
		Timestamp last_publish_sent; // Stores the timestamp when the last publish has been sent for a single subscription
  };

  // Methods to handle and send
  // 802.11 management messages
  String recv_beacon (Packet *p);
  void recv_probe_request (Packet *p);
  void recv_deauth (Packet *p);
  void send_beacon (EtherAddress dst, EtherAddress bssid, String my_ssid, bool probe);
  void recv_assoc_request (Packet *p);
  void send_assoc_response (EtherAddress, uint16_t status, uint16_t associd);
  void recv_open_auth_request (Packet *p);
  void send_open_auth_response (EtherAddress dst, uint16_t seq, uint16_t status);
  Packet* wifi_encap (Packet *p, EtherAddress bssid);

  // Methods to handle pub-sub
  void add_subscription (long subscription_id, EtherAddress addr, String statistic, relation_t r, double val);
  void clear_subscriptions ();

  // Methods to add/remove VAPs.
  int add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> sta_ssid);
  int set_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssid);
  int remove_vap (EtherAddress sta_mac);

  //debug
  void print_stations_state();


  // Read/Write handlers
  static String read_handler(Element *e, void *user_data);
  static int write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh);


  // Extend this enum table to add
  // new handlers.
  enum {
    handler_view_mapping_table,
    handler_num_slots,
    handler_add_vap,
    handler_set_vap,
    handler_txstat,
    handler_rxstat,
    handler_remove_vap,
    handler_channel,
    handler_interval,
    handler_subscriptions,
    handler_debug,
    handler_probe_response,
    handler_probe_request,
    handler_report_mean,
    handler_update_signal_strength,
    handler_signal_strength_offset,
    handler_channel_switch_announcement,
	handler_scan_client,
	handler_scan_APs,
	handler_send_measurement_beacon,
	handler_scanning_flags,
    handler_txpower,
    handler_sta_rssi,
  };

  // Tx and Rx-stats about stations
  class StationStats {
  public:
    int _rate;
    int _noise;
    int _signal;
	int _len_pkt;
	int _packets;					//number of packets
	double _avg_signal;		//average value of the signal
	double _avg_rate;			//average rate of the packets
	double _avg_len_pkt;	//average length of the packets
	double _air_time;			//airtime consumed by this STA, calculated as 8 * _len_pkt / _rate
	Timestamp _time_first_packet;	//timestamp of the first packet included in the statistics
    Timestamp _time_last_packet;		//timestamp of the last packet included in the statistics
    String _equipment;      //identify the equipment that transmit
    StationStats() {
      memset(this, 0, sizeof(*this));
    }
  };

  // All VAP related information should be accessible here on
  // a per client basis
  HashTable<EtherAddress, OdinStationState> _sta_mapping_table;
  HashTable<EtherAddress, Timestamp> _mean_table;
  HashTable<EtherAddress, Timestamp> _station_subs_table; // Table storing the last time when a publish for an ETH address has been sent

  // For stat collection
  double _mean;
  double _num_mean;
  double _m2; // for estimated variance
  int _signal_offset;

  // Keep track of tx-statistics of stations from which
  // we send frames. Only keeping track of data frames for
  // now.
  HashTable<EtherAddress, StationStats> _tx_stats;

  // Keep track of rx-statistics of stations from which
  // we hear frames.
  HashTable<EtherAddress, StationStats> _rx_stats;

  int _interval_ms; // Beacon interval: common between all VAPs for now
  int _interval_ms_default; // Beacon interval: normal mode timer
  int _interval_ms_burst; // Beacon interval: burst mode timer, used during channel switch
  int _channel; // Channel to be shared by all VAPs.
  int _scan_channel; // Channel to be used for scanning.
  int _new_channel; // New channel for CSA
  bool _csa; // For channel switch announcement
  int _count_csa_beacon; // For channel switch announcement
  int _count_csa_beacon_default; // Default number of beacons before channel switch
  int _client_scanned_packets; // Number of packets scanned
  double _client_signal; // Packet power in dbm
  double _client_signal_mW; // Packet power in mW
  double _client_avg_signal_mW; // Average packet power in mW
  double _client_avg_signal; // Average packet power in dBm
  int _burst_after_addlvap; // Number of beacons to send after add_lvap

  //Scanning
  int _active_client_scanning; // To active STA scanning
  EtherAddress _scanned_sta_mac; // STA MAC to scan
  int _client_scanning_result; // Result for STA scanning

  class APScanning {
    public:
        EtherAddress bssid;
		double avg_signal;
		int packets; //# packets
	APScanning() {
      memset(this, 0, sizeof(*this));
    }
  };
  
  
  int _active_AP_scanning; // To active AP scanning
  String _scanning_SSID; // SSID to scan
  //int _AP_scanning_interval; // Interval to scan APs (ms)
  //int _num_intervals_for_AP_scanning; // count the number of scanning intervals for AP scanning 
  Vector<APScanning> _APScanning_list; //Scanned APs for distance (dBs) between APs
  HashTable<EtherAddress, StationStats> _scanned_station_stats; // Keep track of rx-statistics of scanned stations from which we hear frames.
  

  int _active_measurement_beacon; // To active measurement beacon
  String _measurement_beacon_SSID; // SSID to send
  //int _measurement_beacon_interval; // Interval to send (ms)
  //int _num_measurement_beacon; // number of measurement beacon to send
  //int _num_intervals_for_measurement_beacon; // count the number of scanning intervals for measurement beacons
  int _interval_ms_measurement_beacon; // measurement beacon interval: time interval [msec] after which measurement beacon timer will be rescheduled. 
  void send_measurement_beacon();

  //bool _debug;
  int _debug_level;		//"0" no info displayed; "1" only basic info displayed; "2" all the info displayed; "1x" demo info displayed

  //Subscription
  Vector<Subscription> _subscription_list;
  HashTable<EtherAddress, String> _packet_buffer;
  void match_against_subscriptions(StationStats stats, EtherAddress src);

  // Agents use the same channel or agents use different channels
  int _multichannel_agents;  
  
  // CSA table
  HashTable<EtherAddress, int> _csa_table;

private:
  void compute_bssid_mask ();
  void update_tx_stats(Packet *p);
  void update_rx_stats(Packet *p);
  void update_scanned_station_stats(Packet *p);
  EtherAddress _hw_mac_addr;
  class AvailableRates *_rtable;
  int _associd;
  Timer _beacon_timer;
  Timer _clean_stats_timer;
  Timer _general_timer;
  Timer _scanning_timer;
  IPAddress _default_gw_addr;
  String _debugfs_string;
  String _ssid_agent_string;	// stores the SSID of the agent
  int _tx_rate;
  int _tx_power;
  int _hidden;
  /*Stats to file*/
  int _capture_mode;
  EtherAddress _capture_mac;
  String _capture_mac_str;
  bool exists_file(String name);
  void stats_to_file(Packet *p, String filename);
};


CLICK_ENDDECLS
#endif
