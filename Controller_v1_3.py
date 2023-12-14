from ryu.topology import api
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, in_proto, ipv4, ipv6, icmp, tcp, udp, arp
from ryu.lib import addrconv
import struct
from scapy.all import IP, TCP, Ether, Raw

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_dataport = {}
        self.TCP_buffered_packets = {}
        self.buffered_packets = {}
        self.threedup = {}
        self.flag = 0
        self.acktosend=0;

    def print_dictionary_keys(self, n, dictionary, prefix=()):
        for key, value in dictionary.items():
            if isinstance(prefix, str):
                prefix = (prefix,)
            if isinstance(key, str) or isinstance(key, int):
                key = (key,)
            current_key = prefix + key
            print(current_key)
            if isinstance(value, dict):
                self.print_dictionary_keys(value, prefix=current_key)

    def get_nested_values(self, d):
        values = []
        for k, v in d.items():
            if isinstance(v, dict):
                values.extend(self.get_nested_values(v))
            else:
                values.append(v)
        return values

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "d").zfill(16)
        print("Switch Connected! Address - ", dpid)

        if dpid == "0000000000000001":

            print("S1 connected. Adding flowrules")

            self.mac_to_dataport.setdefault("00:00:00:00:00:01",datapath)
            self.mac_to_dataport.setdefault("00:00:00:00:00:02",datapath)

            # match = parser.OFPMatch(in_port = 2, eth_dst="00:00:00:00:00:03", ip_proto=in_proto.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
            # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            # self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(ip_proto=in_proto.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            self.add_flow(datapath, 2, match, actions)

            print("Added s1 flowrules")

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        #   ofproto.OFPCML_NO_BUFFER
                                        )]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_mobile_flow(self, datapath, mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # match = parser.OFPMatch(eth_src=mac, ip_proto=in_proto.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
        match = parser.OFPMatch(ip_proto=in_proto.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 2, match, actions)

        node_port = 1
        match = parser.OFPMatch(eth_dst=mac)
        actions = [parser.OFPActionOutput(node_port)]
        self.add_flow(datapath, 1, match, actions)

        # Send all the Non TCP buffered packets to the mobile node at once
        if mac in self.buffered_packets:
            for packet_data in self.buffered_packets[mac]:
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=packet_data)
                datapath.send_msg(out)
            # Clear the buffered packets for the mobile node 
            del self.buffered_packets[mac]

        if mac in self.TCP_buffered_packets:
            for packet_data in self.get_nested_values(self.TCP_buffered_packets[mac]):
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=packet_data)
                datapath.send_msg(out)
        return

    def del_mobile_flows(self, datapath, mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_dst=mac)
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,)
        datapath.send_msg(mod)

        match = parser.OFPMatch(eth_src=mac)
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,)
        datapath.send_msg(mod)

        self.buffered_packets.setdefault(mac, [])
        return

    def handle_arp(self, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        print("ARP Packet received, sending reply")
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src='00:00:00:00:00:03'))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac='00:00:00:00:00:03',
                                 src_ip='10.0.0.3',
                                 dst_mac=pkt_arp.src_mac,
                                 dst_ip=pkt_arp.src_ip))
        return pkt

    def handle_ack(self, data, src_mac, dst_mac, datapath):
        pkt = packet.Packet(data)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "d").zfill(16)
        node_port = self.mac_to_port[dpid][src_mac]
        # node_port = 1
        actions = [parser.OFPActionOutput(node_port)]

        tcp_ack_pkt = pkt.get_protocol(tcp.tcp)
        src_ip = pkt.get_protocol(ipv4.ipv4).src
        dst_ip = pkt.get_protocol(ipv4.ipv4).dst
        src_port = tcp_ack_pkt.src_port
        dst_port = tcp_ack_pkt.dst_port
        ack=tcp_ack_pkt.ack
        seq=tcp_ack_pkt.seq

        # deleting all previous sequence numbered packets when ack for higher sequence number arrives
        # key = (src_ip, src_port, dst_ip, dst_port)
        key_ack = (dst_ip, dst_port, src_ip, src_port)
        
        if src_mac in self.TCP_buffered_packets:
            if key_ack in self.TCP_buffered_packets[src_mac]:
                seq_to_delete = [seq for seq in self.TCP_buffered_packets[src_mac][key_ack] if seq < ack]
                for seq in seq_to_delete:
                    del self.TCP_buffered_packets[src_mac][key_ack][seq]
            else:
                print(f"key_ack {key_ack} not found in {src_mac}")
        else:
            print(f"dst_mac {src_mac} not found")

        sa_to_delete = [(s,a) for (s,a) in self.threedup if a < ack]
        for (s,a) in sa_to_delete:
            del self.threedup[(s,a)]
                
        # checking for 3 duplicate, if present then sending the packet and droping the ack 
        if ((seq,ack) not in self.threedup or self.threedup[(seq,ack)]==0):
            print("******************************** First Duplicate **************************************")
            self.threedup[(seq,ack)]=1
        elif self.threedup[(seq,ack)]==1:
            print("******************************** Second Duplicate *************************************")
            self.threedup[(seq,ack)]=2
        else:
            print("******************************** Third Duplicate **************************************")
            self.flag=1
            if src_mac in self.TCP_buffered_packets:
                if key_ack in self.TCP_buffered_packets[src_mac]:
                    if ack in self.TCP_buffered_packets[src_mac][key_ack]:
                        packet_data = self.TCP_buffered_packets[src_mac][key_ack][ack]
                        out = parser.OFPPacketOut(
                            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                            in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                            data=packet_data)
                        print("Sending packet from controller with sequence number ", ack, "*****************")
                        datapath.send_msg(out)
                    else:
                        print(f"ack {ack} not found in {key_ack} in {src_mac}")
                else:
                    print(f"key_ack {key_ack} not found in {src_mac}")
            else:
                print(f"dst_mac {src_mac} not found")

    def send_packet(self, dst_mac, datapath, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "d").zfill(16)
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        self.logger.info("************************* Sending packet to switch: %s, Port: %s ******************************", dpid, out_port)

        datapath.send_msg(out)    

    def calculate_checksum(self, data):
        pkt = packet.Packet(data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Assuming pkt is the parsed Packet object
        tcp_payload = pkt.protocols[-1] if isinstance(pkt.protocols[-1], bytes) else b''

        # Construct the pseudo-header
        pseudo_header = addrconv.ipv4.text_to_bin(ip_pkt.src) + \
                        addrconv.ipv4.text_to_bin(ip_pkt.dst) + \
                        bytes([0]) + \
                        bytes([ip_pkt.proto]) + \
                        len(tcp_pkt.serialize(payload=tcp_payload, prev=ip_pkt)).to_bytes(2, 'big')

        # Set the checksum field to 0 before recomputing
        received_checksum = tcp_pkt.csum
        tcp_pkt.csum = 0
        serialized_tcp = tcp_pkt.serialize(payload=tcp_payload, prev=ip_pkt)

        # Concatenate the pseudo-header and serialized TCP segment
        concatenated_data = pseudo_header + serialized_tcp

        # Step 3: Calculate the Checksum
        if len(concatenated_data) % 2 == 1:
            concatenated_data += b'\x00'
        words = struct.unpack('!%sH' % (len(concatenated_data) // 2), concatenated_data)
        checksum = sum(words)
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = ~checksum & 0xFFFF
        # print("Pseudo-header:", pseudo_header.hex())
        # print("Serialized TCP:", serialized_tcp.hex())
        # print("TCP Payload:", tcp_payload.hex() if tcp_payload else "None")
        # print("Concatenated Data:", concatenated_data.hex())
        # print("Calculated Checksum:", checksum)
        # print("Actual Checksum from TCP Header:", received_checksum)
        return checksum

    def request_retransmission(self, datapath, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "d").zfill(16)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        src_mac = eth.src
        dst_mac = eth.dst
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        src_port = tcp_pkt.src_port
        dst_port = tcp_pkt.dst_port
        seq = tcp_pkt.seq
        ack = tcp_pkt.ack

        pkt = bytes(Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", ack=seq, seq=ack)/Raw(load=b''))
        
        node_port = self.mac_to_port[dpid][src_mac]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt)
        print("******************************** SENDING RETRANSISSION OUT ***********************************")
        datapath.send_msg(out)

    def send_zero_window_ack(self, datapath, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "d").zfill(16)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        src_mac = eth.src
        dst_mac = eth.dst
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        src_port = tcp_pkt.src_port
        dst_port = tcp_pkt.dst_port
        seq = tcp_pkt.seq
        ack = tcp_pkt.ack

        self.acktosend=self.acktosend+2896
        pkt = bytes(Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", ack=self.acktosend, seq=ack, window=0)/Raw(load=b''))
        
        node_port = self.mac_to_port[dpid][src_mac]
        actions = [parser.OFPActionOutput(node_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt)
        print("******************************** SENDING ZWA OUT ***********************************")
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        data = msg.data
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        arp_pkt = pkt.get_protocol(arp.arp)
        src_mac = eth.src
        dst_mac = eth.dst
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src_mac] = in_port
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if tcp_pkt:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            key = (src_ip, src_port, dst_ip, dst_port)
            if (dpid == "1152921504606846977"or dpid == "1152921504606846978" or dpid == "1152921504606846979"):
                self.acktosend=tcp_pkt.ack

            self.logger.info("""TCP packet in switch: %s, 
                             Src MAC: %s, Src IP: %s, Src Port: %s, 
                             Dst MAC: %s, Dst IP: %s, Dst Port: %s, 
                             Seq : %s, Ack : %s, Inport: %s""", dpid, src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port, tcp_pkt.seq, tcp_pkt.ack, in_port)

            if (tcp_pkt.has_flags(tcp.TCP_SYN)):
                print("New TCP connection - Adding dict")
                self.TCP_buffered_packets.setdefault(dst_mac,{}).setdefault(key,{})
                self.send_packet(dst_mac, self.mac_to_dataport[dst_mac], data)

            elif (tcp_pkt.has_flags(tcp.TCP_FIN, tcp.TCP_ACK) or tcp_pkt.has_flags(tcp.TCP_FIN) or tcp_pkt.has_flags(tcp.TCP_RST, tcp.TCP_ACK) or tcp_pkt.has_flags(tcp.TCP_RST)):
                print("Terminating TCP, deleting buffer")
                if dst_mac in self.TCP_buffered_packets:
                    if key in self.TCP_buffered_packets[dst_mac]:
                        del self.TCP_buffered_packets[dst_mac][key]
                self.send_packet(dst_mac, self.mac_to_dataport[dst_mac], data)

            else:
                print("Storing TCP packet in buffer\n Stored-")
                match_checksum = self.calculate_checksum(data)
                # for p in pkt:
                #     print(repr(p))
                if match_checksum < 0:
                    print("******************************** INCORRECT CHECKSUM!! ***********************************")
                    self.request_retransmission(datapath, pkt)
                else:
                    self.TCP_buffered_packets[dst_mac][key].setdefault(tcp_pkt.seq,msg.data)
                    self.handle_ack(msg.data, src_mac, dst_mac, datapath)
                    # self.print_dictionary_keys(self.TCP_buffered_packets)
                    if self.flag == 1:
                        self.flag=0
                    elif dst_mac in self.buffered_packets:
                        self.send_zero_window_ack(datapath, pkt)
                    else:
                        self.send_packet(dst_mac, self.mac_to_dataport[dst_mac], data)

        else:
            if arp_pkt and dst_mac in self.buffered_packets:
                arp_reply_pkt=self.handle_arp(eth, arp_pkt)
                self.send_packet(src_mac, datapath, arp_reply_pkt)
                return

            # logic for determining connect and disconnect packets 
            if udp_pkt and udp_pkt.src_port==55000:
                self.logger.info("Disconnect packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)
                self.mac_to_port[dpid][src_mac] = 1
                del self.mac_to_dataport[src_mac]
                self.del_mobile_flows(datapath, src_mac)
                return

            if udp_pkt and udp_pkt.src_port==55001:
                self.logger.info("Connect packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)
                self.mac_to_port[dpid][src_mac] = 1
                self.mac_to_dataport[src_mac]=datapath
                self.add_mobile_flow(datapath, src_mac)
                dp = self.mac_to_dataport["00:00:00:00:00:01"]
                match = parser.OFPMatch(eth_dst=src_mac)
                if (dpid=="1152921504606846977"):
                    node_port = 3
                    actions = [parser.OFPActionOutput(node_port)]
                    self.add_flow(dp, 1, match, actions)
                if (dpid=="1152921504606846978"):
                    node_port = 4
                    actions = [parser.OFPActionOutput(node_port)]
                    self.add_flow(dp, 1, match, actions)
                if (dpid=="1152921504606846979"):
                    node_port = 5
                    actions = [parser.OFPActionOutput(node_port)]
                    self.add_flow(dp, 1, match, actions)
                return

            else:
                if dst_mac in self.buffered_packets:
                    self.buffered_packets[dst_mac].append(msg.data)
                    return

                else:
                    if dst_mac in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst_mac]
                    else:
                        out_port = ofproto.OFPP_FLOOD

                    actions = [parser.OFPActionOutput(out_port)]

                    if out_port != ofproto.OFPP_FLOOD:                    
                        match = parser.OFPMatch(eth_dst=dst_mac)
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                            return
                        else:
                            self.add_flow(datapath, 1, match, actions)

                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                            in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)