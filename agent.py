#!/usr/bin/env python2

import socket
import struct
import logging
import pyeapi
import netaddr

logging.basicConfig(format="DF-AGENT: %(levelname)-8s %(message)s")
LOG = logging.getLogger()


def parse_gre_header(raw_data):

    flags, version, protocol = struct.unpack(">BBH", raw_data[:4])

    gre_header = {"flags": flags, "version": version, "protocol": protocol}
    LOG.debug("Parsed GRE packet: {}".format(gre_header))

    if hex(protocol) != "0x88be":
        LOG.warn(
            "Received packet doesn't looks like a ERSPAN. Protocol is {}".format(
                hex(protocol)
            )
        )

    return gre_header


def parse_ip_header(raw_data):

    version, dscp, total_len, ip_id, flags, ttl, proto, checksum, src_ip, dst_ip = struct.unpack(
        ">BBHHHBBHII", raw_data
    )

    ip_header = {
        "version": version,
        "dscp": dscp,
        "total_len": total_len,
        "ip_id": ip_id,
        "flags": flags,
        "ttl": ttl,
        "proto": proto,
        "checksum": checksum,
        "src_ip": socket.inet_ntoa(struct.pack("!L", src_ip)),
        "dst_ip": socket.inet_ntoa(struct.pack("!L", dst_ip)),
    }

    LOG.debug("Parsed IP packet: {}".format(ip_header))

    return ip_header


def pre_parse_ip_header(raw_data):

    version, _, total_len = struct.unpack(">BBH", raw_data[:4])

    header_len = int(bin(version)[-4:], 2) * 4  # Increments of 32bit or 4bytes

    LOG.debug(
        "IP header is {} bytes with total payload {} bytes".format(
            header_len, total_len
        )
    )

    return header_len, total_len


def parse_tcp_header(raw_data):

    src_port, dst_port = struct.unpack(">HH", raw_data[:4])

    tcp_header = {"src_port": src_port, "dst_port": dst_port}

    LOG.debug("Parsed TCP header between {} <-> {}".format(src_port, dst_port))

    return tcp_header


def parse_eth_header(raw_data):

    dst_mac = struct.unpack(">BBBBBB", raw_data[:6])

    src_mac = struct.unpack(">BBBBBB", raw_data[6:12])

    ethType, = struct.unpack(">H", raw_data[12:14])

    eth_header = {
        "dst_mac": "%x:%x:%x:%x:%x:%x" % dst_mac,
        "src_mac": "%x:%x:%x:%x:%x:%x" % src_mac,
        "eth_type": hex(ethType),
    }

    LOG.debug("Parsed Ethernet header {}".format(eth_header))

    return eth_header


def get_src_intf(connection, src_ip):
    # This is a very simple implementation, not assuming ECMP/LAG
    # However should be easy to extend to find the exact incoming interface based on both IP and MAC

    command = ["enable", "show ip route {}".format(src_ip)]

    output = connection.execute(command)

    result = output["result"][1]["vrfs"]["default"]["routes"]

    my_intf = list()

    for route, attrs in result.iteritems():
        if src_ip in netaddr.IPNetwork(
            route
        ):  # Just making sure we've got the right routes back
            for via in attrs["vias"]:
                my_intf.append(via["interface"])

    if (
        len(my_intf) != 1
    ):  # So far assuming there can only be one interface (otherwise may need to disable src intf hashing)
        LOG.warn("Found {} interfaces for IP {}".format(len(my_intf), src_ip))
        return ""

    return my_intf[0]


def get_nexthop(connection, intf, src_ip, dst_ip, src_port, dst_port):

    ip_proto = 6  # Hardcoding this to TCP for now

    cmd_show_lb = ""
    cmd_show_lb += "show load-balance destination ip"
    cmd_show_lb += " ingress-interface {}".format(intf)
    cmd_show_lb += " src-ipv4-address {}".format(src_ip)
    cmd_show_lb += " dst-ipv4-address {}".format(dst_ip)
    cmd_show_lb += " ip-protocol {}".format(ip_proto)
    cmd_show_lb += " src-l4-port {}".format(src_port)
    cmd_show_lb += " dst-l4-port {}".format(dst_port)

    command = ["enable", cmd_show_lb]

    output = connection.execute(command, "text")

    result = output["result"][1]["output"]

    if "unable" in result.lower():
        LOG.inf(result)
        return ""

    # Getting the last value
    egress_intf = result.split()[-1]

    cmd_show_ip_route = "show ip route {}".format(dst_ip)

    command = ["enable", cmd_show_ip_route]

    output = connection.execute(command)

    result = output["result"][1]

    # Hardcoding this to default vrf for now
    routes = result["vrfs"]["default"]["routes"]

    for prefix, route in routes.iteritems():
        LOG.debug("Checking prefix {}".format(prefix))
        if dst_ip in netaddr.IPNetwork(prefix):
            for via in route["vias"]:
                LOG.debug(
                    "Checking nexthops {}@{}".format(
                        via["nexthopAddr"], via["interface"]
                    )
                )
                if via["interface"] == egress_intf:
                    LOG.debug(
                        "Found matching nexthop {}, returning".format(
                            via["nexthopAddr"]
                        )
                    )
                    return via["nexthopAddr"]

    return ""


def create_or_update_directflow(
    connection, src_ip, dst_ip, src_port, dst_port, nexthop
):

    flow = list()

    flow.append(
        "flow {}-{}-{}-{}".format(
            src_ip.replace(".", "_"), src_port, dst_ip.replace(".", "_"), dst_port
        )
    )

    flow.append("match ethertype ip")
    flow.append("match source ip {}".format(src_ip))
    flow.append("match destination ip {}".format(dst_ip))
    flow.append("match ip protocol tcp")
    flow.append("match destination port {}".format(dst_port))
    flow.append("match source port {}".format(src_port))
    flow.append("no persistent")
    flow.append("timeout idle 300")
    flow.append("action output nexthop {}".format(nexthop))

    command = ["enable", "configure", "directflow", "no shutdown"] + flow

    output = connection.execute(command)

    return len(output["result"][1]) == 0


def main():

    LOG.setLevel(logging.DEBUG)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)

    s.bind(("", 0))

    LOG.info("Entering while loop")

    while True:
        raw_data = s.recv(65536)

        if not raw_data:
            break

        outer_ip_packet = raw_data[:]
        outer_header_len, total_len = pre_parse_ip_header(outer_ip_packet)
        if total_len != len(outer_ip_packet):
            LOG.warn(
                "Received more than 1 packet. Total length is {}".format(total_len)
            )

        outer_ip_header = parse_ip_header(outer_ip_packet[:outer_header_len])
        if outer_ip_header["proto"] != 47:
            LOG.warn(
                "Payload doesn't appear to be a GRE. IP proto is {}".format(
                    outer_ip_header["proto"]
                )
            )

        gre_packet = outer_ip_packet[outer_header_len:]
        parse_gre_header(gre_packet)

        eth_frame = gre_packet[4:]
        eth_header = parse_eth_header(eth_frame)
        if eth_header["eth_type"] != "0x800":
            LOG.warn(
                "Ethernet doesn't appear to be carrying IP. EthType is {}".format(
                    eth_header["eth_type"]
                )
            )

        inner_ip_packet = eth_frame[14:]
        inner_header_len, _ = pre_parse_ip_header(inner_ip_packet)
        inner_ip_header = parse_ip_header(inner_ip_packet[:inner_header_len])
        if inner_ip_header["proto"] != 6:
            LOG.warn(
                "Payload doesn't appear to be a TCP. IP proto is {}".format(
                    inner_ip_header["proto"]
                )
            )

        tcp_packet = inner_ip_packet[inner_header_len:]
        tcp_header = parse_tcp_header(tcp_packet)

        connection = pyeapi.connect(host=outer_ip_header["src_ip"])

        src_intf = get_src_intf(connection, inner_ip_header["src_ip"])
        if not src_intf:
            LOG.warn("Could not identify source interface, skipping...")
            continue

        nexthop = get_nexthop(
            connection,
            src_intf,
            inner_ip_header["src_ip"],
            inner_ip_header["dst_ip"],
            tcp_header["src_port"],
            tcp_header["dst_port"],
        )
        if not nexthop:
            LOG.warn("Could not identify nexthop, skipping...")
            continue

        ok = create_or_update_directflow(
            connection,
            inner_ip_header["src_ip"],
            inner_ip_header["dst_ip"],
            tcp_header["src_port"],
            tcp_header["dst_port"],
            nexthop,
        )
        if not ok:
            LOG.info("Failed to install directflow")
        else:
            LOG.info(
                "Installed DF entry {}:{} <-> {}:{} via {}".format(
                    inner_ip_header["src_ip"],
                    tcp_header["src_port"],
                    inner_ip_header["dst_ip"],
                    tcp_header["dst_port"],
                    nexthop,
                )
            )


if __name__ == "__main__":
    main()
