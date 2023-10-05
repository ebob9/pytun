import pytun
import logging
import select
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError as e:
    # no scapy for pretty print, just use generic HEX output.
    SCAPY_AVAILABLE = False


def pprint_buf(buf):
    """ Dirty & convenient function to display the hexademical
        repr. of a buffer.
    """

    DEFAULT_SIZE = 4

    def hex2(i, l = None):
        l = l if l is not None else DEFAULT_SIZE

        h = hex(i).upper()[2:]

        if len(h) != l:
            h = "0" * (l - len(h)) + h

        return h

    def displayable_char(test_c):
        if not str.isprintable(str(test_c)):
            test_c = "."
        return str(test_c)

    print(" " * DEFAULT_SIZE, end="")
    for i in range(16):
        print(hex2(i, 2), end="")
    print("")

    raws = []
    for i, c in enumerate(buf):
        if i % 16 == 0:
            if i:
                print("\t" + "".join(raws))
                raws = []

            print(hex2(i), end="")
        raws.append(displayable_char(c))

        print(hex2(ord(str(c)), 2),)

    print("   " * (15 - (i % 16)) + "\t" + "".join(raws))


def main():
    # Configure pytun's logger
    pytun.logger.setLevel(logging.DEBUG)
    logging.basicConfig()

    # Open the tunnel
    try:
        tun = pytun.open()

    except pytun.Tunnel.NotPermitted:
        print("")
        print("*" * 80)
        print(f"You don't have the rights to access the file {pytun.TUN_KO_PATH}")
        print("Give the access of this file to pytun, or if you trust me,")
        print("elevate this current script to root level.")
        print("*" * 80)
        print("")

        raise

    print("*" * 80)
    print("")
    print(f"OK. The tunnel '{tun.name.decode(encoding='utf-8')}' had been created.")
    print("")
    print("If you want to play with it, first configure it.")
    print("")
    print("1. Set up the network and set an IP")
    print(f"    # ip addr add 192.168.42.1/24 dev {tun.name.decode(encoding='utf-8')}")
    print(f"    # ip link set {tun.name.decode(encoding='utf-8')} up")
    print("")
    print("2. Add the network route")
    print(f"    # ip route add 192.168.42.0/24 dev {tun.name.decode(encoding='utf-8')}")
    print("")
    print("Then, try to ping some IP in this network ...")
    print("    # ping 192.168.42.42")
    print("")
    print("Or do some UDP netcat magic.")
    print("    # nc 192.168.42.42 4242 -u")
    print("")
    print("Enjoy !")
    print("")
    print("*" * 80)

    try:
        # Receive loop
        while True:
            buf = tun.recv()
            if SCAPY_AVAILABLE:
                from scapy.layers.tuntap import LinuxTunPacketInfo
                #packet = scapy.Packet(buf)
                tun_packet = LinuxTunPacketInfo(buf)
                pytun.logger.info("Packet received!")
                pytun.logger.debug("\n" + tun_packet.show2(dump=True))
                pytun.logger.debug("\n" + scapy.hexdump(tun_packet, dump=True))

            else:
                pytun.logger.info("Packet received! Raw HEX:")
                pytun.logger.debug(f"\n{buf.hex(' ', 2)}\m")
                #pprint_buf(buf)
            print("")

    except KeyboardInterrupt:
        print("Keyboard interrupt. Closing.")

    finally:
        # Close the tunnel
        tun.close()


if __name__ == "__main__":
    main()

