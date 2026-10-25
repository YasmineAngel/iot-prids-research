"""Read a pcap file and extract header values from each packet."""
import sys
import dpkt

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

def mac_to_str(mac_bytes):
    """Convert 6 raw bytes into 'aa:bb:cc:dd:ee:ff'."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def open_reader(f):
    """Return a dpkt reader for either pcap or pcapng files."""
    magic = f.read(4)
    f.seek(0)
    if magic == PCAPNG_MAGIC:
        return dpkt.pcapng.Reader(f)
    return dpkt.pcap.Reader(f)


def peek(path, n=10):
    """Print basic info about the first n packets of a pcap file."""
    with open(path, "rb") as f:
        reader = open_reader(f)
        for i, (ts, buf) in enumerate(reader):
            if i >= n:
                break
            eth = dpkt.ethernet.Ethernet(buf)
            print(f"{i}  {ts}  {len(buf)}  {mac_to_str(eth.src)}  {mac_to_str(eth.dst)}")


if __name__ == "__main__":
    peek(sys.argv[1])