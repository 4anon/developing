import threading
from terminaltables import AsciiTable
class Scanner(threading.Thread):
    """ Scanner Thread class """
    def __init__(self, queue, lock, ip):
        super(Scanner, self).__init__()
        self.queue = queue
        self.lock = lock
        self.ip = ip

    def run(self):
        global closed
        src_port = RandShort()
        port = self.queue.get()
        p = IP(dst=self.ip)/TCP(sport=src_port, dport=port, flags='S')
        resp = sr1(p, timeout=2)
        if resp is None:
            with self.lock:
                closed += 1
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                send_rst = sr(IP(dst=self.ip)/TCP(sport=src_port, dport=port, flags='AR'), timeout=1)
                with self.lock:
                    print "[*] %d %s open" % (port, portlist.get(port, errorhandlingmessage))
            elif resp.getlayer(TCP).flags == 0x14:
                with self.lock:
                    closed += 1
        self.queue.task_done()


def pscan():

    print
    print
    print "[*] You did choose Port Scanning"
    table_data = [
        ["Portscanning", "Available Scans"],
        ["Stealth", "The TCP Stealth Scan"],
        ["Xmas", "A Scan with all flags"],
        #["TCP XMas", "Fake an SMTP email address"],
    ]
    table = AsciiTable(table_data)
    print table.table
    pscanChoice = raw_input("What kind of portscanning do you want?")
    ip = raw_input("[+]Please enter your Target > ")
    minport = raw_input("[+] Please enter the minimum of port to scan, Enter to keep default range > ")
    maxport = raw_input("[+] Please enter the maximum port to scan, Enter to keep default range\n  tip: dont do to much, then it takes to much time > ")
    empty = ''
    try:
        if minport and maxport != 0:
            ports = range(int(minport), int(maxport))
        elif minport and maxport == 0:
            ports = range(1, 1024)
        else:
            print "[~]Something went wrong"
            sys.exit()
    except:
        print "[~]Error in the File"
        print "[*] Exiting"
        sys.exit()
    pscanChoice = pscanChoice.lower()
    if pscanChoice == 'stealth':
        conf.verb = 0
        start_time = time.time()
        lock = threading.Lock()
        queue = Queue.Queue()
        if is_up(ip):
            print "Host %s is up, start scanning" % ip
            for port in ports:
                queue.put(port)
                scan = Scanner(queue, lock, ip)
                scan.start()
            queue.join()
            duration = time.time()-start_time
            print "%s Scan Completed in %fs" % (ip, duration)
            print "%d closed ports in %d total port scanned" % (closed, len(ports))
    else:
        print hi
