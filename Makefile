test:
	PYTHONPATH=network_tools_lib python3 -m pytest -l -s -v --cov=. --cov-report term-missing
	# TODO: complete pytype coverage.
	PYTHONPATH=network_tools_lib pytype -k mercury/ network_tap/ network_tools_lib/ p0f/ pcap_to_node_pcap/ rbqwrapper/ replay_pcap/ snort/ tcprewrite_dot1q/
