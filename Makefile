test:
	PYTHONPATH=network_tools_lib python3 -m pytest -l -s -v --cov=. --cov-report term-missing
	# TODO: complete pytype coverage for pcap_stats
	PYTHONPATH=network_tools_lib pytype -k --exclude=pcap_stats .
	./network_tap/ncapture/test_ncapture.sh
