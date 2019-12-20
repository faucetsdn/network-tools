test:
	pytest -l -s -v --cov=. --cov-report term-missing
	# TODO: expand pytype to other plugins
	pytype p0f/
