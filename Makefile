.PHONY: test

test:
	python3 -m py_compile webhook_server.py
	python3 -m pytest -q
