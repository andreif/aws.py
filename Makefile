path = /usr/local/bin/aws.py

clean:
	rm -f ${path}

help: ${path}
	aws.py | yq -P
list: ${path}
	aws.py -l | yq -P
list-profiles: ${path}
	aws.py -p | yq -P
run: ${path}
	aws.py
run-yq: ${path}
	aws.py | yq -P

serve: ${path}
	aws.py serve

stop: ${path}
	aws.py stop

${path}:
	ln -sf $$(realpath aws.py) ${path}
