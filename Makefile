.PHONY: venv galaxy lint check run ping
VENV=. .venv/bin/activate

venv:
	python3 -m venv .venv && $(VENV) && pip install -r requirements.txt

galaxy:
	$(VENV) && ansible-galaxy collection install -r collections/requirements.yml

lint:
	$(VENV) && ansible-lint

# dry-run (DEV only)
check:
	$(VENV) && ansible-playbook -i inventories/inventory.yml playbooks/fortiweb_status.yml --check --limit fortiweb_dev

# real run (DEV only)
run:
	$(VENV) && ansible-playbook -i inventories/inventory.yml playbooks/fortiweb_status.yml --limit fortiweb_dev

# quick reachability test to your lab devices (httpapi)
ping:
	$(VENV) && ansible -i inventories/inventory.yml fortilab -m fortinet.fortiweb.fwebos_system_setting -a ''
