C8RUN_DIR ?= $(HOME)/camunda/c8run
JAVA_HOME  ?= $(shell asdf where java 2>/dev/null || echo "")

.PHONY: start stop test integration-test test-all

start:
	cd $(C8RUN_DIR) && JAVA_HOME=$(JAVA_HOME) env $$(grep -v '^#' $(CURDIR)/.env | grep -v '^$$' | xargs) ./start.sh > $(C8RUN_DIR)/log/startup.log 2>&1 &
	@echo "Starting c8run with .env secrets... (tail $(C8RUN_DIR)/log/startup.log to follow)"

stop:
	cd $(C8RUN_DIR) && ./shutdown.sh

test:
	cd test && mvn test

integration-test:
	cd test && env $$(grep -v '^#' ../.env | grep -v '^$$' | xargs) mvn test -P integration-test

test-all:
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory integration-test
	@echo ""
	@echo "=== Summary ==="
	@grep -h "Tests run:" test/target/surefire-reports/*.txt | sort -u
