# Telco: Service Order Fulfillment

**Technical level:** High
<br>
**Industry:** Telecommunication
<br>
**Use Cases:** Order Processing/Microservice Orchestration

## Summary

This blueprint depicts the order management and fulfillment of a mixed service order, containing hardware and mobile partial orders. As a first step, the Friendly-Enough Expression Language (FEEL) is used to determine the price dimensions of the order. As a next step, FEEL is used to map the incoming order into partial orders, sorted by type, into multiple lists. An inclusive gateway and multi-instance subprocesses are used to orchestrate the fulfillment of each partial order of either type hardware or mobile. The blueprint depicts synchronous and asynchronous interfaces to telco-internal, but process-external systems.

### Run the low-code tests in Hub

The project includes the test file, `telco service order fulfillment retail.integration.test`. The Marketplace import adds it automatically. To run the low-code tests:

1. Open `telco service order fulfillment retail.integration.test` in Hub.
2. Click **Open in Test mode**.
3. Deploy and run the tests.
4. Review the results in the run history.

The tests publish messages with fixed correlation keys. If a run stops halfway, cancel its leftover process instance before you run the suite again.
