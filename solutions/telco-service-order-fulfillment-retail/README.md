# Telco: Service Order Fulfillment

**Technical level:** High
<br>
**Industry:** Telecommunication
<br>
**Use Cases:** Order Processing/Microservice Orchestration

## Summary

This blueprint depicts the order management and fulfillment of a mixed service order, containing hardware and mobile partial orders. As a first step, the Friendly-Enough Expression Language (FEEL) is used to determine the price dimensions of the order. As a next step, FEEL is used to map the incoming order into partial orders, sorted by type, into multiple lists. An inclusive gateway and multi-instance subprocesses are used to orchestrate the fulfillment of each partial order of either type hardware or mobile. The blueprint depicts synchronous and asynchronous interfaces to telco-internal, but process-external systems.

### Run the low-code tests in Hub

The Marketplace import does not include the test file. To run the low-code tests:

1. Download [`telco-service-order-fulfillment-retail.integration.test.json`](./telco-service-order-fulfillment-retail.integration.test.json).
2. Use **Upload files** on the imported project's page to add it to that project.
3. Open the diagram's **Test tab**.
4. Run the suite.
5. Review the results in the run history.

The tests publish messages with fixed correlation keys. If a run stops halfway, cancel its leftover process instance before you run the suite again.

Do not upload the CPT suite in `test/` to Hub. Run it with Maven.
