# Quick Start: API Orchestration
**Technical level:** Easy 
<br>
**Industry:** Any 
<br>
**Use Cases:** API Orchestration

## Summary

This process shows a simple example on how to call an API endpoint. The example is based on our getting started guide for [API Orchestration](https://docs.camunda.io/docs/guides/orchestrate-apis/). There is also a [video](https://vimeo.com/762692362/025d801c73) available, walking you through the process.

### Run the low-code tests in Hub

The Marketplace import does not include the test file. To run the low-code tests:

1. Download [`Quick Start_ API Orchestration.integration.test.json`](./Quick%20Start_%20API%20Orchestration.integration.test.json).
2. Use **Upload files** on the imported project's page to add it to that project.
3. Open the diagram's **Test tab**.
4. Run the suite.
5. Review the results in the run history.

The test calls the cat fact API live. You need a connectors runtime and internet access.

Do not upload the CPT suite in `test/` to Hub. Run it with Maven.
