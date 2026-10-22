# Quick Start: Orchestrate Microservices
**Technical level:** Easy 
<br>
**Industry:** Any 
<br>
**Use Cases:** Microservice Orchestration

## Summary

This process shows a simple example on how to orchestrate one Microservice. The example is based on our getting started guide for [Microservice Orchestration](https://docs.camunda.io/docs/guides/orchestrate-microservices/). There is also a [video](https://vimeo.com/762694985/07220e785a) available, walking you through the process details.

### Run the low-code tests in Hub

The Marketplace import does not include the test file. To run the low-code tests:

1. Download [`Quick Start_ Microservices.integration.test.json`](./Quick%20Start_%20Microservices.integration.test.json).
2. Use **Upload files** on the imported project's page to add it to that project.
3. Open the diagram's **Test tab**.
4. Run the suite.
5. Review the results in the run history.

Stop `worker-java` before you run the suite. Otherwise the worker takes the job before the test can complete it.

Do not upload the CPT suite in `test/` to Hub. Run it with Maven.
