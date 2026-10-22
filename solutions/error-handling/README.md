# Error Handling
**Technical level:** Medium 
<br>
**Industry:** Any 
<br>
**Use Cases:** API Orchestration

## Summary

When implementing microservices, taking into account how to respond when a service is unable to successfully complete its task is an important step in ensuring robustness of your process but also important in making your process fully automated. This example shows how BPMN Error events can be used to catch and continue the process based on predefined criteria. It shows how those events propagate and how scope works within a process, sub process and event sub process.

### Run the low-code tests in Hub

The Marketplace import does not include the test file. To run the low-code tests:

1. Download [`Error Handling.integration.test.json`](./Error%20Handling.integration.test.json).
2. Use **Upload files** on the imported project's page to add it to that project.
3. Open the diagram's **Test tab**.
4. Run the suite.
5. Review the results in the run history.

Do not upload the CPT suite in `test/` to Hub. Run it with Maven.
