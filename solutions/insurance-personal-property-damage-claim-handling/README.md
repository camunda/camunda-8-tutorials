# Insurance: Personal Property Damage Claim Handling

**Technical level:** Low
<br>
**Industry:** Insurance
<br>
**Use Cases:** Claim Handling/Human Task Orchestration

## Summary

This blueprint describes a simple claim handling process. It shows the interaction between the customer, the insurance's IT systems and also a Gen AI tool to analyze the photo of the damaged property. In this process, the claim is either approved automatically, determined by various business rules specified in a DMN table, or adjudicated manually.

Intermediate none events are used to keep track of the different outcomes and milestones: the claim is either approved automatically, approved manually, or declined manually. These events are suitable to define KPIs in Optimize, which in turn can help improve the rules for automatic claim processing to minimize costs.

### Run the low-code tests in Hub

The Marketplace import does not include the test file. To run the low-code tests:

1. Download [`insurance-personal-property-damage-claim-handling.integration.test.json`](./insurance-personal-property-damage-claim-handling.integration.test.json).
2. Use **Upload files** on the imported project's page to add it to that project.
3. Open the diagram's **Test tab**.
4. Run the suite.
5. Review the results in the run history.

The tests publish messages with fixed correlation keys. If a run stops halfway, cancel its leftover process instance before you run the suite again.

Do not upload the CPT suite in `test/` to Hub. Run it with Maven.
