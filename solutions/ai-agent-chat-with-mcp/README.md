# AI Agent Chat With MCP

This Camunda 8.10 example runs an AI chat process whose agent can call tools exposed by Model Context Protocol (MCP) servers. The BPMN uses the AI Agent Sub-process element-template ID `io.camunda.connectors.agenticai.ai-agent-subprocess.v2` (version 1). Its MCP Client and MCP Remote Client tools use element-template IDs `io.camunda.connectors.agenticai.mcp.client.v0` and `io.camunda.connectors.agenticai.mcp.remoteclient.v0` (both version 3), with connector task types `io.camunda.agenticai:mcpclient:1` and `io.camunda.agenticai:mcpremoteclient:1`. The process, forms, and executable tests are maintained in this repository.

## Supported topology

The MCP Client connector is not hosted directly on Camunda 8 SaaS. SaaS is supported when a customer-managed Connector Runtime, configured with the Agentic AI, MCP Client, and MCP Remote Client connectors, is connected to the SaaS cluster. Self-Managed is also supported when its Connector Runtime is configured with those connectors. A plain SaaS cluster without that configured runtime is not a supported deployment.

| Environment | Supported setup |
| --- | --- |
| Camunda 8 SaaS | Connect a customer-managed Connector Runtime with the required connectors and MCP clients. |
| Camunda 8 Self-Managed | Configure the Connector Runtime with the required connectors and MCP clients. |
| Hybrid | Use the Self-Managed Connector Runtime connected to the SaaS cluster. |

See the [MCP Client connector documentation](https://docs.camunda.io/docs/components/connectors/out-of-the-box-connectors/agentic-ai-mcp-client-connector/) for runtime setup and the [Camunda-provided LLM documentation](https://docs.camunda.io/docs/components/agentic-orchestration/camunda-provided-llm/) for model availability and prerequisites.

## Prerequisites

- Camunda 8.10 and Web Modeler or Desktop Modeler.
- A Connector Runtime connected to the cluster, with the Agentic AI, MCP Client, and MCP Remote Client connectors enabled.
- The filesystem and time MCP servers configured in that runtime. The example configuration below starts them with Node.js/npx and Docker.
- Outbound access from the runtime to the configured MCP endpoints, including `mcp.deepwiki.com`.
- Camunda-provided LLM access enabled for the cluster, or a separately configured supported model provider.

The runtime starts configured STDIO servers as local processes. Only configure trusted server commands, and restrict the filesystem server to a directory intended for this example.

## Configure MCP clients

Add the clients used by the BPMN to the Connector Runtime configuration. Replace `<path-to-files>` with a directory the filesystem tool is allowed to access. Configure OpenMemory separately and replace its example URL with the endpoint from your OpenMemory setup.

```yaml
camunda:
  connector:
    agenticai:
      mcp:
        client:
          enabled: true
          clients:
            filesystem:
              type: stdio
              stdio:
                command: npx
                args:
                  - '-y'
                  - '@modelcontextprotocol/server-filesystem'
                  - '<path-to-files>'
            time:
              type: stdio
              stdio:
                command: docker
                args:
                  - 'run'
                  - '-i'
                  - '--rm'
                  - 'mcp/time'
            openmemory:
              type: sse
              sse:
                url: http://localhost:8765/mcp/openmemory/sse/<your-client-id>
```

The Deepwiki tool uses the public Streamable HTTP MCP endpoint `https://mcp.deepwiki.com/mcp`; ensure it is reachable from the runtime. The MCP Remote Client opens connections for tool discovery and calls, so Camunda documents it primarily for prototyping and testing rather than production throughput. The OpenMemory endpoint and its storage are customer-managed.

## Import, deploy, and run

1. Import `ai-agent-chat-with-mcp.bpmn` and all three forms from this directory into the same Modeler project: `ai-agent-chat-initial-request.form`, `ai-agent-chat-user-feedback.form`, and `mcp-tool-call-confirmation.form`.
2. Configure the Connector Runtime and MCP clients as described above, then connect it to the target cluster.
3. Enable Camunda-provided LLM access. On environments where its secrets are not provisioned automatically, configure `CAMUNDA_PROVIDED_LLM_API_ENDPOINT`, `CAMUNDA_PROVIDED_LLM_API_KEY`, and `CAMUNDA_PROVIDED_LLM_DEFAULT_MODEL` for the runtime. Alternatively, configure another supported provider in the AI Agent Sub-process.
4. Deploy the BPMN process and its forms.
5. Start an instance with an `inputText` request, for example:

   ```json
   { "inputText": "Compare the New York and Berlin time zones and write the results to a markdown file" }
   ```

6. The agent can use configured MCP tools. Filesystem write and delete calls require a user to approve the requested operation; read-only filesystem calls do not.

To run the automated process tests, use `mvn test` from `solutions/ai-agent-chat-with-mcp/test` (Docker must be available for the Process Test runtime).

## Tools and safeguards

- **OpenMemory** stores or retrieves user-requested, non-sensitive memories through the configured OpenMemory MCP server. Do not store credentials or sensitive personal data.
- **Deepwiki** retrieves indexed documentation for public repositories. It does not read private repositories or guarantee access to live, unindexed changes.
- **Time** returns time information for a requested time zone. Supply an IANA time-zone identifier such as `Europe/Berlin`.
- **Filesystem** read-only operations run without confirmation. Other filesystem operations require user approval before execution.

The user-feedback form displays an AI-generated-content disclosure for each response. Keep it visible whenever the form is changed.

_Canonical source: [`solutions/ai-agent-chat-with-mcp`](https://github.com/camunda/camunda-8-tutorials/tree/main/solutions/ai-agent-chat-with-mcp)._
