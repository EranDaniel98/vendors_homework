import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { config, logger } from './config.js';
import { VulnerabilityStore } from './store.js';
import { registerTools } from './tools.js';

async function main(): Promise<void> {
  const store = new VulnerabilityStore();
  await store.load(config.vendorsPath, config.vulnsPath);

  const server = new McpServer({
    name: config.serverName,
    version: config.serverVersion,
  });
  registerTools(server, store);

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info('ready', { vendors: store.vendorCount, vulns: store.vulnCount });
}

main().catch((err) => {
  logger.error('fatal', err);
  process.exit(1);
});
