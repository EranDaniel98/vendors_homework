import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));

const LogLevelSchema = z.enum(['silent', 'error', 'info', 'debug']);
type LogLevel = z.infer<typeof LogLevelSchema>;

const EnvSchema = z.object({
  VULN_DB_DIR: z.string().optional(),
  VENDORS_FILE: z.string().default('vendors.db'),
  VULNS_FILE: z.string().default('vulnerabilities.db'),
  SERVER_NAME: z.string().default('vulnerability-registry'),
  SERVER_VERSION: z.string().default('1.0.0'),
  DEFAULT_PAGE_LIMIT: z.coerce.number().int().positive().default(50),
  MAX_PAGE_LIMIT: z.coerce.number().int().positive().default(500),
  LOG_LEVEL: LogLevelSchema.default('info'),
});

let parsed: z.infer<typeof EnvSchema>;
try {
  parsed = EnvSchema.parse(process.env);
} catch (err) {
  if (err instanceof z.ZodError) {
    const issue = err.issues[0];
    const field = issue?.path.join('.') ?? '<unknown>';
    throw new Error(
      `Invalid environment variable ${field}: ${issue?.message ?? 'validation failed'}`,
    );
  }
  throw err;
}

const dbDir = path.resolve(parsed.VULN_DB_DIR ?? repoRoot);

export const config = {
  repoRoot,
  dbDir,
  vendorsPath: path.resolve(dbDir, parsed.VENDORS_FILE),
  vulnsPath: path.resolve(dbDir, parsed.VULNS_FILE),
  serverName: parsed.SERVER_NAME,
  serverVersion: parsed.SERVER_VERSION,
  defaultPageLimit: parsed.DEFAULT_PAGE_LIMIT,
  maxPageLimit: parsed.MAX_PAGE_LIMIT,
  logLevel: parsed.LOG_LEVEL,
} as const;

const levelRank: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  info: 2,
  debug: 3,
};

function write(level: LogLevel, msg: string, meta?: unknown): void {
  if (levelRank[level] > levelRank[config.logLevel]) return;
  const prefix = `[${new Date().toISOString()}] [${level}]`;
  const suffix = meta === undefined ? '' : ` ${safeStringify(meta)}`;
  process.stderr.write(`${prefix} ${msg}${suffix}\n`);
}

function safeStringify(value: unknown): string {
  if (value instanceof Error) {
    return JSON.stringify({ name: value.name, message: value.message, stack: value.stack });
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export const logger = {
  error: (msg: string, meta?: unknown) => write('error', msg, meta),
  info: (msg: string, meta?: unknown) => write('info', msg, meta),
  debug: (msg: string, meta?: unknown) => write('debug', msg, meta),
};
