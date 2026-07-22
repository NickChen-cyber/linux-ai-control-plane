import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const auditEvents = sqliteTable("audit_events", {
  id: text("id").primaryKey(),
  occurredAt: text("occurred_at").notNull(),
  sessionId: text("session_id").notNull(),
  actorId: text("actor_id").notNull(),
  actorName: text("actor_name").notNull(),
  eventType: text("event_type").notNull(),
  page: text("page").notNull(),
  action: text("action").notNull(),
  target: text("target"),
  result: text("result").notNull().default("recorded"),
  metadata: text("metadata"),
  previousHash: text("previous_hash"),
  integrityHash: text("integrity_hash").notNull(),
}, (table) => [
  index("audit_occurred_at_idx").on(table.occurredAt),
  index("audit_actor_idx").on(table.actorId),
  index("audit_session_idx").on(table.sessionId),
]);

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  displayName: text("display_name").notNull(),
  status: text("status").notNull().default("active"),
  mfaEnabled: integer("mfa_enabled", { mode: "boolean" }).notNull().default(false),
  createdAt: text("created_at").notNull(),
});

export const groups = sqliteTable("groups", {
  id: text("id").primaryKey(),
  name: text("name").notNull().unique(),
  description: text("description").notNull(),
  hostScope: text("host_scope").notNull(),
  createdAt: text("created_at").notNull(),
});

export const hosts = sqliteTable("hosts", {
  id: text("id").primaryKey(),
  hostname: text("hostname").notNull().unique(),
  address: text("address").notNull(),
  environment: text("environment").notNull(),
  operatingSystem: text("operating_system").notNull(),
  status: text("status").notNull().default("unknown"),
  lastSeenAt: text("last_seen_at"),
});

export const tasks = sqliteTable("tasks", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  risk: text("risk").notNull(),
  status: text("status").notNull(),
  requestedBy: text("requested_by").notNull(),
  approvedBy: text("approved_by"),
  targetScope: text("target_scope").notNull(),
  createdAt: text("created_at").notNull(),
});
