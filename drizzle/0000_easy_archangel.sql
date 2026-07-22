CREATE TABLE `audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`occurred_at` text NOT NULL,
	`session_id` text NOT NULL,
	`actor_id` text NOT NULL,
	`actor_name` text NOT NULL,
	`event_type` text NOT NULL,
	`page` text NOT NULL,
	`action` text NOT NULL,
	`target` text,
	`result` text DEFAULT 'recorded' NOT NULL,
	`metadata` text,
	`previous_hash` text,
	`integrity_hash` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `audit_occurred_at_idx` ON `audit_events` (`occurred_at`);--> statement-breakpoint
CREATE INDEX `audit_actor_idx` ON `audit_events` (`actor_id`);--> statement-breakpoint
CREATE INDEX `audit_session_idx` ON `audit_events` (`session_id`);--> statement-breakpoint
CREATE TABLE `groups` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`description` text NOT NULL,
	`host_scope` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `groups_name_unique` ON `groups` (`name`);--> statement-breakpoint
CREATE TABLE `hosts` (
	`id` text PRIMARY KEY NOT NULL,
	`hostname` text NOT NULL,
	`address` text NOT NULL,
	`environment` text NOT NULL,
	`operating_system` text NOT NULL,
	`status` text DEFAULT 'unknown' NOT NULL,
	`last_seen_at` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `hosts_hostname_unique` ON `hosts` (`hostname`);--> statement-breakpoint
CREATE TABLE `tasks` (
	`id` text PRIMARY KEY NOT NULL,
	`title` text NOT NULL,
	`risk` text NOT NULL,
	`status` text NOT NULL,
	`requested_by` text NOT NULL,
	`approved_by` text,
	`target_scope` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`display_name` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`mfa_enabled` integer DEFAULT false NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);