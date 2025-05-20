import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Users table for authentication (if needed later)
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

// Scans table to store scan history
export const scans = pgTable("scans", {
  id: serial("id").primaryKey(),
  target: text("target").notNull(), // URL or code snippet
  scanType: text("scan_type").notNull(), // web, code, network, etc.
  status: text("status").notNull(), // completed, in-progress, failed
  startedAt: timestamp("started_at").notNull().defaultNow(),
  completedAt: timestamp("completed_at"),
  findings: jsonb("findings"), // Array of findings
  options: jsonb("options"), // Scan options
});

// Findings table (if we want to store them separately)
export const findings = pgTable("findings", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").notNull(), // Reference to scan
  severity: text("severity").notNull(), // critical, high, medium, low, info
  title: text("title").notNull(),
  location: text("location").notNull(), // Where the issue was found
  description: text("description").notNull(),
  evidence: text("evidence"),
  impact: text("impact"),
  remediation: text("remediation"),
  falsePositive: boolean("false_positive").default(false),
  verified: boolean("verified").default(false),
});

// Scan Options schema
export const scanOptionsSchema = z.object({
  useProxy: z.boolean().default(false),
  useAuth: z.boolean().default(false),
  passiveOnly: z.boolean().default(false),
  advanced: z.record(z.any()).optional(),
});

// Severity type
export const severityEnum = z.enum(["critical", "high", "medium", "low", "info"]);

// Finding schema
export const findingSchema = z.object({
  id: z.string(),
  severity: severityEnum,
  title: z.string(),
  location: z.string(),
  description: z.string(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
  remediation: z.string().optional(),
  codeFix: z.string().optional(),
  falsePositive: z.boolean().default(false),
  verified: z.boolean().default(false),
});

// Scan result schema
export const scanResultSchema = z.object({
  target: z.string(),
  scanType: z.string(),
  startedAt: z.date(),
  completedAt: z.date().optional(),
  status: z.enum(["completed", "in-progress", "failed"]),
  findings: z.array(findingSchema),
  stats: z.object({
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    info: z.number(),
  }),
});

// Web scan request schema
export const webScanRequestSchema = z.object({
  url: z.string().url("Please enter a valid URL"),
  scanType: z.string(),
  options: scanOptionsSchema,
});

// Code analysis request schema
export const codeAnalysisRequestSchema = z.object({
  language: z.string(),
  code: z.string(),
});

// Create insert schemas
export const insertUserSchema = createInsertSchema(users);
export const insertScanSchema = createInsertSchema(scans);
export const insertFindingSchema = createInsertSchema(findings);

// Export types
export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertScan = z.infer<typeof insertScanSchema>;
export type InsertFinding = z.infer<typeof insertFindingSchema>;
export type User = typeof users.$inferSelect;
export type Scan = typeof scans.$inferSelect;
export type Finding = typeof findings.$inferSelect;
export type ScanOptions = z.infer<typeof scanOptionsSchema>;
export type ScanResult = z.infer<typeof scanResultSchema>;
export type WebScanRequest = z.infer<typeof webScanRequestSchema>;
export type CodeAnalysisRequest = z.infer<typeof codeAnalysisRequestSchema>;
export type Severity = z.infer<typeof severityEnum>;
