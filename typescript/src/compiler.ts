/**
 * The compiler (TypeScript port): natural language -> mandate -> signed payload.
 * The rule-based parser mirrors the Python one; an LLM parser can be injected as
 * `parser` to handle arbitrary phrasing (off-the-shelf model, no fine-tuning).
 */

import { buildMandate, type Amount, type Constraints } from "./mandate.ts";
import { signMandate, type SignedMandate } from "./signing.ts";

export interface ParsedConstraints {
  intent?: string;
  categories?: string[];
  merchants?: { allow?: string[]; deny?: string[] };
  max_amount?: Amount;
  expires_at?: Date;
}

export type Parser = (text: string, now?: Date) => ParsedConstraints;

const CURRENCY_SYMBOLS: Record<string, string> = { "$": "USD", "£": "GBP", "€": "EUR" };
const CURRENCY_WORDS: Record<string, string> = {
  dollar: "USD", dollars: "USD", usd: "USD",
  pound: "GBP", pounds: "GBP", gbp: "GBP",
  euro: "EUR", euros: "EUR", eur: "EUR",
};
const CATEGORY_WORDS = [
  "apparel", "clothing", "electronics", "groceries", "grocery",
  "travel", "software", "books", "food", "hardware", "office",
];
const CATEGORY_ALIASES: Record<string, string> = { clothing: "apparel", grocery: "groceries" };
const MONTHS: Record<string, number> = {
  january: 1, february: 2, march: 3, april: 4, may: 5, june: 6,
  july: 7, august: 8, september: 9, october: 10, november: 11, december: 12,
};

// A merchant name is one or more consecutive Capitalized words ("Blue Bottle").
const NAME = "[A-Z][\\w&.'-]*(?:\\s+[A-Z][\\w&.'-]*)*";

function parseAmount(text: string): Amount | undefined {
  const m = text.match(
    /(?:up to|under|max(?:imum)?(?: of)?|no more than|≤|<=|below)\s*([$£€])?\s*([\d,]+(?:\.\d{1,2})?)\s*([a-zA-Z]{3}|dollars?|pounds?|euros?)?/i,
  );
  if (!m) return undefined;
  const [, symbol, number, word] = m;
  const value = Number(number.replace(/,/g, ""));
  let currency = "USD";
  if (symbol) currency = CURRENCY_SYMBOLS[symbol] ?? "USD";
  else if (word) currency = CURRENCY_WORDS[word.toLowerCase()] ?? word.toUpperCase().slice(0, 3);
  return { value, currency };
}

function parseExpiry(text: string, now: Date): Date | undefined {
  const isoM = text.match(/expir\w*\s+(?:on\s+|by\s+|at\s+)?(\d{4}-\d{2}-\d{2})/i);
  if (isoM) {
    const [y, mo, d] = isoM[1].split("-").map(Number);
    return new Date(Date.UTC(y, mo - 1, d, 23, 59, 59));
  }
  const m = text.match(
    /expir\w*\s+(?:on\s+|by\s+|at\s+)?(?:(\d{1,2})\s+([A-Za-z]+)|([A-Za-z]+)\s+(\d{1,2}))/i,
  );
  if (m) {
    let day: number, monthName: string;
    if (m[1]) { day = Number(m[1]); monthName = m[2]; }
    else { monthName = m[3]; day = Number(m[4]); }
    const month = MONTHS[monthName.toLowerCase()];
    if (month) {
      let year = now.getUTCFullYear();
      let candidate = new Date(Date.UTC(year, month - 1, day, 23, 59, 59));
      if (candidate < now) candidate = new Date(Date.UTC(year + 1, month - 1, day, 23, 59, 59));
      return candidate;
    }
  }
  return undefined;
}

function parseCategories(text: string): string[] {
  const cats: string[] = [];
  const re = /any\s+([a-zA-Z]+)\s+(?:retailer|retailers|store|stores|merchant|merchants|shop|shops)/gi;
  for (const m of text.matchAll(re)) cats.push(m[1].toLowerCase());
  for (const word of CATEGORY_WORDS) {
    if (new RegExp(`\\b${word}\\b`, "i").test(text)) cats.push(word);
  }
  const normed: string[] = [];
  for (let c of cats) {
    c = CATEGORY_ALIASES[c] ?? c;
    if (!normed.includes(c)) normed.push(c);
  }
  return normed;
}

function parseMerchants(text: string): { allow: string[]; deny: string[] } {
  const allow: string[] = [];
  const deny: string[] = [];
  const m = text.match(new RegExp(`only (?:from|at)\\s+(${NAME}(?:(?:,|\\s+and)\\s+${NAME})*)`));
  if (m) {
    for (const s of m[1].trim().split(/,\s*|\s+and\s+/)) {
      if (s.trim()) allow.push(s.trim());
    }
  }
  for (const dm of text.matchAll(new RegExp(`(?:not|never|except)\\s+(?:from|at)\\s+(${NAME})`, "g"))) {
    deny.push(dm[1].trim());
  }
  return { allow, deny };
}

function parseIntent(text: string): string | undefined {
  const m = text.match(
    /\b(?:to\s+)?(buy|purchase|order|book|pay for|rent|subscribe to)\s+(.+?)(?:\s+from\b|\s+at\b|\s+up to\b|\s+under\b|\s+expir|,|\.|$)/i,
  );
  if (m) return `${m[1].toLowerCase()} ${m[2].trim()}`.trim();
  return undefined;
}

export const ruleBasedParser: Parser = (text, now = new Date()) => {
  const out: ParsedConstraints = {};
  const intent = parseIntent(text);
  if (intent) out.intent = intent;
  const cats = parseCategories(text);
  if (cats.length) out.categories = cats;
  const merchants = parseMerchants(text);
  if (merchants.allow.length || merchants.deny.length) out.merchants = merchants;
  const amount = parseAmount(text);
  if (amount) out.max_amount = amount;
  const expiry = parseExpiry(text, now);
  if (expiry) out.expires_at = expiry;
  return out;
};

export interface CompileOptions {
  agentId: string;
  privateKey: Buffer;
  parser?: Parser;
  ttlDays?: number;
  now?: Date;
}

export function compile(text: string, opts: CompileOptions): SignedMandate {
  const parser = opts.parser ?? ruleBasedParser;
  const parsed = parser(text, opts.now);
  const mandate = buildMandate({
    agentId: opts.agentId,
    intent: parsed.intent,
    categories: parsed.categories,
    merchants: parsed.merchants,
    maxAmount: parsed.max_amount,
    issuedAt: opts.now,
    expiresAt: parsed.expires_at,
    ttlDays: opts.ttlDays,
  });
  return signMandate(mandate as unknown as Record<string, unknown>, opts.privateKey);
}
