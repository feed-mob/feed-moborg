import fs from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

type PageEntry = {
  pageId: string;
  title: string;
  depth: number;
  url: string;
  file: string;
  version?: number;
  createdAt?: string;
  bytesHtml?: number;
};

type IndexFile = {
  count: number;
  pages: PageEntry[];
};

const root = process.cwd();
const inputDir = path.join(root, 'scraped');
const indexPath = path.join(inputDir, 'index.json');
const outputPath = path.join(root, 'data', 'db', 'docs.sqlite');

const index = JSON.parse(await fs.readFile(indexPath, 'utf8')) as IndexFile;

await fs.mkdir(path.dirname(outputPath), { recursive: true });
await fs.rm(outputPath, { force: true });

const db = new DatabaseSync(outputPath);
db.exec(`
  PRAGMA journal_mode = OFF;
  PRAGMA synchronous = OFF;

  CREATE TABLE pages (
    id INTEGER PRIMARY KEY,
    page_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    depth INTEGER NOT NULL,
    url TEXT NOT NULL,
    file TEXT NOT NULL,
    version INTEGER,
    created_at TEXT,
    bytes_html INTEGER,
    content TEXT NOT NULL
  );

  CREATE INDEX idx_pages_page_id ON pages(page_id);
  CREATE INDEX idx_pages_file ON pages(file);
  CREATE INDEX idx_pages_url ON pages(url);
  CREATE INDEX idx_pages_title ON pages(title);

  CREATE VIRTUAL TABLE pages_fts USING fts5(
    page_id,
    title,
    file,
    url,
    content,
    tokenize = 'unicode61'
  );
`);

const insertPage = db.prepare(`
  INSERT INTO pages (
    id, page_id, title, depth, url, file, version, created_at, bytes_html, content
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const insertFts = db.prepare(`
  INSERT INTO pages_fts (rowid, page_id, title, file, url, content)
  VALUES (?, ?, ?, ?, ?, ?)
`);

for (const [rowIndex, page] of index.pages.entries()) {
  const content = await fs.readFile(path.join(inputDir, page.file), 'utf8');
  const rowId = rowIndex + 1;
  insertPage.run(
    rowId,
    page.pageId,
    page.title,
    page.depth,
    page.url,
    page.file,
    page.version ?? null,
    page.createdAt ?? null,
    page.bytesHtml ?? null,
    content
  );
  insertFts.run(rowId, page.pageId, page.title, page.file, page.url, content);
}

db.exec('PRAGMA optimize;');
db.close();

console.log(`Wrote ${outputPath} with ${index.pages.length} pages`);
