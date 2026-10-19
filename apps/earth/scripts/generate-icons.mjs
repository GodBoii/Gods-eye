#!/usr/bin/env node
// Export the shared God's Eye artwork for both frontends. Run from any directory.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const source = await readFile(path.join(root, 'assets/branding/godseye-master.png'));
const destinations = ['apps/web/public', 'apps/earth/public'];
const sizes = [16, 32, 48, 180, 192, 512];
const icons = new Map();
for (const size of sizes) {
  icons.set(size, await sharp(source).resize(size, size).png({ compressionLevel: 9 }).toBuffer());
}
// Keep the mark inside the central safe circle used by mobile icon masks.
const maskable = await sharp(source).resize(420, 420)
  .extend({ top: 46, bottom: 46, left: 46, right: 46, background: '#090b0b' })
  .png({ compressionLevel: 9 }).toBuffer();

// ICO supports embedded PNG frames; include small native sizes for browser tabs.
const frames = [16, 32, 48].map((size) => ({ size, data: icons.get(size) }));
const header = Buffer.alloc(6 + frames.length * 16);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(frames.length, 4);
let offset = header.length;
frames.forEach(({ size, data }, index) => {
  const entry = 6 + index * 16;
  header[entry] = size;
  header[entry + 1] = size;
  header.writeUInt16LE(1, entry + 4);
  header.writeUInt16LE(32, entry + 6);
  header.writeUInt32LE(data.length, entry + 8);
  header.writeUInt32LE(offset, entry + 12);
  offset += data.length;
});
const ico = Buffer.concat([header, ...frames.map(({ data }) => data)]);

for (const destination of destinations) {
  const publicDir = path.join(root, destination);
  await mkdir(path.join(publicDir, 'icons'), { recursive: true });
  for (const [size, data] of icons) {
    await writeFile(path.join(publicDir, `icons/icon-${size}.png`), data);
  }
  await writeFile(path.join(publicDir, 'icons/icon-512-maskable.png'), maskable);
  await writeFile(path.join(publicDir, 'favicon.ico'), ico);
  console.log(`Brand assets exported to ${destination}`);
}
