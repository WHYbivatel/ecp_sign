// Deterministic rasterization of our own geometric T logo; no browser/runtime dependency.
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
const crc32 = data => {
  let crc = 0xffffffff;
  for (const value of data) {
    crc ^= value;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
};
function chunk(type, data) {
  const name = Buffer.from(type); const length = Buffer.alloc(4); length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4); checksum.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, checksum]);
}
for (const size of [16,32,48,128]) {
  const rows = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    let red=0, green=0, blue=0, alpha=0;
    for (let sy=0;sy<4;sy++) for(let sx=0;sx<4;sx++) {
      const px=(x+(sx+.5)/4)*40/size, py=(y+(sy+.5)/4)*40/size;
      const dx=Math.max(12-px,0,px-28),dy=Math.max(12-py,0,py-28);
      if(dx*dx+dy*dy>144) continue;
      alpha++;
      const letter=(px>=10&&px<=30&&py>=12&&py<=16)||(px>=18&&px<=22&&py>=16&&py<=28);
      const t=(px+py)/80;
      red+=letter?255:69+(40-69)*t;green+=letter?255:111+(72-111)*t;blue+=letter?255:240+(188-240)*t;
    }
    const offset=y*(size*4+1)+1+x*4;
    if(alpha) { rows[offset]=Math.round(red/alpha); rows[offset+1]=Math.round(green/alpha); rows[offset+2]=Math.round(blue/alpha); rows[offset+3]=Math.round(alpha/16*255); }
  }
  const header=Buffer.alloc(13);header.writeUInt32BE(size,0);header.writeUInt32BE(size,4);header[8]=8;header[9]=6;
  writeFileSync(new URL(`../extension/assets/icon-${size}.png`,import.meta.url), Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),chunk('IDAT',deflateSync(rows)),chunk('IEND',Buffer.alloc(0))]));
}
console.log('Generated Tegin toolbar icons.');
