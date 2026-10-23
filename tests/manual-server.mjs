// Interactive test harness: loopback only, disposable keys, no real user data.
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
const directory = mkdtempSync(join(tmpdir(), 'ncabrowser-manual-'));
const rsa = rsaFixture();
writeFileSync(join(directory, 'test-rsa.p12'), rsa.container);
writeFileSync(join(directory, 'test-rsa-certificate.pem'), rsa.certificate);
rsa.container.fill(0);
for (const family of ['512', '256', '2004']) {
  const key = gostFixture(family); writeFileSync(join(directory, `test-gost${family}.p12`), key.container); key.container.fill(0);
}
writeFileSync(join(directory, 'document.txt'), 'Disposable manual browser test: Привет');
const javascript = `
const $ = id => document.getElementById(id);
let socket;
async function run(method) {
  $('status').textContent = 'Ожидание расширения…'; $('result').value = '';
  socket = new WebSocket('wss://127.0.0.1:13579');
  let welcome = true;
  socket.onerror = () => { $('status').textContent = 'Ошибка: адаптер недоступен'; };
  socket.onmessage = ({data}) => {
    const answer = JSON.parse(data);
    if (welcome) {
      welcome = false;
      $('adapter').textContent = JSON.stringify(answer);
      if (method === 'getActiveTokens' || method === 'getKeyInfo') socket.send(JSON.stringify({module:'kz.gov.pki.knca.commonUtils',method,args:['PKCS12']}));
      else socket.send(JSON.stringify({module:'kz.gov.pki.knca.commonUtils',method:method==='xml'?'signXml':method,args:method==='xml'?['PKCS12','SIGNATURE','<request><text>Disposable browser test: Привет</text></request>','','']:['PKCS12','SIGNATURE',btoa(unescape(encodeURIComponent($('document').value))),true]}));
      $('status').textContent = method==='getActiveTokens'?'Проверка адаптера…':'Подтвердите операцию в окне расширения';
      return;
    }
    $('result').value = JSON.stringify(answer, null, 2);
    $('status').textContent = answer.code === '200'?'Успешно: результат получен':'Операция отменена или завершилась ошибкой';
    if (answer.code === '200' && typeof answer.responseObject === 'string') {
      const xml = method==='xml';
      const value = xml ? answer.responseObject : Uint8Array.from(atob(answer.responseObject), c=>c.charCodeAt(0));
      $('download').href=URL.createObjectURL(new Blob([value]));
      $('download').download=xml?'ncabrowser-manual-signed.xml':'ncabrowser-manual-signature.p7s'; $('download').hidden=false;
    }
    socket.close();
  };
}
for (const button of document.querySelectorAll('[data-method]')) button.onclick = ()=>{ $('download').hidden=true;run(button.dataset.method); };
`;
const html = `<!doctype html><html lang="ru"><meta charset="utf-8"><title>Tegin — ручной тест</title><style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 20px;background:#f5f6fa;color:#172239}button,a{margin:4px;padding:12px;border:1px solid #ccd5eb;border-radius:8px;background:white;color:#234dc8}textarea{width:100%;padding:12px;box-sizing:border-box}pre{white-space:pre-wrap;overflow-wrap:anywhere}p{line-height:1.6}</style><h1>Tegin · тест установленного Chrome</h1><p>Только одноразовые тестовые ключи. Пароль: <strong>${PASSWORD}</strong>.<br>Это тестовая страница; документы и ключи пользователя не нужны.</p><textarea id="document" rows="3">Disposable manual browser test: Привет</textarea><p><button data-method="getActiveTokens">Проверить адаптер</button><button data-method="getKeyInfo">Сведения о ключе</button><button data-method="createCAdESFromBase64">Подписать CAdES-BES</button><button data-method="createCMSSignatureFromBase64">Подписать CAdES-T</button><button data-method="xml">Подписать XML</button></p><p id="status" role="status">Готов к проверке</p><pre id="adapter"></pre><textarea id="result" rows="10" readonly></textarea><p><a id="download" hidden>Скачать тестовый результат</a></p><script src="/test.js"></script></html>`;
const server = createServer((req,res)=> {
  if (req.method !== 'GET' || !['/','/test.js'].includes(req.url)) {res.writeHead(404);res.end();return;}
  res.setHeader('Content-Type',req.url==='/'?'text/html; charset=utf-8':'text/javascript; charset=utf-8');
  res.setHeader('Cache-Control','no-store');res.end(req.url==='/'?html:javascript);
});
server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({url:`http://127.0.0.1:${server.address().port}/`,directory,password:PASSWORD})));
const cleanup=()=>server.close(()=>{rmSync(directory,{recursive:true,force:true});process.exit(0);});
process.on('SIGTERM',cleanup);process.on('SIGINT',cleanup);
