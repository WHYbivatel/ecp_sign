async function requestSignature(request) {
  const socket = new WebSocket('wss://127.0.0.1:13579');
  return new Promise((resolve, reject) => {
    let welcomed = false;
    socket.onerror = () => reject(new Error('Расширение не обнаружено. Проверьте установку и доступ к сайту.'));
    socket.onclose = () => reject(new Error('Соединение закрыто.'));
    socket.onmessage = event => {
      const message = JSON.parse(event.data);
      if (!welcomed) {
        if (!message.result?.version) return reject(new Error('Неожиданное приветствие.'));
        welcomed = true; socket.send(JSON.stringify(request)); return;
      }
      if (message.status === false || (message.code && message.code !== '200')) reject(new Error(message.message || 'Операция отменена.'));
      else if (message.status && !message.body?.result) reject(new Error('Операция отменена.'));
      else resolve(message.responseObject ?? message.body.result);
      socket.close();
    };
  });
}

for (const format of ['xml', 'cms']) document.querySelector(`#${format}`).addEventListener('click', async () => {
  const status = document.querySelector('#status');
  try {
    const text = document.querySelector('#input').value;
    const data = format === 'cms' ? btoa(String.fromCharCode(...new TextEncoder().encode(text))) : text;
    status.textContent = 'Подтвердите операцию в окне расширения.';
    const result = await requestSignature({ module: 'kz.gov.pki.knca.basics', method: 'sign', args: {
      allowedStorages: ['PKCS12'], format, data,
      signingParams: format === 'cms' ? { decode: true, encapsulate: true } : {}, signerParams: { extKeyUsageOids: [] }
    } });
    document.querySelector('#result').value = Array.isArray(result) ? result.join('\n\n') : result;
    status.textContent = 'Подпись получена. На сервер этот пример её не отправляет.';
  } catch (error) { status.textContent = error.message; }
});
