# Подключение нового сайта к Tegin

Отдельного API у Tegin нет: сайт говорит с ним на протоколе NCALayer. Расширение отвечает
внутри страницы на `wss://127.0.0.1:13579`, локальная служба не нужна. Ниже — подмножество
протокола, которое одинаково работает с Tegin и с NCALayer 1.4. Подробности поведения NCALayer —
в [ncalayer-reference.md](ncalayer-reference.md).

## Рекомендуемый вызов: `kz.gov.pki.knca.basics` → `sign`

```js
function sign(args) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket('wss://127.0.0.1:13579/');
    socket.onopen = () => socket.send(JSON.stringify({ module: 'kz.gov.pki.knca.basics', method: 'sign', args }));
    socket.onmessage = event => {
      const response = JSON.parse(event.data);
      if (response.result?.version) return; // приветствие NCALayer, не ответ
      socket.close();
      if (response.status === true && Array.isArray(response.body?.result)) resolve(response.body.result);
      else if (response.status === true) reject(Object.assign(new Error('Отменено'), { cancelled: true }));
      else reject(new Error(response.message || response.code));
    };
    socket.onerror = () => reject(new Error('Нет ни Tegin, ни NCALayer'));
  });
}

const [cms] = await sign({
  allowedStorages: ['PKCS12'],
  format: 'cms',
  data: base64Document,
  signingParams: { decode: true, encapsulate: false, digested: false, tsaProfile: {} },
  signerParams: { extKeyUsageOids: ['1.3.6.1.5.5.7.3.4'] },
  locale: 'ru'
});
const der = cms.replace(/-----(BEGIN|END) CMS-----|\s/g, ''); // NCALayer отдаёт PEM, Tegin — base64
```

## Правила

- **Приветствие.** NCALayer после открытия сокета всегда присылает
  `{"result":{"version":"1.4"}}`. Tegin присылает его (с `implementation: "Tegin"`), только если
  запрос не отправлен сразу в `onopen`. Не считайте первое сообщение ответом.
- **Один запрос на сокет.** Второй `send`, пока первый не завершён, закрывает сокет (код 1008).
  Запрос не больше 3 МБ, до 10 документов в `data`.
- **Хранилище.** Tegin работает только с файлами PKCS#12: в `allowedStorages` должен быть
  `PKCS12` (или поле не передаётся). Аппаратные носители — отказ.
- **Форматы.** `xml` (целый документ, enveloped XMLDSig), `cms` (CAdES-BES, с `tsaProfile: {}` —
  CAdES-T с меткой НУЦ), `raw`. Метка времени — только для CMS.
- **Ответ.** `body.result` у Tegin всегда массив. CMS в Tegin — base64 DER, в NCALayer — PEM;
  принимайте оба. Одну raw-подпись NCALayer отдаёт строкой, Tegin — массивом из одной строки.
- **Отмена и таймаут.** `{"status":true,"body":{}}` — пользователь отменил или прошло 3 минуты
  (у NCALayer таймаута нет). Не показывайте это как ошибку подписи.
- **Ошибка.** `{"status":false,"code":…,"message":…}`. `message` у Tegin — текст на русском для
  пользователя; `details` есть только при причине исключения.
- **Ограничения выбора ключа.** `signerParams`: `extKeyUsageOids` (все OID должны быть в
  сертификате), `iin`, `bin`, `serialNumber`, `chain` (`[]` — цепочка необязательна, иначе
  проверяется цепочка НУЦ РК). Неизвестные поля и параметры — явный отказ, а не игнорирование.
- **Проверка на сервере.** Tegin проверяет срок, цепочку и отзыв перед подписью, но сайт обязан
  сам проверить подпись, сертификат и привязку к пользователю.

## Common Utils и сторонние модули

`kz.gov.pki.knca.commonUtils` поддерживается для старых сайтов: `getKeyInfo`, `signXml`,
`signXmls`, `createCAdESFromBase64`, `createCAdESFromBase64Hash`, `createCMSSignatureFromBase64`.
Ответы и фильтр `keyType` — как в Common Bundle 0.3.4. Для новых сайтов используйте Basics.
Сторонние модули (NURSign, ИСЭЗ и другие) — в [modules.md](modules.md); пользователь может их
выключить.

## Чего нет

- Выпуск ключей (`PKIEssentials.generateCsr`, `importCertificate`) доступен только основной
  странице `did.pki.gov.kz` / `nca.pki.gov.kz`.
- HTTP API KAZTOKEN (`https://127.0.0.1:24680/`) не перехватывается.
- `getActiveTokens` возвращает пустой список.
