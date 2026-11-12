# Эталон NCALayer: Basics, PKIEssentials, Common Utils

Поведение официальных модулей описано по коду бандлов из дистрибутива НУЦ. Это закрывает
пробел «официального описания нет» для Common Utils и PKIEssentials. Тексты кода в репозиторий
не переносились, ниже — только наблюдаемое поведение.

## Источник

`https://ncl.pki.gov.kz/images/NCALayer/ncalayer.zip`, скачан 12.11.2026, SHA-256
`31f47c126fe56107d76f11c446110dfa09fc397f032a54ef8ee4d7bcaf6461cb`. Внутри `ncalayer.sh`
(Linux, `Version=1.4`) с приложенным ZIP `kncabundles/`:

| Бандл | Версия | SCM-Revision | Что содержит |
|---|---|---|---|
| `knca_applet` | 0.4.10 | `5ca44527` | модуль `kz.gov.pki.knca.basics`: `PKIExtras.sign`, `PKIEssentials.generateCsr/importCertificate` |
| `NCALayerCommonBundle` | 0.3.4 | `95a0f0bb` | модуль `kz.gov.pki.knca.commonUtils` |
| `NCALayerServices` | 0.7.4 | `33e04bb5` | обёртка ответа Basics (`CommonResponse`, `CommonInvoker`) |
| `NCAWebSocket` | 0.4.2 | `436fab1e` | сервер `wss://127.0.0.1:13579` |
| `knca_provider_util` | 0.8.8 | `37b9d06c` | тип ключа, хранилища, CMS/XML |
| `kalkancrypt` | 0.7.8 | `06922d4b` | провайдер Kalkan, `PEMWriter` |

NCALayer может обновлять модули с сервера НУЦ после установки. Всё ниже относится к этим
версиям; ответы установленного NCALayer у пользователя могут отличаться.

## Транспорт (NCAWebSocket 0.4.2)

- При открытии сокета сервер всегда сначала отправляет `{"result":{"version":"1.4"}}`
  (значение из свойства `ncalayer.version`). Подключения не с `127.0.0.1` закрываются.
- `--heartbeat--` возвращается эхом.
- Поле `module` по умолчанию `kz.gov.pki.knca.applet.Applet` (старый API апплета).
  Неизвестный модуль: `{"success":false,"errorCode":"MODULE_NOT_FOUND"}`.
- Модулю передаётся `origin` из заголовка рукопожатия. Basics его не проверяет:
  константы `nca.pki.gov.kz`/`ca.pki.gov.kz` объявлены, но не используются.

## Basics (`kz.gov.pki.knca.basics`)

Обёртка ответа: успех `{"status":true,"body":…}`; ошибка
`{"status":false,"code":…,"message":…,"details":…}`. `details` — `toString()` причины
Java-исключения и **присутствует только при наличии причины**. Коды: `SIGNING_FAILURE`,
`INVALID_SIGNING_PARAMS`, `CERTIFICATE_PARSING_FAILURE`, `CSR_GENERATING_FAILURE`,
`CERTIFICATE_IMPORTING_FAILURE`, `INVALID_IMPORTING_CERTIFICATE`, `GENERAL_ERROR`,
`INVOCATION_ERROR`, а также коды провайдера (`ProviderUtilFailure`). Отмена в окне —
`EmptyResponse`, то есть `{"status":true,"body":{}}`. Таймаута ожидания нет: вызов ждёт окно
без ограничения.

`sign` (класс `PKIExtras`; поле `class` можно не указывать):

- `allowedStorages` нет → все хранилища; неизвестные имена отбрасываются.
- `format`: `xml`, `cms`, `raw`; иное → `INVALID_SIGNING_PARAMS`.
- `data`: строка или массив строк **для любого формата** (wiki говорит «только XML»).
- XML: `signingParams.allowExpired`, `allowRevoked`. CMS: `decode` (false), `encapsulate`
  (true), `digested` (false), `allowRevoked`, `tsaProfile` — только наличие объекта, профиль
  фиксирован (ГОСТ 34.11-2015-512, политика TSA ГОСТ-2015). raw: `decode`, `outputCert`.
- `signerParams`: `extKeyUsageOids` (обязателен), `chain` (нет → действующие УЦ НУЦ;
  `[]` → цепочка необязательна), `iin`, `bin`, `serialNumber`.
- Также читаются `logo` (base64 до 50 000 символов) и `type`, `locale`.
- Результат CMS: **PEM** `-----BEGIN CMS-----` … `-----END CMS-----` для каждого документа
  (`PEMWriter` Kalkan), массив в `body.result`. XML: массив подписанных XML.
- Результат raw: без `outputCert` один документ → `body.result` — строка base64, несколько →
  массив; с `outputCert` → `{signatures:[…], certificate:PEM}`. RSA подписывается
  `SHA256withRSA`, ГОСТ — алгоритмом ключа.
- Формы ответа подтверждены запуском официального `PKIExtras.sign` и обёртки `CommonInvoker` на
  синтетическом ключе RSA, без окна выбора ключа (`tests/interop/BasicsReference.java`, результат —
  `tests/fixtures/ncalayer-basics-results.json`). PEM пишется с системным переводом строки: в
  Windows `\r\n`. XML получает объявление `standalone="no"` и каноникализацию
  `REC-xml-c14n-20010315`; Tegin сохраняет объявление документа и использует exc-c14n.

`generateCsr` (класс `PKIEssentials`):

- `allowedStorages` обязателен; файловым хранилищам ставится пароль `defaultPassword`.
- `dn` — объект OID → значение; RDN сортируются в естественном порядке OID.
- `subjectAltNames`: если непустой, обязан содержать CN, иначе ошибка; каждое имя — `dNSName`.
  `email` (непустой) добавляется в тот же SAN как `rfc822Name`. В DN e-mail не попадает.
- `params` — массив `{algorithm, length}`: по ключу и CSR на элемент, в один контейнер.
- `omittedKeyIds` — передаётся провайдеру; для удостоверения личности дополняется ID
  созданных ключей. Для файла не используется.
- `locale` по умолчанию `kk`. `isCustomPKCS12Password` в NCALayer не передаётся — это
  логика страницы НУЦ.
- Ответ `{status:true, body:{pems:[…]}}`; поля `container` нет (страница его читает, если есть).

`importCertificate`:

- `allowedStorage` (одно), `defaultPassword`, `keystorePath`, `certificates` (PEM). Каждый
  сертификат ставится в контейнер к своему ключу; неразборчивый → `INVALID_IMPORTING_CERTIFICATE`.
- Для файла после установки пароль контейнера меняется с `defaultPassword` на введённый
  пользователем в окне установки.
- Ответ `{status:true, body:{result:true}}`.

## Common Utils (`kz.gov.pki.knca.commonUtils`)

- Ответ `{"code":"200"|"500","message":…,"responseObject":…}`; пустые поля в JSON не попадают,
  `uuid` запроса возвращается. Любая ошибка — `code:"500"`; отмена — `message:"action.canceled"`. Метод ищется по имени и числу аргументов;
  нет такого → `500`, `NoSuchMethodException <имя>`.
- **`keyType` фильтрует ключи**: в окне видны только ключи нужного типа. Тип ключа по
  сертификату (`knca_provider_util`):
  - SIGNATURE — KeyUsage digitalSignature и nonRepudiation; такой ключ также AUTHENTICATION,
    если подпись сертификата ГОСТ 34.10-2015-512 или sha256WithRSA с keyAgreement;
  - AUTHENTICATION — digitalSignature, keyEncipherment и EKU clientAuth;
  - неизвестное значение `keyType` → как без него: видны SIGNATURE и AUTHENTICATION, ключи
    других типов скрыты.
- `getKeyInfo(storage)` → `responseObject`: `alias`, `keyId` (SKI, hex), `algorithm`,
  `subjectCn`, `subjectDn`, `issuerCn`, `issuerDn`, `serialNumber` (hex), `certNotBefore`,
  `certNotAfter` (миллисекунды строкой), `authorityKeyIdentifier` (hex), `pem`. Проверено запуском
  официальных классов на синтетических сертификатах (`tests/interop/KeyInfoReference.java`,
  результат — `tests/fixtures/ncalayer-keyinfo.json`):
  - `algorithm` — имя ключа в Kalkan: `RSA`, `ECGOST3410-2015` (256 и 512), `ECGOST34310` (2004);
  - DN — прямой порядок RDN, обозначения X509Name Kalkan (`S` для ST, `G` для givenName, `T`,
    `E`, `SURNAME`, `SERIALNUMBER`, `DC`, `UID`, `STREET`, `PostalCode`, `BusinessCategory`,
    иначе OID), экранируются `, " \ + = < > ;`, хвостовые пробелы значения отбрасываются;
  - `serialNumber` — hex содержимого DER INTEGER, ведущий нулевой байт сохраняется;
  - без SKI пропадают и `keyId`, и `authorityKeyIdentifier`;
  - сертификат без KeyUsage не относится ни к одному типу и в окне не показывается.
- `getActiveTokens` → список найденных аппаратных хранилищ.
- `changeLocale(lang)` → `{"code":"200"}` без `responseObject`.
- `createCMSSignatureFromBase64` → base64 DER (в отличие от Basics, не PEM).

## Сравнение с Tegin

| № | Вопрос | NCALayer | Tegin | Решение |
|---|---|---|---|---|
| 1 | `keyType` в Common Utils | фильтрует по правилу выше | не сужал выбор | исправлено (`05db357`); сторонние модули сохраняют своё правило |
| 2 | `details` в ошибке Basics | только при наличии причины | отсутствует | совпадает с ошибками NCALayer без причины; не менять |
| 3 | Форма `getKeyInfo` | поля выше | были свои поля (`name`, `notAfter`, `certificate`…) | эталонные поля добавлены, `subjectDn`/`issuerDn`/`algorithm` в форме Kalkan, свои поля оставлены (`9ae3817`); `alias` не передаётся — хранилища ключей нет |
| 4 | Таймаут | нет | 180 с → ответ отмены | ближайший эквивалент; оставить, описано |
| 5 | Резервный таймер `bridge.js` | — | отвечал формой Common Utils и на Basics | исправлено: форма по модулю (`4552a35`, `a293148`) |
| 6 | Просроченный запрос при новом | — | окно не закрывалось | исправлено (`e6be5f5`) |
| 7 | raw, массив CMS, `changeLocale`, `getActiveTokens` | raw и массив для любого формата — официальные; `changeLocale` → `{"code":"200"}`; токены — реальный список | raw всегда массив | `changeLocale` → `{"code":"200"}`, ошибки Common Utils → `500`, отмена `action.canceled`, `uuid` возвращается (`a293148`); raw-строка для одной подписи — **решение владельца** вместе с п. 9; `getActiveTokens: []` верно, токенов нет |
| 8 | HTTP API KAZTOKEN | вне NCALayer | не перехватывается | не исправимо в расширении; описано |
| 9 | **CMS в Basics** | **PEM `BEGIN CMS`**, перевод строки системный (`\n`, в Windows `\r\n`) | **голый base64** | контракт Tegin сохранён до сверки с развёрнутым ЭДО; оба закреплены в `basics-results.test.js` |
| 10 | Приветствие | всегда при открытии | пропускается, если запрос отправлен в `onopen` | сознательно; страницы НУЦ приветствие игнорируют |
| 11 | XML `allowExpired`/`allowRevoked`, `logo` | читаются | неизвестные параметры → явная ошибка | целевые порталы их не передают; проверить при подключении сайта |
| 12 | `subjectAltNames` в `generateCsr` | `dNSName`, CN обязателен | отказ «пока не поддерживаются» | реализовать по эталону, если понадобится шаблону ИС |
| 13 | Пароль при выпуске | задаётся при установке | задаётся при генерации (шифрует ключ заявки) и при сохранении `.p12` | итоговый файл эквивалентен; описано в `nca-key-issuance.md` |
