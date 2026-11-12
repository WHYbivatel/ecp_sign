# Подача в Chrome Web Store, Edge Add-ons и Firefox AMO

Подготовка к шагу 8. **Ничего не подано**: публикация в магазинах — отдельное действие владельца. Документ
описывает код ветки `codex/nca-key-issuance`; формулировки для форм магазинов даны по-английски, потому что
ревьюеры читают их на английском.

## Артефакты и их проверка

- Сборка: `npm run verify:package` — `npm run package` (`dist/tegin-chromium-<версия>.zip`,
  `dist/tegin-firefox-<версия>.zip`, `dist/checksums.json`), затем `scripts/verify-package.mjs --smoke`.
- Что проверяется в самих архивах: версия манифеста равна `package.json`; все файлы, на которые ссылаются манифест
  и страницы, на месте; нет тестовой сборки, source map, ключей, `.env`, `node_modules`, тестов; CSP `script-src
  'self'`, нет удалённых скриптов; содержимое побайтно равно `dist/<target>`; SHA-256 равен `checksums.json`.
  `--smoke`: архив Chromium распаковывается во временную папку и загружается в Chromium — service worker нужной
  версии запускается, 6 страниц расширения открываются без ошибок скриптов и нарушений CSP.
- Firefox-архив проходит официальный валидатор AMO `addons-linter` 10.15.0: 12.11.2026 — 0 ошибок, 1
  предупреждение (`data_collection_permissions` не поддерживается минимальной версией Firefox для Android; Android
  не заявляется).
- CI (задача `package`) выполняет то же и выкладывает архивы артефактом `tegin-packages-<sha>` на 14 дней.
  Подавать в магазин нужно архив, прошедший эти проверки, а не пересобранный вручную.

## Назначение (single purpose)

> Tegin signs documents and portal requests with the user's Kazakhstan electronic signature (PKCS#12 file key,
> GOST and RSA) locally in the browser. It replaces the NCALayer desktop application for the supported portal
> operations: the page sends a signing request, the user reviews it in the extension window, selects the key file
> and enters its password; the private key and password never leave the extension.

## Разрешения

| Разрешение | Где используется | Justification (для формы) |
|---|---|---|
| `storage` | `storage.session`: ожидающий запрос сайта (до 180 с) и журнал вызовов вкладки без значений; `storage.local`: зашифрованный ключ заявки НУЦ до установки сертификата, настройки модулей | Keeps a pending signing request while the user reviews it, the module settings, and an application key encrypted with the user's password until the certificate authority issues the certificate. No keys or passwords in clear. |
| `scripting` | `registerContentScripts` только для сайта, который пользователь подключил кнопкой «Подключить сайт» (после `permissions.request`) | Registers the NCALayer-compatible adapter on a non-.kz HTTPS site only after the user connects that site and grants access to it. |
| `activeTab` | Клик по значку: окно расширения читает адрес текущей вкладки, чтобы показать её статус и предложить «Подключить сайт» | Lets the extension window show the status of the tab the user clicked from and offer to connect that site. |
| `alarms` | Резервный таймер ожидающего запроса: просроченный запрос завершается, окно закрывается | Expires a pending signing request and closes its window if the service worker was suspended. |
| `https://*.kz/*` | Content scripts адаптера NCALayer на казахстанских порталах (eGov, НУЦ, Госзакупки и др.); загрузка CRL НУЦ (`crl.pki.gov.kz`, `crl1.pki.gov.kz`, `crl.root.gov.kz`) | Kazakhstan government portals call NCALayer through a local WebSocket; the adapter answers those calls on .kz sites. Certificate revocation lists are fetched from the national certificate authority. |
| `http://ocsp.pki.gov.kz/*`, `http://tsp.pki.gov.kz/*` | OCSP и метки времени НУЦ (службы работают только по HTTP; ответы проверяются по подписи и цепочке НУЦ) | Certificate status (OCSP) and RFC 3161 timestamps from the national certificate authority, which serves them over HTTP only; responses are verified against the authority's pinned roots. |
| `http://localhost/*`, `http://127.0.0.1/*` | Локальные страницы интеграторов и тесты | **Решение владельца**, см. ниже. |
| `optional_host_permissions: https://*/*` | Запрашивается для одного сайта, когда пользователь нажимает «Подключить сайт» | Requested per site, only when the user connects a non-.kz HTTPS site that uses the NCALayer protocol. |

Широкие права на хосты (`https://*.kz/*`, необязательное `https://*/*`) ведут к углублённой проверке в Chrome Web
Store; это ожидаемо.

## Удалённый код

> No remote code. All scripts are packaged; the extension pages CSP is `script-src 'self'; worker-src 'self';
> object-src 'none'`. Network requests go only to the national certificate authority services listed above, and
> their responses are data (OCSP, CRL, timestamps), never code.

Код собран esbuild и минифицирован, не обфусцирован. **AMO требует исходный код** для минифицированных файлов:
приложить архив исходников коммита (`git archive`) и инструкцию сборки (Node 22, `npm ci`, `npm run build`,
результат — `dist/firefox`; сборка воспроизводится побайтно, `tests/build-paths.test.js` и раздел «Сверка ветки»
в журнале работ).

## Данные (Chrome «Privacy practices», Edge, AMO)

Основа — [privacy-policy.md](privacy-policy.md) (черновик, не опубликован; страница должна быть доступна по
URL до подачи).

- Разработчику ничего не передаётся: серверов Tegin нет, аналитики и рекламы нет.
- Хранятся только на устройстве: ожидающий запрос (`storage.session`), зашифрованный ключ заявки и настройки
  (`storage.local`), публичные CRL НУЦ в Cache Storage.
- Третьему лицу — НУЦ РК — уходят: в OCSP серийный номер сертификата пользователя; в метку времени — хеш значения
  подписи. Это нужно для основной функции (проверка отзыва и метка времени).
- Заявления Chrome: не продаётся, не используется вне назначения, не используется для кредитных решений.

**Требует решения:** как отметить передачу серийного номера сертификата в НУЦ. В Chrome — вероятно,
«Personally identifiable information» не отмечается (серийный номер не идентифицирует человека сам по себе), но
категория «Authentication information» относится к паролям, которые не передаются. В Firefox манифест сейчас
заявляет `data_collection_permissions.required: ['none']`; по правилам Mozilla «none» означает, что данные не
передаются ни разработчику, ни третьим лицам. Ответ согласовать с юристом до подачи (вопросы — в записке для
юриста, этап 5) и при необходимости изменить манифест отдельным коммитом.

## Инструкция для ревьюера

Реальный ключ ЭЦП РК ревьюеру недоступен. Проверка без портала:

1. Создать синтетический ключ: `openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=Reviewer Test" -days 30
   -keyout k.pem -out c.pem && openssl pkcs12 -export -inkey k.pem -in c.pem -out reviewer.p12 -passout
   pass:Review-2026` (или приложить такой файл к заявке; личных данных в нём нет).
2. Значок Tegin → «Подписать» → любой файл → `reviewer.p12`, пароль `Review-2026` → «Подписать» → «Скачать
   подпись» / «Проверить эту подпись».
Интерфейс только на русском: в инструкции указать названия кнопок. Сертификат вне цепочки НУЦ подписывает, статус
отзыва для него «не проверялся». Портальный сценарий ревьюер не проверит: порталы требуют сертификатов НУЦ
(демо SDK `sdk.pki.gov.kz` — сертификат с назначением clientAuth).

> Reviewer notes: the extension needs a PKCS#12 key file. A self-signed test key is attached (password
> `Review-2026`). Open the extension, choose "Подписать", pick any file, select the key, enter the password and
> sign; then verify the result in "Проверить". No account is required.

## Переход с распакованной версии и обновления

- У магазинной сборки другой ID расширения, и её `storage.local` пуст. Ключ заявки НУЦ, ещё не дождавшийся
  сертификата, переносится только файлом резервной копии `.tegin-request.json`; восстановление — в окне установки
  сертификата. Копию предлагают скачать **только сразу после создания заявки**, в разделе «Ключи заявок» выгрузки
  нет. Если копия не сохранена, сертификат нужно установить в распакованной копии (получится `.p12`) и только потом
  переходить. Выгрузка копии из «Ключей заявок» — кандидат на доработку до подачи.
- Две копии одновременно: страница видит «Конфликт версий» (проверка уже есть), пользователь удаляет старую.
- Обновления из магазинов приходят автоматически. Версия манифеста должна расти: `0.5.3` уже занята двумя
  разными сборками на сайте (`71a68ff`, `dd40b5e`), поэтому первая магазинная версия — новая (например `0.6.0`),
  повышение — отдельным коммитом при подготовке релиза.

## Откат

- Сайт: `releases.json` хранит предыдущую сборку Chromium (`rollback`), архив остаётся по своему URL.
- Магазины не принимают версию ниже опубликованной. Откат — повторная подача кода предыдущего коммита с
  повышенной версией (например `0.6.1` с кодом `0.6.0`); если в кабинете магазина есть функция возврата к прошлой
  версии, проверить её на момент подачи. Firefox AMO позволяет отключить проблемную версию, и пользователи
  получат предыдущую подписанную.
- Перед любым откатом проверить, читает ли старая версия данные `storage.local`, записанные новой (формат записи
  ключа заявки).

## Решения владельца до подачи

1. ID для Firefox: сейчас `ncabrowser@local.invalid`. ID постоянен после первой загрузки в AMO — выбрать свой
   (например `tegin@esl.kz`) до подачи; это меняет ID и хранилище для временно установленных копий.
2. `http://localhost/*` и `http://127.0.0.1/*` в магазинной сборке: оставить (локальные страницы интеграторов,
   нужно обоснование) или собирать магазинный вариант без них (тесты используют локальный сайт; потребуется
   отдельный профиль сборки).
3. Ответы о данных: серийный номер сертификата в OCSP НУЦ (см. выше), значение `data_collection_permissions`.
4. Версия первой магазинной сборки и коммит, из которого она собирается.
5. AMO: публичный листинг или только подпись для распространения с сайта (unlisted).
6. Аккаунты разработчика: Chrome Web Store (разовый взнос), Microsoft Partner Center, addons.mozilla.org.
