# Подача в Chrome Web Store, Edge Add-ons и Firefox AMO

Подготовка к шагу 8. **Ничего не подано**: публикация в магазинах — отдельное действие владельца. Документ
описывает код ветки `codex/nca-key-issuance`; формулировки для форм магазинов даны по-английски, потому что
ревьюеры читают их на английском.

## Артефакты и их проверка

- Сборка: `npm run verify:package` — `npm run package` (`dist/tegin-chromium-<версия>.zip`,
  `dist/tegin-firefox-<версия>.zip`, исходники для AMO `dist/tegin-source-<версия>.zip`, `dist/checksums.json`),
  затем `scripts/verify-package.mjs --smoke`.
- Архивы воспроизводимы побайтно: имена по порядку, без каталогов, время 1980-01-01, режим 0644; повторная
  упаковка `dist/<target>` даёт те же байты (в пределах одной линии Node — хеш зависит от zlib, в CI Node 22).
  Архив исходников — `git archive` текущего коммита: без `.p12`, `.pfx`, `.env`, `dist/` и `node_modules/`,
  повторный `git archive` даёт те же байты. При незакоммиченных изменениях `package.mjs` предупреждает, что
  исходники не совпадают с собранным.
- Что проверяется в самих архивах: версия манифеста равна `package.json`; все файлы, на которые ссылаются манифест
  и страницы, на месте; нет тестовой сборки, source map, ключей, `.env`, `node_modules`, тестов; CSP `script-src
  'self'`, нет удалённых скриптов; содержимое побайтно равно `dist/<target>`; SHA-256 равен `checksums.json`.
  `--smoke`: архив Chromium распаковывается во временную папку и загружается в Chromium — service worker нужной
  версии запускается, 6 страниц расширения открываются без ошибок скриптов и нарушений CSP.
- Firefox-архив проходит официальный валидатор AMO `addons-linter` 10.15.0: 12.11.2026 — 0 ошибок, 1
  предупреждение (`data_collection_permissions` не поддерживается минимальной версией Firefox для Android; Android
  не заявляется).
- `dist/release.json` связывает архивы с коммитом: версия, полный SHA коммита, признак чистого дерева
  (`extension/`, `scripts/`, `vendor/`, `package*.json` без незакоммиченных изменений), размер и SHA-256 каждого
  архива. `verify-package.mjs --release` требует чистое дерево и совпадение с `HEAD` и файлами.
- CI (задача `package`) выполняет то же (`--smoke --release`) и выкладывает архивы (включая исходники и
  `release.json`) артефактом `tegin-packages-<sha>` на 14 дней. Подавать в магазин нужно архив, прошедший эти
  проверки, а не пересобранный вручную.
- Сайт: `node website/scripts/check-releases.mjs --release dist/release.json --chromium-zip <файл> --firefox-zip <файл>`
  сверяет `releases.json` и ссылки `index.html` с архивами и коммитом сборки.

### Кандидат 0.6.0

| Архив | Имя на сайте | Байт | SHA-256 |
|---|---|---|---|
| `tegin-chromium-0.6.0.zip` | `tegin-chromium-0.6.0-5b3eae2.zip` | 508 818 | `9a773c63d5788efa40ba1b6753263f1a398cdab119f62c7ccf83974ce263f653` |
| `tegin-firefox-0.6.0.zip` | `tegin-firefox-0.6.0-5b3eae2.zip` | 508 895 | `96a15d8f6c781391b9080c2efb756d82bc047d03931d7d685c157dc22adff735` |
| `tegin-source-0.6.0.zip` | (для AMO) | 746 075 | `c48bc22c506451fe89163f753f2c44a720a920e9f06c15c771feb0b5125a3a3c` |

Собраны из `5b3eae2` (`release.json`: `clean: true`, Node 22.23.4); повторная сборка `npm run package` даёт те же
байты. Коммиты после `5b3eae2`, меняющие только `website/`, `docs/` и тесты, архивы не меняют. Если до выкладки
изменится код расширения, кандидат пересобирается и `releases.json`, `index.html` и эта таблица обновляются.

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
приложить `dist/tegin-source-<версия>.zip` (собирается `npm run package`) и инструкцию сборки (Node 22,
`npm ci`, `npm run build`, результат — `dist/firefox`; сборка воспроизводится побайтно, `tests/build-paths.test.js`
и раздел «Сверка ветки» в журнале работ).

## Данные (Chrome «Privacy practices», Edge, AMO)

Основа — [privacy-policy.md](privacy-policy.md); страница сайта `website/privacy.html` (выходит с 0.6.0, URL для
форм: `https://tegin.esl.kz/privacy.html`). Магазины требуют контакт разработчика: на сайте его пока нет.

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

Проверено E2E на кандидате 0.6.0 (`tests/e2e-update.mjs` в Chromium, Chrome и Edge; `tests/e2e-update-firefox.mjs`
в Firefox; оба в CI, задача `issuance-browsers`, шаг «Update from the published build»). Тест сначала сверяет, что
опубликованный архив побайтно равен сборке своего коммита (`dd40b5e`), и работает с ним, а не с пересборкой.

| Переход | Что сохраняется | Что делает пользователь |
|---|---|---|
| Chromium `dd40b5e` → 0.6.0, та же папка | ID, настройки модулей (разрешённые сайты, политика меток), ключи заявок `dd40b5e` (поле `holder` удаляется при показе), их установка и резервная копия | Заменить файлы в папке и нажать «Обновить» |
| Firefox 0.5.2 → 0.6.0, тот же профиль | Весь `storage.local` без изменений, разрешение подключённого сайта и его скрипты, адаптер на странице | Загрузить временное дополнение заново |
| 0.6.0 → магазинная сборка или другая папка (другой ID) | Ключи заявок из резервных копий `dd40b5e` и 0.6.0: восстановление и установка сертификата проходят | Скачать резервные копии до перехода; настройки и подключённые сайты задать заново |

Найденный дефект, исправлен в `5b3eae2`: Chromium при каждой перезагрузке распакованного расширения, а Firefox при
переустановке временного дополнения удаляют зарегистрированные скрипты подключённых сайтов. Разрешение оставалось,
а адаптер на странице пропадал. Теперь фон пересоздаёт скрипты из выданных разрешений при установке, обновлении,
запуске браузера и выдаче разрешения (`extension/lib/connected-sites.js`, `tests/connected-sites.test.js`); проверка
с отключённым исправлением падает.

Ограничение автоматизации: в Chromium выдачу необязательного разрешения нельзя подтвердить без пользователя, поэтому
сохранение подключённого сайта при обновлении проверено в Firefox, а в Chromium проверено пересоздание скриптов.

- Ключ заявки НУЦ, ещё не дождавшийся сертификата, переносится на другой ID только файлом `.tegin-request.json`;
  восстановление — в окне установки сертификата. Копию предлагают скачать сразу после создания заявки, а для каждой
  незавершённой заявки — в разделе «Ключи заявок». Другой путь — установить сертификат до перехода (получится `.p12`).
- Две копии одновременно: страница видит «Конфликт версий» (проверка уже есть), пользователь удаляет старую.
- Обновления из магазинов приходят автоматически. Версия манифеста растёт: первая магазинная версия не ниже 0.6.0.

## Откат

| Откат | Результат |
|---|---|
| Chromium 0.6.0 → `dd40b5e` в той же папке | Настройки и их применение сохраняются; ключ заявки, созданный в 0.6.0, устанавливается старой версией |
| Firefox 0.6.0 → 0.5.2 → 0.6.0 | `storage.local` не меняется, включая зашифрованный ключ заявки; настройки применяются. 0.5.2 не пересоздаёт скрипты подключённого сайта: один раз нажать «Обновить» в окне расширения. После возврата на 0.6.0 запись побайтно та же и показана в «Ключах заявок» |

- Сайт: `releases.json` хранит предыдущую сборку для Chromium (`dd40b5e`) и Firefox (0.5.2) в поле `rollback`,
  архивы остаются по своим URL.
- Магазины не принимают версию ниже опубликованной. Откат — повторная подача кода предыдущего коммита с
  повышенной версией (например `0.6.1` с кодом `0.6.0`); Firefox AMO позволяет отключить проблемную версию, и
  пользователи получат предыдущую подписанную.

## Решения владельца до подачи

Рекомендации подготовлены; решение и действия в аккаунтах остаются за владельцем.

1. **ID для Firefox.** Сейчас `ncabrowser@local.invalid`; после первой загрузки в AMO ID не меняется.
   Рекомендация: `tegin@esl.kz` только для сборки AMO. Архив на сайте сохраняет прежний ID, иначе у текущих
   пользователей пропадут настройки и ключи заявок. Переход на подписанную сборку — как на любой другой ID, через
   резервную копию (проверено). Нужен профиль сборки `firefox-amo`, который меняет только ID; это отдельный коммит
   после решения.
2. **`localhost` и `127.0.0.1` в магазинной сборке.** Рекомендация: оставить. Это только локальная машина
   пользователя, данных наружу не добавляет, а интеграторы проверяют на локальных страницах. Обоснование для
   формы: «Loopback only: lets developers test their NCALayer integration on a local page before deploying it; no
   remote host is reached through these patterns.» Вариант без них потребует отдельного профиля сборки и перевода
   E2E на адреса `.kz`.
3. **Ответы о данных.** Серийный номер сертификата уходит в OCSP НУЦ, а НУЦ, выдавший сертификат, по нему знает
   владельца. Рекомендация — раскрывать, а не отвечать «ничего»: Chrome — «Personally identifiable information»
   с пояснением «certificate serial number sent to the national certificate authority's OCSP service to check
   revocation; never to the developer»; Firefox — `data_collection_permissions.required: ['personallyIdentifyingInfo']`
   вместо `['none']`. Согласовать с юристом (записка `legal-review-notes.md`), манифест менять отдельным коммитом.
4. **Версия и коммит.** Chrome Web Store и Edge: тот же архив `tegin-chromium-0.6.0.zip` из `5b3eae2`, что и на
   сайте. AMO: сборка с выбранным ID из коммита, где появится профиль `firefox-amo`, версия 0.6.0 или выше, с
   архивом исходников того же коммита.
5. **Тип публикации AMO.** Рекомендация: сначала unlisted (подпись для распространения с сайта). Подписанный XPI
   устанавливается постоянно, без перезагрузки после каждого запуска, а листинг не обещает работу на порталах,
   пока она не подтверждена. Публичный листинг — после приёмки на порталах.
6. **Аккаунты разработчика**: Chrome Web Store (разовый взнос), Microsoft Partner Center, addons.mozilla.org.

## Действия, которые требуют владельца

| Действие | Что нужно |
|---|---|
| Выкладка сайта с 0.6.0 | Разрешение на выкладку. Скопировать архивы под именами с коммитом в `public/downloads/`, поставить `publishedAt` на дату выкладки, выполнить `check-releases.mjs` с `--release`, `--chromium-zip`, `--firefox-zip`, затем синхронизировать `website/` (включая `legal.html`, `privacy.html`) |
| Контакт и оператор сайта | Указать на `privacy.html` и `legal.html`, кто управляет сайтом, и адрес для обращений; магазины требуют контакт |
| Решения 1–5 выше | Ответ владельца; по пунктам 3 и 1 затем отдельный коммит |
| Аккаунты и подача | Регистрация, оплата, загрузка архивов, ответы на вопросы ревью |
