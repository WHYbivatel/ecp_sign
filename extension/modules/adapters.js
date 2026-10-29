import { COMMON, findModule } from './registry.js';
const fail = message => { throw new Error(message); };
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const text = value => typeof value === 'string' && value.length > 0;
function documents(value, multiple = false) {
  const list = multiple ? value : [value];
  if (!Array.isArray(list) || !list.length || list.length > 10 || list.some(value => !text(value))) fail('Нужны данные от 1 до 10 документов.');
  return list;
}
function fields(input, allowed) {
  if (Object.keys(input).some(key => !allowed.includes(key))) fail('Этот параметр модуля пока не поддерживается. Запрос не изменён и не подписан.');
}
function purpose(value) {
  if (!['AUTH', 'SIGN', 'AUTHENTICATION', 'SIGNATURE'].includes(value)) fail('Неизвестное назначение ключа.');
  return { extKeyUsageOids: [['AUTH', 'AUTHENTICATION'].includes(value) ? '1.3.6.1.5.5.7.3.2' : '1.3.6.1.5.5.7.3.4'] };
}
export function adaptRequest(input) {
  const module = findModule(input.module);
  if (!module || ['common', 'basics'].includes(module.id)) return null;
  const base = { moduleId: module.id, operation: 'sign', decode: false, multiple: false };
  if (module.id === 'goszakup') {
    fields(input, ['module', 'type', 'data', 'source', 'needHash']);
    if (input.type === 'version') return { ...base, immediate: true, value: { version: '1.0.0' } };
    if (input.source !== undefined && input.source !== 'local') fail('Госзакупки: передайте данные в запросе. Скачивание документов по ссылке не реализовано.');
    if (input.needHash !== undefined && input.needHash !== '') fail('Госзакупки: ответ needHash пока не реализован.');
    if (['xml', 'multixml'].includes(input.type)) return { ...base, format: 'xml', documents: documents(input.data, input.type === 'multixml'), multiple: input.type === 'multixml' };
    if (input.type === 'binary') return { ...base, format: 'cms', documents: documents(input.data), decode: true, encapsulate: false, cades: true };
    if (input.type === 'text') return { ...base, format: 'cms', documents: documents(input.data), encapsulate: false, cades: true, timestamp: true };
    if (input.type === 'multitext') {
      if (!object(input.data)) fail('Госзакупки: нужен объект документов.');
      const keys = Object.keys(input.data);
      if (keys.some(key => key.length > 200)) fail('Слишком длинный идентификатор документа.');
      return { ...base, format: 'cms', documents: documents(Object.values(input.data), true), resultKeys: keys, multiple: true, encapsulate: false, cades: true, timestamp: true };
    }
    fail('Госзакупки: этот тип операции требует отдельного переноса. Доступны XML и данные в запросе.');
  }
  if (module.id === 'samruk') {
    if (input.method === 'version') { fields(input, ['module', 'method']); return { ...base, immediate: true, value: '1' }; }
    fields(input, ['module', 'method', 'uid', 'chain', 'storageName', 'keyType', 'xml', 'tbsElementXPath', 'signatureParentElementXPath']);
    if (input.method !== 'signXml' || input.storageName !== 'PKCS12' || !text(input.uid) || input.uid.length > 200 || input.tbsElementXPath || input.signatureParentElementXPath) fail('ИСЭЗ: доступна подпись целого XML файловым ключом, без XPath.');
    if (input.chain !== undefined && (typeof input.chain !== 'string' || input.chain.length > 200)) fail('Некорректный идентификатор цепочки операций.');
    return { ...base, format: 'xml', documents: documents(input.xml), signerParams: purpose(input.keyType) };
  }
  if (module.id === 'qiwi') {
    fields(input, ['module', 'method', 'args']);
    if (!Array.isArray(input.args) || !text(input.args[0]) || input.args[0].length > 200) fail('QIWI: нужен идентификатор операции.');
    if (input.method === 'logOut' && input.args.length === 1) return { ...base, immediate: true, value: { callID: input.args[0], logOutResult: true } };
    if (input.method === 'signXml' && input.args.length === 2) return { ...base, format: 'xml', documents: documents(input.args[1]) };
    fail('QIWI: метод или параметры не поддерживаются.');
  }
  fields(input, ['module', 'method', 'args', 'uuid']);
  if (input.uuid !== undefined && (typeof input.uuid !== 'string' || input.uuid.length > 200)) fail('Некорректный идентификатор запроса.');
  const allowed = module.id === 'uchet' ? ['signXml'] : module.id === 'metadoc-info' ? ['getKeyInfo', 'changeLocale'] : ['getActiveTokens', 'getKeyInfo', 'signXml', 'createCMSSignatureFromBase64'];
  if (!allowed.includes(input.method)) fail('Этот метод стороннего модуля ещё не перенесён в Tegin.');
  const arity = { getActiveTokens: 0, getKeyInfo: 1, changeLocale: 1, signXml: 5, createCMSSignatureFromBase64: 4 }[input.method];
  if ((input.args == null ? 0 : Array.isArray(input.args) ? input.args.length : -1) !== arity) fail('Неверное число параметров модуля.');
  if (input.method === 'changeLocale' && !['ru', 'kk', 'en'].includes(input.args[0])) fail('Неизвестный язык интерфейса.');
  return { commonInput: { ...input, module: COMMON }, moduleId: module.id,
    constraints: ['signXml', 'createCMSSignatureFromBase64'].includes(input.method) ? purpose(input.args?.[1]) : undefined };
}
export function assembleResult(normalized, result) {
  if (normalized.basics) return { result: Array.isArray(result) ? result : [result] };
  if (normalized.resultKeys) return { items: Object.fromEntries(normalized.resultKeys.map((key, index) => [key, result[index]])) };
  if (normalized.moduleId === 'qiwi' && !normalized.immediate) return { callID: normalized.callId, signedXml: result[0], verificationResult: true };
  return Array.isArray(result) && !normalized.multiple ? result[0] : result;
}
export function adapterResponse(input, result, message, cancelled = false) {
  const module = findModule(input?.module);
  if (module?.id === 'goszakup') return message !== undefined ? { errorCode: cancelled ? '500' : '400', errorMessage: message } : { errorCode: 'NONE', result };
  if (module?.id === 'samruk') return { code: message !== undefined ? (cancelled ? '500' : '400') : '200', uid: typeof input.uid === 'string' ? input.uid : null, message: message ?? '', responseObject: message !== undefined ? null : result, newChain: null };
  if (module && !['common', 'basics'].includes(module.id)) return { code: message !== undefined ? (cancelled ? '500' : '400') : '200', message: message ?? '', responseObject: message !== undefined ? null : result, ...(typeof input.uuid === 'string' ? { uuid: input.uuid } : {}) };
  return null;
}
