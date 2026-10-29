import { adaptRequest, adapterResponse } from '../modules/adapters.js';
const COMMON = 'kz.gov.pki.knca.commonUtils';
const BASICS = 'kz.gov.pki.knca.basics';
export const MAX_MESSAGE_LENGTH = 3 * 1024 * 1024;
const unsupported = message => { throw new Error(message || 'Этот метод NCALayer пока не поддерживается.'); };
function signerConstraints(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['extKeyUsageOids', 'iin', 'bin', 'serialNumber', 'chain'].includes(key))) unsupported('Условия выбора сертификата не поддерживаются.');
  if (value.extKeyUsageOids !== undefined && (!Array.isArray(value.extKeyUsageOids) || value.extKeyUsageOids.length > 24 || value.extKeyUsageOids.some(id => typeof id !== 'string' || !/^\d+(\.\d+)+$/.test(id)))) unsupported('Некорректное назначение сертификата.');
  for (const field of ['iin', 'bin']) if (value[field] !== undefined && (typeof value[field] !== 'string' || !/^\d{12}$/.test(value[field]))) unsupported('Некорректный ИИН или БИН.');
  if (value.serialNumber !== undefined && (typeof value.serialNumber !== 'string' || !/^[0-9a-f]{1,128}$/i.test(value.serialNumber))) unsupported('Некорректный серийный номер.');
  if (value.chain !== undefined && (!Array.isArray(value.chain) || value.chain.length > 24 || value.chain.some(cert => typeof cert !== 'string' || cert.length > 16384 || !cert.includes('-----BEGIN CERTIFICATE-----')))) unsupported('Некорректная цепочка сертификатов.');
  return structuredClone(value);
}

export function normalizeRequest(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) unsupported('Некорректный запрос.');
  if (JSON.stringify(input).length > MAX_MESSAGE_LENGTH) unsupported('Запрос превышает допустимый размер.');
  const adapted = adaptRequest(input);
  if (adapted) {
    if (adapted.commonInput) return { ...normalizeRequest(adapted.commonInput), moduleId: adapted.moduleId, ...(adapted.constraints ? { signerParams: adapted.constraints } : {}) };
    if (adapted.moduleId === 'qiwi') adapted.callId = input.args[0];
    return adapted;
  }
  const { module, method, args } = input;
  if (module === COMMON) {
    if (method === 'getActiveTokens') return { immediate: true, value: [] };
    if (method === 'changeLocale') return { immediate: true, value: true };
    if (!Array.isArray(args) || args[0] !== 'PKCS12') unsupported('Поддерживаются только файловые ключи PKCS#12.');
    if (method === 'getKeyInfo') return { operation: 'info', documents: [], format: 'info' };
    if (method === 'signXml' || method === 'signXmls') {
      const documents = method === 'signXmls' ? args[2] : [args[2]];
      if (!Array.isArray(documents) || !documents.length || documents.length > 10 || documents.some(doc => typeof doc !== 'string') || args[3] || args[4]) unsupported('Поддерживается подпись целого XML без XPath, до 10 документов.');
      return { operation: 'sign', format: 'xml', documents, decode: false, multiple: method === 'signXmls' };
    }
    if (['createCMSSignatureFromBase64', 'createCAdESFromBase64', 'createCAdESFromBase64Hash'].includes(method)) {
      const digested = method === 'createCAdESFromBase64Hash';
      if (typeof args[2] !== 'string' || (!digested && typeof args[3] !== 'boolean')) unsupported('Некорректные параметры CMS.');
      return { operation: 'sign', format: 'cms', documents: [args[2]], decode: true, encapsulate: digested ? false : args[3], digested,
        timestamp: method === 'createCMSSignatureFromBase64', cades: true };
    }
    unsupported();
  }
  if (module === BASICS && method === 'sign') {
    if (!args || typeof args !== 'object' || Array.isArray(args)) unsupported('Некорректные параметры подписания.');
    if (args.allowedStorages != null && (!Array.isArray(args.allowedStorages) || !args.allowedStorages.includes('PKCS12'))) unsupported('Сайт не разрешает файловые ключи PKCS#12.');
    const params = args.signingParams || {};
    if (typeof params !== 'object' || Array.isArray(params)) unsupported('Некорректные параметры подписи.');
    const timestamp = params.tsaProfile != null;
    if (timestamp && (typeof params.tsaProfile !== 'object' || Array.isArray(params.tsaProfile) || Object.keys(params.tsaProfile).length)) unsupported('Поддерживается стандартный профиль метки времени НУЦ: tsaProfile={}.');
    if (timestamp && args.format !== 'cms') unsupported('Метка времени поддерживается для CMS/CAdES.');
    for (const field of ['decode', 'encapsulate', 'digested']) if (params[field] !== undefined && typeof params[field] !== 'boolean') unsupported('Параметры подписи должны быть логическими значениями.');
    if (params.digested && args.format === 'xml') unsupported('XML нельзя подписать по готовому хешу.');
    if (params.digested && params.encapsulate !== false && args.format === 'cms') unsupported('Для готового хеша нужна отдельная подпись: encapsulate=false.');
    const allowedParams = new Set(['decode', 'encapsulate', 'digested', 'tsaProfile']);
    if (Object.keys(params).some(key => !allowedParams.has(key))) unsupported('Неизвестные параметры подписи.');
    if (!['cms', 'xml', 'raw'].includes(args.format)) unsupported('Поддерживаются CMS, XML и raw.');
    const signerParams = signerConstraints(args.signerParams);
    const documents = Array.isArray(args.data) ? args.data : [args.data];
    if (!documents.length || documents.length > 10 || documents.some(value => typeof value !== 'string' || !value)) unsupported('Некорректные данные подписания.');
    return { operation: 'sign', format: args.format, documents, decode: Boolean(params.decode), digested: Boolean(params.digested), encapsulate: params.encapsulate !== false, timestamp,
      signerParams, trustRequired: signerParams.chain === undefined || signerParams.chain.length > 0, basics: true };
  }
  unsupported();
}

export function successResponse(input, result) {
  return adapterResponse(input, result) || (input.module === BASICS ? { status: true, body: result } : { code: '200', message: '', responseObject: result });
}
export function errorResponse(input, message, cancelled = false) {
  return adapterResponse(input, undefined, message, cancelled) || (input?.module === BASICS
    ? (cancelled ? { status: true, body: {} } : { status: false, code: 'UNSUPPORTED_OR_FAILED', message })
    : { code: cancelled ? '500' : '400', message, responseObject: null });
}
