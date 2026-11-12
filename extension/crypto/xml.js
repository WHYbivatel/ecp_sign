import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import xpath from 'xpath';
import { ExclusiveCanonicalization } from 'xml-crypto/lib/exclusive-canonicalization.js';
import { C14nCanonicalization, C14nCanonicalizationWithComments } from 'xml-crypto/lib/c14n-canonicalization.js';
import { findAncestorNsForElement } from 'xml-crypto/lib/utils.js';
import { verifySignedBytes } from './verification.js';
import { O, utf8, base64, unbase64 } from './encoding.js';

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const EXC_COMMENTS = `${EXC}WithComments`;
const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
const C14N_COMMENTS = `${C14N}#WithComments`;
const ENVELOPED = `${DS}enveloped-signature`;
const SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';
const CANONICAL = [C14N, C14N_COMMENTS, EXC, EXC_COMMENTS];
export const MAX_XPATH_LENGTH = 512;
const algorithms = {
  [O.rsa]: ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', 'http://www.w3.org/2001/04/xmlenc#sha256'],
  [O.gost512]: ['urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512', 'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512'],
  [O.gost2004]: ['http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311', 'http://www.w3.org/2001/04/xmldsig-more#gost34311']
};

export function parseXml(xml) {
  if (typeof xml !== 'string' || !xml.trim() || xml.length > 2 * 1024 * 1024) throw new Error('XML пуст или превышает 2 МБ.');
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error('XML с DTD или объявлениями сущностей не поддерживается.');
  const doc = new DOMParser({ onError(level, message) { throw new Error(`Некорректный XML: ${message}`); } }).parseFromString(xml, 'application/xml');
  if (!doc.documentElement) throw new Error('В XML отсутствует корневой элемент.');
  let count = 0;
  function visit(node, depth = 0) {
    if (++count > 50000 || depth > 64) throw new Error('Слишком сложный XML.');
    for (let child = node.firstChild; child; child = child.nextSibling) visit(child, depth + 1);
  }
  visit(doc);
  return doc;
}

const elements = (node, name) => [...node.childNodes].filter(child => child.nodeType === 1 && child.namespaceURI === DS && child.localName === name);
const isInside = (node, ancestor) => { for (let current = node; current; current = current.parentNode) if (current === ancestor) return true; return false; };

// Same-document references by bare name and URI="" exclude comments (XMLDSig 1.0, 4.3.3.3), so a
// "#WithComments" transform after them canonicalizes without comments, as Santuario does.
function canonicalize(algorithm, node, { comments = false, prefixes = [] } = {}) {
  if (algorithm === EXC || algorithm === EXC_COMMENTS) {
    const canon = new ExclusiveCanonicalization();
    canon.includeComments = comments && algorithm === EXC_COMMENTS;
    return canon.process(node, { inclusiveNamespacesPrefixList: prefixes });
  }
  const Canon = comments && algorithm === C14N_COMMENTS ? C14nCanonicalizationWithComments : C14nCanonicalization;
  return new Canon().process(node, { ancestorNamespaces: node.nodeType === 1 ? findAncestorNsForElement(node) : [] });
}

// Elements carrying the identifier under any of the names verifiers resolve (Id, ID, id).
function byId(doc, id) {
  return [...doc.getElementsByTagName('*')].filter(element => ['Id', 'ID', 'id'].some(name => element.getAttributeNode(name)?.value === id));
}

const keep = message => new Error(`В XML уже есть подпись, сохранность которой Tegin не может проверить: ${message}. Новая подпись не создана.`);

// Canonical bytes every earlier signature depends on: its SignedInfo and the data of each Reference.
// If they are equal before and after the new signature is added, every earlier signature keeps its status.
function covered(doc, signatures) {
  return signatures.map(signature => {
    const [signedInfo, ...extra] = elements(signature, 'SignedInfo');
    const [method] = signedInfo ? elements(signedInfo, 'CanonicalizationMethod') : [];
    if (!signedInfo || extra.length || !CANONICAL.includes(method?.getAttribute('Algorithm'))) throw keep('неизвестная каноникализация');
    const parts = [canonicalize(method.getAttribute('Algorithm'), signedInfo, { comments: true })];
    const references = elements(signedInfo, 'Reference');
    if (!references.length) throw keep('нет ссылок на данные');
    for (const reference of references) {
      if (!reference.hasAttribute('URI')) throw keep('ссылка без URI');
      const uri = reference.getAttribute('URI');
      const transforms = elements(reference, 'Transforms').flatMap(node => elements(node, 'Transform'));
      let algorithm = C14N, prefixes = [], enveloped = false;
      for (const transform of transforms) {
        const name = transform.getAttribute('Algorithm');
        const children = [...transform.childNodes].filter(child => child.nodeType === 1);
        if (name === ENVELOPED && !children.length) { enveloped = true; continue; }
        if (!CANONICAL.includes(name) || children.some(child => child.namespaceURI !== EXC || child.localName !== 'InclusiveNamespaces')) throw keep(`преобразование ${name || 'без имени'}`);
        algorithm = name;
        prefixes = children.flatMap(child => (child.getAttribute('PrefixList') || '').split(/\s+/).filter(Boolean));
      }
      let target = doc;
      if (uri !== '') {
        const found = /^#[A-Za-z_][\w.-]*$/.test(uri) ? byId(doc, uri.slice(1)) : [];
        if (found.length !== 1) throw keep(`ссылка ${uri.slice(0, 80)} не указывает ровно на один элемент`);
        target = found[0];
      }
      const parent = signature.parentNode, next = signature.nextSibling;
      if (enveloped && isInside(signature, target)) parent.removeChild(signature);
      try { parts.push(canonicalize(algorithm, target, { prefixes })); }
      finally { if (!signature.parentNode) parent.insertBefore(signature, next); }
    }
    return parts;
  }).flat();
}

// Prefixes resolve as in knca_provider_util 0.8.8 (XMLUtil.PkiNamespaceContext): SOAP-ENV is the SOAP
// envelope, every other prefix is XMLDSig; names without a prefix match elements without a namespace.
const namespaces = prefix => prefix === 'SOAP-ENV' ? SOAP : DS;
function selectOne(doc, expression, label) {
  if (typeof expression !== 'string' || expression.length > MAX_XPATH_LENGTH) throw new Error(`XPath ${label} длиннее ${MAX_XPATH_LENGTH} символов.`);
  let nodes;
  try { nodes = xpath.parse(expression).select({ node: doc, namespaces }); }
  catch { throw new Error(`Некорректное выражение XPath ${label}: ${expression}`); }
  const found = Array.isArray(nodes) ? nodes.length : 0;
  // NCALayer takes the first match; a second match would make it unclear which element is signed.
  if (found !== 1 || nodes[0].nodeType !== 1) throw new Error(`XPath ${label} (${expression}) должен указывать ровно на один элемент, найдено: ${found}${found === 1 ? ', и это не элемент' : ''}.`);
  return nodes[0];
}

export function locateTarget(doc, tbsXPath, parentXPath) {
  const element = selectOne(doc, tbsXPath, 'подписываемого элемента');
  const id = element.getAttributeNode('Id')?.value;
  if (!id) throw new Error('Указанный для подписи элемент не содержит атрибут Id.');
  if (!/^[A-Za-z_][\w.-]*$/.test(id)) throw new Error('Атрибут Id подписываемого элемента содержит недопустимые символы.');
  if (byId(doc, id).length !== 1) throw new Error(`Идентификатор ${id} встречается в XML несколько раз: неясно, какой элемент подписывается.`);
  if (!parentXPath) throw new Error('Не указан элемент, в который помещается подпись (signatureParentElementXPath).');
  const parent = selectOne(doc, parentXPath, 'элемента для подписи');
  if (isInside(parent, element)) throw new Error('Подпись нельзя поместить внутрь подписываемого элемента: она нарушила бы саму себя.');
  return { element, parent, id };
}

// Common Utils 0.3.4 profile (knca_provider_util 0.8.8 XMLUtil.createXmlSignature):
// - whole document: Reference URI="", enveloped-signature, signature appended to the root;
// - tbsElementXPath: Reference URI="#Id" with C14N#WithComments, signature appended to the element
//   found by signatureParentElementXPath. SignedInfo uses exclusive C14N in both cases.
// A document that already holds signatures is signed only if the data they cover stays byte-identical.
export async function signXml(signer, xml, { tbsXPath = '', parentXPath = '' } = {}) {
  if (!algorithms[signer.info.keyOid]) throw new Error('XMLDSig для ГОСТ-256 не подтверждён официальным Kalkan. Используйте CMS/CAdES или другой сертификат.');
  const doc = parseXml(xml);
  const earlier = [...doc.getElementsByTagNameNS(DS, 'Signature')];
  const before = covered(doc, earlier);
  const target = tbsXPath ? locateTarget(doc, tbsXPath, parentXPath) : null;
  const [signatureAlgorithm, digestAlgorithm] = algorithms[signer.info.keyOid];
  const digest = base64(await signer.digest(utf8(target ? canonicalize(C14N, target.element) : canonicalize(EXC, doc))));
  const element = (name, attributes = {}, text) => {
    const node = doc.createElementNS(DS, `ds:${name}`);
    for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
    if (text !== undefined) node.appendChild(doc.createTextNode(text));
    return node;
  };
  const signature = element('Signature');
  signature.setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', DS);
  const signedInfo = element('SignedInfo');
  signedInfo.appendChild(element('CanonicalizationMethod', { Algorithm: EXC }));
  signedInfo.appendChild(element('SignatureMethod', { Algorithm: signatureAlgorithm }));
  const reference = element('Reference', { URI: target ? `#${target.id}` : '' });
  const transforms = element('Transforms');
  for (const algorithm of target ? [C14N_COMMENTS] : [ENVELOPED, EXC]) transforms.appendChild(element('Transform', { Algorithm: algorithm }));
  reference.appendChild(transforms);
  reference.appendChild(element('DigestMethod', { Algorithm: digestAlgorithm }));
  reference.appendChild(element('DigestValue', {}, digest));
  signedInfo.appendChild(reference);
  signature.appendChild(signedInfo);
  (target ? target.parent : doc.documentElement).appendChild(signature);
  const after = covered(doc, earlier);
  if (before.length !== after.length || before.some((value, index) => value !== after[index])) {
    throw new Error(`Новая подпись изменила бы данные, уже подписанные в этом XML, и нарушила бы прежнюю подпись. Подпись не создана.${target ? '' : ' Документ с подписью целиком можно доподписать только по элементу (XPath), если сайт это поддерживает.'}`);
  }
  signature.appendChild(element('SignatureValue', {}, base64(await signer.sign(utf8(canonicalize(EXC, signedInfo))))));
  const keyInfo = element('KeyInfo');
  const x509 = element('X509Data');
  x509.appendChild(element('X509Certificate', {}, signer.info.summary.certificate));
  keyInfo.appendChild(x509);
  signature.appendChild(keyInfo);
  return new XMLSerializer().serializeToString(doc);
}

// Self-check of our exact profile before a protocol promises a result. Re-parses the output: the new
// signature is the last child of its parent, earlier signatures cover the same bytes as in the input.
// This is not a general-purpose XML verifier.
export async function verifyCreatedXml(signer, xml, { original, tbsXPath = '', parentXPath = '' } = {}) {
  try {
    const doc = parseXml(xml);
    if (!algorithms[signer.info.keyOid]) return false;
    const target = tbsXPath ? locateTarget(doc, tbsXPath, parentXPath) : null;
    const signature = (target ? target.parent : doc.documentElement).lastChild;
    if (signature?.nodeType !== 1 || signature.namespaceURI !== DS || signature.localName !== 'Signature') return false;
    const all = [...doc.getElementsByTagNameNS(DS, 'Signature')];
    const earlier = all.filter(node => node !== signature);
    if (all.some(node => node !== signature && isInside(node, signature))) return false;
    if (original !== undefined) {
      const source = parseXml(original);
      const was = covered(source, [...source.getElementsByTagNameNS(DS, 'Signature')]), now = covered(doc, earlier);
      if (was.length !== now.length || was.some((value, index) => value !== now[index])) return false;
    } else if (earlier.length) return false;
    const single = (parent, name) => { const nodes = elements(parent, name); if (nodes.length !== 1) throw new Error('Ambiguous generated XML'); return nodes[0]; };
    const signedInfo = single(signature, 'SignedInfo');
    const reference = single(signedInfo, 'Reference');
    const [sigAlgorithm, hashAlgorithm] = algorithms[signer.info.keyOid];
    const certificate = single(single(single(signature, 'KeyInfo'), 'X509Data'), 'X509Certificate');
    if (single(signedInfo, 'CanonicalizationMethod').getAttribute('Algorithm') !== EXC || single(signedInfo, 'SignatureMethod').getAttribute('Algorithm') !== sigAlgorithm ||
      reference.getAttribute('URI') !== (target ? `#${target.id}` : '') || single(reference, 'DigestMethod').getAttribute('Algorithm') !== hashAlgorithm ||
      certificate.textContent !== signer.info.summary.certificate) return false;
    const transforms = elements(single(reference, 'Transforms'), 'Transform').map(node => node.getAttribute('Algorithm'));
    if (transforms.join(' ') !== (target ? [C14N_COMMENTS] : [ENVELOPED, EXC]).join(' ')) return false;
    const infoBytes = utf8(canonicalize(EXC, signedInfo));
    const value = unbase64(single(signature, 'SignatureValue').textContent);
    const expected = single(reference, 'DigestValue').textContent;
    let data;
    if (target) data = canonicalize(C14N, target.element);
    else { signature.parentNode.removeChild(signature); data = canonicalize(EXC, doc); }
    if (base64(await signer.digest(utf8(data))) !== expected) return false;
    return await verifySignedBytes(signer.info, infoBytes, value, signer.info.algorithm.signature, signer.info.algorithm.hash);
  } catch { return false; }
}
