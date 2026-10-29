import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { ExclusiveCanonicalization } from 'xml-crypto/lib/exclusive-canonicalization.js';
import { verifySignedBytes } from './verification.js';
import { O, utf8, base64, unbase64 } from './encoding.js';

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED = `${DS}enveloped-signature`;
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

export async function signXml(signer, xml) {
  if (!algorithms[signer.info.keyOid]) throw new Error('XMLDSig для ГОСТ-256 не подтверждён официальным Kalkan. Используйте CMS/CAdES или другой сертификат.');
  const doc = parseXml(xml);
  if (doc.getElementsByTagNameNS(DS, 'Signature').length) throw new Error('Доподписание XML с существующей подписью пока не поддерживается.');
  const [signatureAlgorithm, digestAlgorithm] = algorithms[signer.info.keyOid];
  const canon = new ExclusiveCanonicalization();
  const digest = base64(await signer.digest(utf8(canon.process(doc))));
  const element = (name, attributes = {}, text) => {
    const node = doc.createElementNS(DS, `ds:${name}`);
    for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
    if (text !== undefined) node.appendChild(doc.createTextNode(text));
    return node;
  };
  const signature = element('Signature');
  signature.setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', DS);
  const signedInfo = element('SignedInfo');
  signedInfo.appendChild(element('CanonicalizationMethod', { Algorithm: C14N }));
  signedInfo.appendChild(element('SignatureMethod', { Algorithm: signatureAlgorithm }));
  const reference = element('Reference', { URI: '' });
  const transforms = element('Transforms');
  transforms.appendChild(element('Transform', { Algorithm: ENVELOPED }));
  transforms.appendChild(element('Transform', { Algorithm: C14N }));
  reference.appendChild(transforms);
  reference.appendChild(element('DigestMethod', { Algorithm: digestAlgorithm }));
  reference.appendChild(element('DigestValue', {}, digest));
  signedInfo.appendChild(reference);
  signature.appendChild(signedInfo);
  doc.documentElement.appendChild(signature);
  signature.appendChild(element('SignatureValue', {}, base64(await signer.sign(utf8(canon.process(signedInfo))))));
  const keyInfo = element('KeyInfo');
  const x509 = element('X509Data');
  x509.appendChild(element('X509Certificate', {}, signer.info.summary.certificate));
  keyInfo.appendChild(x509);
  signature.appendChild(keyInfo);
  return new XMLSerializer().serializeToString(doc);
}

// Self-check of our exact, whole-document profile before a protocol promises
// verificationResult=true. This is not a general-purpose XML verifier.
export async function verifyCreatedXml(signer, xml) {
  try {
    const doc = parseXml(xml), canon = new ExclusiveCanonicalization();
    const signatures = doc.getElementsByTagNameNS(DS, 'Signature');
    if (signatures.length !== 1 || !algorithms[signer.info.keyOid]) return false;
    const signature = signatures[0];
    const single = name => { const nodes = signature.getElementsByTagNameNS(DS, name); if (nodes.length !== 1) throw new Error('Ambiguous generated XML'); return nodes[0]; };
    const signedInfo = single('SignedInfo');
    const [sigAlgorithm, hashAlgorithm] = algorithms[signer.info.keyOid];
    if (single('CanonicalizationMethod').getAttribute('Algorithm') !== C14N || single('SignatureMethod').getAttribute('Algorithm') !== sigAlgorithm ||
      single('Reference').getAttribute('URI') !== '' || single('DigestMethod').getAttribute('Algorithm') !== hashAlgorithm ||
      single('X509Certificate').textContent !== signer.info.summary.certificate) return false;
    const transforms = signature.getElementsByTagNameNS(DS, 'Transform');
    if (transforms.length !== 2 || transforms[0].getAttribute('Algorithm') !== ENVELOPED || transforms[1].getAttribute('Algorithm') !== C14N) return false;
    const infoBytes = utf8(canon.process(signedInfo));
    const value = unbase64(single('SignatureValue').textContent);
    const expected = single('DigestValue').textContent;
    signature.parentNode.removeChild(signature);
    if (base64(await signer.digest(utf8(canon.process(doc)))) !== expected) return false;
    return await verifySignedBytes(signer.info, infoBytes, value, signer.info.algorithm.signature, signer.info.algorithm.hash);
  } catch { return false; }
}
