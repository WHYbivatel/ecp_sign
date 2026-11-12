// Goszakup NURSign `type: "xml"` against the official code it delegates to. NURSign 5.1.2
// (kz.ecc.NurSignBundle, pinned with SHA-256 in the signed NCA module catalog) signs XML with
// knca_provider_util XMLUtil.createXmlSignature(SigningEntity, xml, provider), i.e. a whole-document
// signature with no XPath. This script signs the same synthetic document with that official call and
// through Tegin's NURSign adapter, compares the XMLDSig profile (canonicalization differs by design), has the official
// XMLUtil.verifyXmlSignature check Tegin's output and rejects a changed copy. A second part checks Common Utils
// XPath signing and mixed RSA/GOST-512 co-signing with the same official verifier.
// NCA_BUNDLES: folder with kalkancrypt-0.7.8.jar, kalkancrypt_xmldsig-osgi-0.4.jar and
// knca_provider_util-0.8.8.jar from ncalayer.zip; NCA_CORE: core classes (slf4j). NCA_NURSIGN_JAR (optional): the module JAR, checked
// against the catalog hash and for the createXmlSignature call. Synthetic keys created by Kalkan.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, delimiter } from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { DOMParser } from '@xmldom/xmldom';
import { normalizeRequest, successResponse } from '../extension/signing/protocol.js';
import { signXml } from '../extension/crypto/xml.js';
import { openContainer } from '../extension/crypto/signer.js';
import { catalog } from '../extension/modules/catalog.js';
import { assembleResult } from '../extension/modules/adapters.js';

const bundles = process.env.NCA_BUNDLES;
if (!bundles) { console.log('SKIP: set NCA_BUNDLES to the kncabundles folder of ncalayer.zip'); process.exit(0); }
// NCA_CORE: NCALayer core classes extracted from ncalayer.sh (slf4j, org.json), as for tests/ncalayer-password-reference.mjs.
// One jar of each, whatever the version: the archive set (XMLDSig 0.4, util 0.8.8) or the updated one (0.5.2, 0.9.2).
const jar = prefix => {
  const found = readdirSync(bundles).filter(name => name.startsWith(prefix) && name.endsWith('.jar'));
  if (found.length !== 1) throw new Error(`${bundles}: expected one ${prefix}*.jar, found ${found.length}`);
  return join(bundles, found[0]);
};
const jars = [jar('kalkancrypt-'), jar('kalkancrypt_xmldsig'), jar('knca_provider_util')];
console.log(`ENV: ${jars.map(path => path.split(/[\\/]/).pop()).join(', ')}`);
const classpath = [...jars, ...(process.env.NCA_CORE ? [process.env.NCA_CORE] : [])].join(delimiter);
const folder = mkdtempSync(join(tmpdir(), 'tegin-nursign-'));
const PASSWORD = 'Tegin-NurSign-2026';
const DSIG = 'http://www.w3.org/2000/09/xmldsig#';
const ENVELOPED = `${DSIG}enveloped-signature`, C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315', EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
// A rejection must come from the verifier, not from a missing class or file.
const rejected = error => error.status !== 0 && !/NoClassDefFound|ClassNotFound|NoSuchFile|FileNotFound/.test(String(error.stderr));
const java = (args, env = {}) => execFileSync(process.env.NCA_JAVA || 'java', ['-cp', `${classpath}${delimiter}${join(folder, 'classes')}`, ...args],
  { encoding: 'utf8', stdio: 'pipe', env: { ...process.env, TEGIN_TEST_P12_PASSWORD: PASSWORD, ...env } });

// Signature profile: everything a verifier and the portal see except values that depend on the key or time.
function profile(xml, index = 0, count = 1) {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const signatures = doc.getElementsByTagNameNS(DSIG, 'Signature');
  assert.equal(signatures.length, count);
  const signature = signatures[index];
  const one = (parent, name) => parent.getElementsByTagNameNS(DSIG, name)[0];
  const reference = one(signature, 'Reference');
  return {
    parent: signature.parentNode.localName,
    lastChild: signature.parentNode.lastChild === signature || signature.parentNode.lastChild?.nodeType === 3,
    prefix: signature.prefix || '',
    canonicalization: one(signature, 'CanonicalizationMethod').getAttribute('Algorithm'),
    signatureMethod: one(signature, 'SignatureMethod').getAttribute('Algorithm'),
    referenceUri: reference.getAttribute('URI'),
    transforms: [...reference.getElementsByTagNameNS(DSIG, 'Transform')].map(node => node.getAttribute('Algorithm')),
    digestMethod: one(reference, 'DigestMethod').getAttribute('Algorithm'),
    keyInfo: [...one(signature, 'KeyInfo').getElementsByTagNameNS(DSIG, '*')].map(node => node.localName)
  };
}

try {
  if (process.env.NCA_NURSIGN_JAR) {
    const entry = catalog.find(item => item.symname === 'kz.ecc.NurSignBundle');
    assert.equal(createHash('sha256').update(readFileSync(process.env.NCA_NURSIGN_JAR)).digest('hex'), entry.hash, 'NURSign JAR matches the signed NCA catalog');
    const classes = join(folder, 'nursign'); mkdirSync(classes);
    execFileSync('unzip', ['-q', process.env.NCA_NURSIGN_JAR, '-d', classes]);
    const code = execFileSync('javap', ['-c', '-p', '-cp', classes, 'kz.ecc.nursign.services.Signer'], { encoding: 'utf8' });
    const signXmlCode = code.slice(code.indexOf('public org.json.JSONObject signXml('), code.indexOf('public org.json.JSONObject signFile('));
    assert.match(signXmlCode, /XMLUtil\.createXmlSignature:\(Lkz\/gov\/pki\/provider\/utils\/model\/SigningEntity;Ljava\/lang\/String;Ljava\/security\/Provider;\)/);
    assert.match(signXmlCode, /String local/);
    console.log(`PASS: NURSign ${entry.version} JAR matches the catalog SHA-256; type "xml" with source "local" calls XMLUtil.createXmlSignature(SigningEntity, xml, provider)`);
  } else console.log('SKIP: NURSign JAR check (set NCA_NURSIGN_JAR)');

  mkdirSync(join(folder, 'classes'));
  execFileSync(process.env.NCA_JAVAC || 'javac', ['--release', '17', '-cp', classpath, '-d', join(folder, 'classes'), resolve('tests/interop/XmlReference.java'), resolve('tests/interop/Pkcs12Interop.java')], { stdio: 'pipe' });
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<lot xmlns="urn:tegin:synthetic"><number>0000000-ТЕСТ-1</number><title>Синтетическая заявка &amp; лот</title><price currency="KZT">1000.00</price></lot>\n';
  writeFileSync(join(folder, 'document.xml'), xml);
  // What Tegin receives from a Goszakup page for this operation.
  const request = { module: 'NURSign', type: 'xml', data: xml, source: 'local' };
  const normalized = normalizeRequest(request);
  assert.equal(normalized.format, 'xml'); assert.equal(normalized.xpath, undefined); assert.deepEqual(normalized.documents, [xml]);

  for (const family of ['RSA', 'GOST512']) {
    const keyPath = join(folder, `${family}.p12`);
    java(['Pkcs12Interop', 'create', family, 'PKCS12', keyPath]);
    const reference = java(['XmlReference', 'sign', keyPath, PASSWORD, join(folder, 'document.xml'), '-', '-']);
    const signer = await openContainer(new Uint8Array(readFileSync(keyPath)), PASSWORD);
    let tegin;
    try { tegin = await signXml(signer, normalized.documents[0]); } finally { signer.destroy(); }
    const response = successResponse(request, assembleResult(normalized, [tegin]));
    assert.deepEqual(Object.keys(response), ['errorCode', 'result']); assert.equal(response.errorCode, 'NONE'); assert.equal(response.result, tegin);
    for (const [label, signed] of [['official', reference], ['Tegin', tegin]]) {
      writeFileSync(join(folder, `${family}-${label}.xml`), signed);
      assert.match(java(['XmlReference', 'official', join(folder, `${family}-${label}.xml`)]), /OFFICIAL VALID/, `${family} ${label}`);
    }
    writeFileSync(join(folder, `${family}-changed.xml`), tegin.replace('1000.00', '1000.01'));
    assert.throws(() => java(['XmlReference', 'official', join(folder, `${family}-changed.xml`)]), rejected, `${family}: a changed price is rejected`);
    // Documented difference (README, docs/ncalayer-reference.md): for the whole document Tegin uses exclusive C14N
    // for SignedInfo and the reference, XMLUtil inclusive C14N 1.0 (#WithComments for the reference).
    const ours = profile(tegin), theirs = profile(reference);
    assert.equal(theirs.canonicalization, C14N); assert.deepEqual(theirs.transforms, [ENVELOPED, `${C14N}#WithComments`]);
    assert.equal(ours.canonicalization, EXC); assert.deepEqual(ours.transforms, [ENVELOPED, EXC]);
    for (const field of ['canonicalization', 'transforms']) { delete ours[field]; delete theirs[field]; }
    assert.deepEqual(ours, theirs, `${family}: the rest of the XMLDSig profile equals the official whole-document signature`);
    console.log(`PASS: NURSign xml ${family}: Tegin's response {errorCode: NONE, result} carries a whole-document XMLDSig (${ours.signatureMethod.split(/[#:]/).pop()}); method, digest, URI="", placement and KeyInfo equal XMLUtil.createXmlSignature, canonicalization differs as documented (exclusive vs inclusive C14N); the official XMLUtil.verifyXmlSignature accepts both and rejects a changed price`);
  }

  // Common Utils signXml with tbsElementXPath and co-signing: an official RSA signature, then Tegin adds GOST-512
  // and RSA signatures over the same element. XMLUtil.verifyXmlSignature(doc, parentXPath) checks every
  // ds:Signature under the parent; Santuario checks each one on its own.
  const xpath = { tbsXPath: '//data', parentXPath: '//signatures' };
  const form = '<?xml version="1.0" encoding="UTF-8"?>\n<application><data Id="lot-1"><price currency="KZT">1000.00</price><note>Синтетика</note></data><signatures/></application>\n';
  const file = name => join(folder, name);
  writeFileSync(file('form.xml'), form);
  let signed = java(['XmlReference', 'sign', file('RSA.p12'), PASSWORD, file('form.xml'), xpath.tbsXPath, xpath.parentXPath]);
  const officialProfile = profile(signed);
  for (const [step, family] of [[2, 'GOST512'], [3, 'RSA']]) {
    const signer = await openContainer(new Uint8Array(readFileSync(file(`${family}.p12`))), PASSWORD);
    try { signed = await signXml(signer, signed, xpath); } finally { signer.destroy(); }
    assert.deepEqual({ ...profile(signed, step - 1, step), signatureMethod: undefined, digestMethod: undefined },
      { ...officialProfile, signatureMethod: undefined, digestMethod: undefined }, `XPath ${family}: same profile as XMLUtil`);
    writeFileSync(file(`form-${step}.xml`), signed);
    assert.match(java(['XmlReference', 'official', file(`form-${step}.xml`), xpath.parentXPath]), /OFFICIAL VALID/, `XPath co-signature ${step}`);
    const each = java(['XmlReference', 'each', file(`form-${step}.xml`)]).trim().split('\n');
    assert.equal(each.length, step); assert.ok(each.every(line => / VALID /.test(line)), each.join('\n'));
  }
  writeFileSync(file('form-changed.xml'), signed.replace('1000.00', '1000.01'));
  assert.throws(() => java(['XmlReference', 'official', file('form-changed.xml'), xpath.parentXPath]), rejected, 'XPath: a changed price is rejected');
  console.log('PASS: XPath //data into //signatures: official RSA signature, then Tegin GOST-512 and RSA co-signatures with the XMLUtil profile (Reference #Id, C14N#WithComments, exclusive SignedInfo); the official XMLUtil.verifyXmlSignature and Santuario accept all 3 signatures and reject a changed price');
  console.log('NURSign XML crosscheck completed.');
} finally {
  rmSync(folder, { recursive: true, force: true });
}
