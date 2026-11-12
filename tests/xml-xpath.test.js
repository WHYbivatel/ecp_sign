import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DOMParser } from '@xmldom/xmldom';
import { rsaFixture, gostFixture, PASSWORD } from './helpers/fixtures.js';
import { openContainer } from '../extension/crypto/signer.js';
import { signXml, verifyCreatedXml } from '../extension/crypto/xml.js';

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const reference = JSON.parse(readFileSync(new URL('./fixtures/ncalayer-xml-reference.json', import.meta.url), 'utf8'));
const xpath = { tbsXPath: reference.tbsElementXPath, parentXPath: reference.signatureParentElementXPath };
const parse = xml => new DOMParser().parseFromString(xml, 'application/xml');
const signatures = xml => [...parse(xml).getElementsByTagNameNS(DS, 'Signature')];
const text = (node, name) => node.getElementsByTagNameNS(DS, name)[0].textContent;
const algorithmsOf = (node, name) => [...node.getElementsByTagNameNS(DS, name)].map(item => item.getAttribute('Algorithm'));
const open = async (fixture = rsaFixture()) => openContainer(fixture.container, PASSWORD);

test('XPath signing follows the Common Utils 0.3.4 profile and digests the element as the official code does', async () => {
  const signer = await open();
  const signed = await signXml(signer, reference.input, xpath);
  const [ours] = signatures(signed), [official] = signatures(reference.signed);
  assert.equal(ours.parentNode.localName, 'signatures');
  assert.equal(ours.getElementsByTagNameNS(DS, 'Reference')[0].getAttribute('URI'), '#d1');
  assert.deepEqual(algorithmsOf(ours, 'Transform'), algorithmsOf(official, 'Transform'));
  assert.deepEqual(algorithmsOf(ours, 'CanonicalizationMethod'), algorithmsOf(official, 'CanonicalizationMethod'));
  assert.deepEqual(algorithmsOf(ours, 'SignatureMethod'), algorithmsOf(official, 'SignatureMethod'));
  assert.deepEqual(algorithmsOf(ours, 'DigestMethod'), algorithmsOf(official, 'DigestMethod'));
  // Comments inside the element and xml:lang inherited from the root: same bytes as Santuario in NCALayer.
  assert.equal(text(ours, 'DigestValue'), reference.digestValue);
  assert.equal(text(official, 'DigestValue'), reference.digestValue);
  assert.equal(await verifyCreatedXml(signer, signed, { original: reference.input, ...xpath }), true);
  signer.destroy();
});

test('the signed element and the signature parent must each be exactly one element', async () => {
  const signer = await open();
  const cases = [
    ['<r><a Id="x"/><a Id="y"/><s/></r>', '//a', '//s', /ровно на один элемент, найдено: 2/],
    ['<r><a Id="x"/><s/></r>', '//b', '//s', /найдено: 0/],
    ['<r><a Id="x"/><s/></r>', '//a/@Id', '//s', /и это не элемент/],
    ['<r><a Id="x"/><s/></r>', 'count(//a)', '//s', /XPath подписываемого элемента/],
    ['<r><a Id="x"/><s/></r>', '//a[', '//s', /Некорректное выражение XPath/],
    ['<r><a Id="x"/><s/><s/></r>', '//a', '//s', /элемента для подписи.*найдено: 2/],
    ['<r><a Id="x"/><s/></r>', '//a', '', /Не указан элемент/],
    ['<r><a/><s/></r>', '//a', '//s', /не содержит атрибут Id/],
    ['<r><a ID="x"/><s/></r>', '//a', '//s', /не содержит атрибут Id/],
    ['<r><a Id="x y"/><s/></r>', '//a', '//s', /недопустимые символы/],
    ['<r><a Id="x"><s/></a></r>', '//a', '//s', /внутрь подписываемого элемента/],
    ['<r><a Id="x"/><s/></r>', '//a', '//a', /внутрь подписываемого элемента/],
    ['<r xmlns="urn:n"><a Id="x"/><s/></r>', '//a', '//s', /найдено: 0/]
  ];
  for (const [xml, tbsXPath, parentXPath, message] of cases) await assert.rejects(signXml(signer, xml, { tbsXPath, parentXPath }), message, `${xml} ${tbsXPath} ${parentXPath}`);
  // Any prefix other than SOAP-ENV means XMLDSig, as in knca_provider_util; SOAP-ENV is the SOAP envelope.
  const soap = '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body Id="b"><x>1</x></SOAP-ENV:Body></SOAP-ENV:Envelope>';
  const signed = await signXml(signer, soap, { tbsXPath: '//SOAP-ENV:Body', parentXPath: '//SOAP-ENV:Header' });
  assert.equal(signatures(signed)[0].parentNode.localName, 'Header');
  assert.equal(await verifyCreatedXml(signer, signed, { original: soap, tbsXPath: '//SOAP-ENV:Body', parentXPath: '//SOAP-ENV:Header' }), true);
  signer.destroy();
});

test('an identifier used twice, or under another attribute name, is refused before signing', async () => {
  const signer = await open();
  for (const xml of ['<r><a Id="x"/><b Id="x"/><s/></r>', '<r><a Id="x"/><b id="x"/><s/></r>', '<r><a Id="x"/><ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><b ID="x"/></ds:Object><s/></r>']) {
    await assert.rejects(signXml(signer, xml, { tbsXPath: '//a', parentXPath: '//s' }), /встречается в XML несколько раз/);
  }
  signer.destroy();
});

test('co-signing by element keeps the first signature byte-identical; the official co-signed reference is preserved too', async () => {
  const first = await open(rsaFixture({ subject: '/CN=Tegin XML first' })), second = await open(gostFixture());
  const once = await signXml(first, reference.input, xpath);
  const twice = await signXml(second, once, xpath);
  const [a, b] = signatures(twice);
  assert.equal(a.toString(), signatures(once)[0].toString());
  assert.deepEqual([a, b].map(node => node.getElementsByTagNameNS(DS, 'Reference')[0].getAttribute('URI')), ['#d1', '#d1']);
  assert.equal(await verifyCreatedXml(second, twice, { original: once, ...xpath }), true);
  // A third signature on the document NCALayer co-signed: both official signatures keep their bytes.
  const third = await signXml(first, reference.cosigned, xpath);
  const all = signatures(third);
  assert.equal(all.length, 3);
  assert.deepEqual(all.slice(0, 2).map(String), signatures(reference.cosigned).map(String));
  assert.equal(await verifyCreatedXml(first, third, { original: reference.cosigned, ...xpath }), true);
  first.destroy(); second.destroy();
});

test('a signature that would change signed data is refused: whole document after any signature, element after a whole-document one', async () => {
  const signer = await open();
  const whole = await signXml(signer, reference.input);
  await assert.rejects(signXml(signer, whole), /нарушила бы прежнюю подпись.*по элементу \(XPath\)/);
  await assert.rejects(signXml(signer, whole, xpath), /нарушила бы прежнюю подпись/);
  // The element signature sits in <signatures>, outside the signed element: a later whole-document signature keeps it.
  const element = await signXml(signer, reference.input, xpath);
  const both = await signXml(signer, element);
  assert.equal(signatures(both)[0].toString(), signatures(element)[0].toString());
  assert.equal(await verifyCreatedXml(signer, both, { original: element }), true);
  // An earlier signature over an element that would contain the new one.
  await assert.rejects(signXml(signer, '<r><a Id="x"><s/></a><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:Reference URI="#x"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms></ds:Reference></ds:SignedInfo></ds:Signature><b Id="y"/></r>', { tbsXPath: '//b', parentXPath: '//s' }), /нарушила бы прежнюю подпись/);
  signer.destroy();
});

test('earlier signatures Tegin cannot follow are refused instead of being risked', async () => {
  const signer = await open();
  const wrap = reference => `<r><b Id="y"/><s/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>${reference}</ds:SignedInfo></ds:Signature></r>`;
  for (const [ref, message] of [
    ['<ds:Reference URI="http://example.kz/doc"/>', /не указывает ровно на один элемент/],
    ['<ds:Reference URI="#missing"/>', /не указывает ровно на один элемент/],
    ['<ds:Reference/>', /ссылка без URI/],
    ['<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>1</ds:XPath></ds:Transform></ds:Transforms></ds:Reference>', /преобразование/],
    ['', /нет ссылок/]
  ]) await assert.rejects(signXml(signer, wrap(ref), { tbsXPath: '//b', parentXPath: '//s' }), message);
  signer.destroy();
});

test('the self-check rejects a changed element, a substituted structure or a changed earlier signature', async () => {
  const signer = await open();
  const signed = await signXml(signer, reference.input, xpath);
  const check = (xml, original = reference.input) => verifyCreatedXml(signer, xml, { original, ...xpath });
  assert.equal(await check(signed.replace('Привет', 'Пока')), false);
  // Wrapping: a copy of the element with the same Id elsewhere makes the reference ambiguous.
  assert.equal(await check(signed.replace('<signatures>', '<signatures><data Id="d1"><item>другое</item></data>')), false);
  // Signature moved out of the requested parent.
  const moved = signed.replace(/<signatures>(<ds:Signature[\s\S]*<\/ds:Signature>)<\/signatures>/, '<signatures/>$1');
  assert.notEqual(moved, signed);
  assert.equal(await check(moved), false);
  // An earlier signature altered in the output compared with the input.
  const once = await signXml(signer, reference.input, xpath);
  const twice = await signXml(signer, once, xpath);
  assert.equal(await check(twice, once), true);
  const firstDigest = text(signatures(once)[0], 'DigestValue');
  assert.equal(await check(twice.replace(firstDigest, firstDigest.replace(/^./, c => c === 'A' ? 'B' : 'A')), once), false);
  assert.equal(await check(twice), false);
  signer.destroy();
});
