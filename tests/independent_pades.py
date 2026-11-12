"""Independent PAdES checks with pyHanko (tested with 0.38.0). Synthetic files only.

  validate <file.pdf> <trusted-cert.pem> [lenient] -> JSON with integrity, coverage, modifications, AdES basic result;
           strict reading by default (refuses hybrid-reference files), 'lenient' reads them
  modify   <signed.pdf> <out.pdf>          -> incremental update that draws over page 1 after signing
  encrypt  <file.pdf> <out.pdf>            -> RC4/AES encrypted copy (user password)
  sign     <file.pdf> <out.pdf> <key.pem> <cert.pem> -> PAdES signature made by pyHanko itself
  sign-locked <file.pdf> <out.pdf> <key.pem> <cert.pem> <field> <1|2|3|-> -> same, field /Lock over <field>, optional /P
  certify  <file.pdf> <out.pdf> <key.pem> <cert.pem> <1|2|3> -> certification signature with DocMDP permission
  fill     <file.pdf> <out.pdf> <field> <value>  -> incremental update that changes a text field value
"""
import asyncio
import json
import sys

from asn1crypto import pem, x509
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.sign import signers
from pyhanko.sign.fields import FieldMDPAction, FieldMDPSpec, MDPPerm, SigFieldSpec, SigSeedSubFilter, append_signature_field
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.ades import ades_basic_validation
from pyhanko.sign.validation.policy_decl import SignatureValidationSpec
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.authority import CertTrustAnchor
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule
from pyhanko_certvalidator.registry import SimpleTrustManager


def certificate(path):
    data = open(path, 'rb').read()
    if pem.detect(data):
        data = pem.unarmor(data)[2]
    return x509.Certificate.load(data)


def validate(path, cert_path, mode='strict'):
    root = certificate(cert_path)
    no_revocation = RevocationCheckingPolicy(RevocationCheckingRule.NO_CHECK, RevocationCheckingRule.NO_CHECK)
    context = ValidationContext(trust_roots=[root], allow_fetching=False, revocation_mode='soft-fail')
    spec = SignatureValidationSpec(CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(trust_roots=[CertTrustAnchor(root)]),
        revinfo_policy=CertRevTrustPolicy(no_revocation)))
    with open(path, 'rb') as stream:
        reader = PdfFileReader(stream, strict=mode != 'lenient')
        result = {'validator': 'pyHanko 0.38.0', 'signatures': []}
        for embedded in reader.embedded_signatures:
            status = validate_pdf_signature(embedded, context)
            ades = asyncio.run(ades_basic_validation(embedded.signed_data, spec, raw_digest=embedded.compute_digest()))
            attributes = sorted(attribute['type'].dotted for attribute in embedded.signer_info['signed_attrs'])
            result['signatures'].append({
                'fieldName': embedded.field_name,
                'subFilter': str(embedded.sig_object['/SubFilter']),
                'intact': status.intact, 'valid': status.valid, 'trusted': status.trusted,
                'coverage': status.coverage.name if status.coverage else None,
                'modificationLevel': status.modification_level.name if status.modification_level else None,
                'docmdpOk': status.docmdp_ok,
                'certification': embedded.docmdp_level.name if embedded.docmdp_level else None,
                'bottomLine': status.bottom_line,
                'adesBasic': ades.ades_subindic.status.name if hasattr(ades.ades_subindic, 'status') else str(ades.ades_subindic),
                'adesSubindication': ades.ades_subindic.name,
                'signedAttributes': attributes,
                'detached': embedded.signed_data['encap_content_info']['content'].native is None,
            })
    print(json.dumps(result))


def modify(path, out):
    with open(path, 'rb') as stream:
        writer = IncrementalPdfFileWriter(stream, strict=True)
        overlay = writer.add_object(generic.StreamObject(stream_data=b'1 0 0 rg 40 700 300 60 re f'))
        writer.add_stream_to_page(0, overlay)
        with open(out, 'wb') as target:
            writer.write(target)


def encrypt(path, out):
    with open(path, 'rb') as stream:
        writer = copy_into_new_writer(PdfFileReader(stream, strict=True))
        writer.encrypt('synthetic-owner', 'synthetic-user')
        with open(out, 'wb') as target:
            writer.write(target)


def sign(path, out, key, cert):
    signer = signers.SimpleSigner.load(key, cert)
    with open(path, 'rb') as stream:
        writer = IncrementalPdfFileWriter(stream, strict=True)
        with open(out, 'wb') as target:
            signers.sign_pdf(writer, signers.PdfSignatureMetadata(field_name='Other', subfilter=SigSeedSubFilter.PADES), signer=signer, output=target)


def sign_locked(path, out, key, cert, field, permission):
    """Signature field whose /Lock (FieldMDP) covers <field>; <permission> 1-3 adds /P, '-' leaves it out."""
    signer = signers.SimpleSigner.load(key, cert)
    lock = FieldMDPSpec(FieldMDPAction.INCLUDE, fields=[field])
    spec = SigFieldSpec('Locked', field_mdp_spec=lock, doc_mdp_update_value=None if permission == '-' else MDPPerm(int(permission)))
    with open(path, 'rb') as stream:
        writer = IncrementalPdfFileWriter(stream, strict=True)
        append_signature_field(writer, spec)
        with open(out, 'wb') as target:
            signers.sign_pdf(writer, signers.PdfSignatureMetadata(field_name='Locked', subfilter=SigSeedSubFilter.PADES), signer=signer, output=target)


def certify(path, out, key, cert, permission):
    """Certification (author) signature with DocMDP <permission>: 1 no changes, 2 form filling, 3 annotations."""
    signer = signers.SimpleSigner.load(key, cert)
    meta = signers.PdfSignatureMetadata(field_name='Certified', subfilter=SigSeedSubFilter.PADES, certify=True, docmdp_permissions=MDPPerm(int(permission)))
    with open(path, 'rb') as stream:
        writer = IncrementalPdfFileWriter(stream, strict=True)
        with open(out, 'wb') as target:
            signers.sign_pdf(writer, meta, signer=signer, output=target)


def fill(path, out, field, value):
    """Incremental update that changes the value of a text field."""
    with open(path, 'rb') as stream:
        writer = IncrementalPdfFileWriter(stream, strict=True)
        fields = writer.root['/AcroForm']['/Fields']
        for index in range(len(fields)):
            reference = fields.raw_get(index)
            node = reference.get_object()
            if node.get('/T') == field:
                node['/V'] = generic.TextStringObject(value)
                writer.mark_update(reference)
        with open(out, 'wb') as target:
            writer.write(target)


if __name__ == '__main__':
    command, *args = sys.argv[1:]
    {'validate': validate, 'modify': modify, 'encrypt': encrypt, 'sign': sign, 'sign-locked': sign_locked, 'certify': certify, 'fill': fill}[command](*args)
