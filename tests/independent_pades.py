"""Independent PAdES checks with pyHanko (tested with 0.38.0). Synthetic files only.

  validate <file.pdf> <trusted-cert.pem>   -> JSON with integrity, coverage, modifications, AdES basic result
  modify   <signed.pdf> <out.pdf>          -> incremental update that draws over page 1 after signing
  encrypt  <file.pdf> <out.pdf>            -> RC4/AES encrypted copy (user password)
  sign     <file.pdf> <out.pdf> <key.pem> <cert.pem> -> PAdES signature made by pyHanko itself
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
from pyhanko.sign.fields import SigSeedSubFilter
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


def validate(path, cert_path):
    root = certificate(cert_path)
    no_revocation = RevocationCheckingPolicy(RevocationCheckingRule.NO_CHECK, RevocationCheckingRule.NO_CHECK)
    context = ValidationContext(trust_roots=[root], allow_fetching=False, revocation_mode='soft-fail')
    spec = SignatureValidationSpec(CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(trust_roots=[CertTrustAnchor(root)]),
        revinfo_policy=CertRevTrustPolicy(no_revocation)))
    with open(path, 'rb') as stream:
        reader = PdfFileReader(stream, strict=True)
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
                'docmdpOk': status.docmdp_ok, 'bottomLine': status.bottom_line,
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


if __name__ == '__main__':
    command, *args = sys.argv[1:]
    {'validate': validate, 'modify': modify, 'encrypt': encrypt, 'sign': sign}[command](*args)
