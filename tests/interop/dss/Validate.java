import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.util.Collections;
import java.nio.file.Files;
import java.util.List;
import java.util.stream.Collectors;

// Offline EU DSS validation: java Validate <signed file> <trusted-cert.pem>[,<more.pem>] [detached original]; prints one JSON object.
public class Validate {
  static String q(Object value) {
    if (value == null) return "null";
    return "\"" + value.toString().replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ") + "\"";
  }
  static String list(List<Message> messages) {
    return messages.stream().map(m -> q(m.getValue())).collect(Collectors.joining(",", "[", "]"));
  }
  static String names(List<String> values) {
    return values == null ? "[]" : values.stream().map(Validate::q).collect(Collectors.joining(",", "[", "]"));
  }
  static int count(List<?> values) { return values == null ? 0 : values.size(); }
  static String timestamps(SignatureWrapper signature, SimpleReport simple) {
    StringBuilder out = new StringBuilder("[");
    for (TimestampWrapper timestamp : signature.getTimestampList()) {
      if (out.length() > 1) out.append(',');
      out.append('{')
        .append("\"type\":").append(q(timestamp.getType())).append(',')
        .append("\"archiveType\":").append(q(timestamp.getArchiveTimestampType())).append(',')
        .append("\"indication\":").append(q(simple.getIndication(timestamp.getId()))).append(',')
        .append("\"subIndication\":").append(q(simple.getSubIndication(timestamp.getId()))).append(',')
        .append("\"imprintIntact\":").append(timestamp.isMessageImprintDataFound() && timestamp.isMessageImprintDataIntact()).append(',')
        .append("\"signatureValid\":").append(timestamp.isSignatureValid()).append(',')
        .append("\"atsHashIndexVersion\":").append(q(timestamp.getAtsHashIndexVersion())).append(',')
        .append("\"atsHashIndexValid\":").append(timestamp.isAtsHashIndexValid()).append(',')
        .append("\"atsHashIndexMessages\":").append(names(timestamp.getAtsHashIndexValidationMessages())).append(',')
        .append("\"timestampedRevocations\":").append(timestamp.getTimestampedRevocations().size()).append(',')
        .append("\"timestampedCertificates\":").append(timestamp.getTimestampedCertificates().size())
        .append('}');
    }
    return out.append(']').toString();
  }
  public static void main(String[] args) throws Exception {
    CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
    for (String path : args[1].split(",")) trusted.addCertificate(DSSUtils.loadCertificate(Files.readAllBytes(new File(path).toPath())));
    CommonCertificateVerifier verifier = new CommonCertificateVerifier();
    verifier.setTrustedCertSources(trusted);
    verifier.setAIASource(null);
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(args[0]));
    validator.setCertificateVerifier(verifier);
    if (args.length > 2) validator.setDetachedContents(Collections.singletonList(new FileDocument(args[2])));
    Reports reports = validator.validateDocument();
    SimpleReport simple = reports.getSimpleReport();
    DiagnosticData diagnostic = reports.getDiagnosticData();
    StringBuilder out = new StringBuilder("{\"validator\":\"EU DSS 6.5.1\",\"signatures\":[");
    boolean first = true;
    for (SignatureWrapper signature : diagnostic.getSignatures()) {
      String id = signature.getId();
      PDFRevisionWrapper revision = signature.getPDFRevision();
      if (!first) out.append(',');
      first = false;
      out.append('{')
        .append("\"indication\":").append(q(simple.getIndication(id))).append(',')
        .append("\"subIndication\":").append(q(simple.getSubIndication(id))).append(',')
        .append("\"format\":").append(q(simple.getSignatureFormat(id))).append(',')
        .append("\"intact\":").append(signature.isSignatureIntact()).append(',')
        .append("\"valid\":").append(signature.isSignatureValid()).append(',')
        .append("\"bLevelValid\":").append(signature.isBLevelTechnicallyValid()).append(',')
        .append("\"filter\":").append(q(revision == null ? null : revision.getFilter())).append(',')
        .append("\"subFilter\":").append(q(revision == null ? null : revision.getSubFilter())).append(',')
        .append("\"byteRange\":").append(q(revision == null ? null : revision.getSignatureByteRange())).append(',')
        .append("\"byteRangeValid\":").append(revision != null && revision.isSignatureByteRangeValid()).append(',')
        .append("\"modifications\":").append(revision != null && revision.arePdfModificationsDetected()).append(',')
        .append("\"objectModifications\":").append(revision != null && revision.arePdfObjectModificationsDetected()).append(',')
        .append("\"fieldNames\":").append(names(revision == null ? null : revision.getSignatureFieldNames())).append(',')
        .append("\"signatureOrFormFillChanges\":").append(revision == null ? 0 : count(revision.getPdfSignatureOrFormFillChanges())).append(',')
        .append("\"annotationChanges\":").append(revision == null ? 0 : count(revision.getPdfAnnotationChanges())).append(',')
        .append("\"extensionChanges\":").append(revision == null ? 0 : count(revision.getPdfExtensionChanges())).append(',')
        .append("\"undefinedChanges\":").append(revision == null ? 0 : count(revision.getPdfUndefinedChanges())).append(',')
        .append("\"revocations\":").append(signature.foundRevocations().getRelatedRevocationData().size()).append(',')
        .append("\"timestamps\":").append(timestamps(signature, simple)).append(',')
        .append("\"errors\":").append(list(simple.getAdESValidationErrors(id))).append(',')
        .append("\"warnings\":").append(list(simple.getAdESValidationWarnings(id)))
        .append('}');
    }
    out.append("]}");
    System.out.println(out);
  }
}
