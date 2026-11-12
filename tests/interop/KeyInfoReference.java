import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.provider.utils.X509Util;
import kz.gov.pki.reference.KeyStoreEntry;
import kz.gov.pki.knca.types.KeyInfo;

// Development-only reference for tests/fixtures/ncalayer-keyinfo.json: getKeyInfo fields and key types as the official
// Common Bundle computes them. Needs kalkancrypt, knca_provider_util and NCALayerCommonBundle from ncalayer.zip.
// A second argument prints the fields KeyInfo would log instead of returning (certificates without SKI or AKI).
public class KeyInfoReference {
 static String q(String v) { return v == null ? "null" : "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\""; }
 public static void main(String[] args) throws Exception {
  Security.addProvider(new KalkanProvider());
  CertificateFactory factory = CertificateFactory.getInstance("X.509", "KALKAN");
  X509Certificate cert;
  try (InputStream in = Files.newInputStream(Path.of(args[0]))) { cert = (X509Certificate) factory.generateCertificate(in); }
  String types;
  try { types = X509Util.getKNCACertificateType(cert).toString(); } catch (Exception e) { types = "ERROR " + e.getMessage(); }
  if (args.length > 1) {
   System.out.println("{\"types\":" + q(types) + ",\"algorithm\":" + q(cert.getPublicKey().getAlgorithm()) + ",\"subjectDn\":" + q(X509Util.getSubjectDN(cert).toString())
    + ",\"issuerDn\":" + q(X509Util.getIssuerDN(cert).toString()) + ",\"serialNumber\":" + q(new KeyStoreEntry("a", "x", cert).getSerialNumber()) + ",\"subjectCn\":" + q(new KeyStoreEntry("a", "x", cert).getSubjectCn()) + "}");
   return;
  }
  KeyInfo info = new KeyInfo(new KeyStoreEntry("alias-1", cert.getPublicKey().getAlgorithm(), cert), "alias-1");
  System.out.println("{\"types\":" + q(types) + ",\"alias\":" + q(info.getAlias()) + ",\"keyId\":" + q(info.getKeyId()) + ",\"algorithm\":" + q(info.getAlgorithm())
   + ",\"subjectCn\":" + q(info.getSubjectCn()) + ",\"subjectDn\":" + q(info.getSubjectDn()) + ",\"issuerCn\":" + q(info.getIssuerCn()) + ",\"issuerDn\":" + q(info.getIssuerDn())
   + ",\"serialNumber\":" + q(info.getSerialNumber()) + ",\"certNotBefore\":" + q(info.getCertNotBefore()) + ",\"certNotAfter\":" + q(info.getCertNotAfter())
   + ",\"authorityKeyIdentifier\":" + q(info.getAuthorityKeyIdentifier()) + ",\"pem\":" + q(info.getPem()) + "}");
 }
}
