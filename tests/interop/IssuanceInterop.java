import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.pkcs.Attribute;
import kz.gov.pki.kalkan.asn1.pkcs.CertificationRequestInfo;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.asn1.x509.GeneralNames;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.x509.BasicConstraints;
import kz.gov.pki.kalkan.asn1.x509.KeyUsage;
import kz.gov.pki.kalkan.asn1.x509.X509Name;
import kz.gov.pki.kalkan.jce.PKCS10CertificationRequest;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.x509.X509V3CertificateGenerator;

// Development-only issuance interop with the official Kalkan provider. Disposable keys only.
//   csr <request.der>                  Kalkan verifies a PKCS#10 request
//   attrs <request.der>                the subject and extensionRequest as Kalkan reads them
//   name <dn.tsv>                      DER of the subject Kalkan builds from OID/value lines
//   request <family> <dn.tsv> <out>    a PKCS#10 request generated and signed by Kalkan
//   issue <request.der> <dir>          Kalkan acts as a GOST CA: root.der and leaf.der for the request
public class IssuanceInterop {
 public static void main(String[] args) throws Exception {
  Security.addProvider(new KalkanProvider());
  switch (args[0]) {
   case "csr": {
    PKCS10CertificationRequest request = new PKCS10CertificationRequest(Files.readAllBytes(Path.of(args[1])));
    if (!request.verify("KALKAN")) throw new Exception("Request signature invalid");
    System.out.println("KALKAN CSR VALID " + request.getSignatureAlgorithm().getObjectId().getId() + " " + request.getPublicKey("KALKAN").getAlgorithm());
    break;
   }
   case "attrs": {
    PKCS10CertificationRequest request = new PKCS10CertificationRequest(Files.readAllBytes(Path.of(args[1])));
    if (!request.verify("KALKAN")) throw new Exception("Request signature invalid");
    CertificationRequestInfo info = request.getCertificationRequestInfo();
    System.out.println("SUBJECT " + info.getSubject().getOIDs());
    ASN1Set attributes = info.getAttributes();
    for (int i = 0; attributes != null && i < attributes.size(); i++) {
     Attribute attribute = Attribute.getInstance(attributes.getObjectAt(i));
     System.out.println("ATTRIBUTE " + attribute.getAttrType().getId());
     if (!attribute.getAttrType().getId().equals("1.2.840.113549.1.9.14")) continue;
     X509Extensions extensions = X509Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
     for (Enumeration<?> e = extensions.oids(); e.hasMoreElements();) {
      DERObjectIdentifier id = (DERObjectIdentifier) e.nextElement();
      X509Extension extension = extensions.getExtension(id);
      System.out.println("EXTENSION " + id.getId() + " critical=" + extension.isCritical());
      if (id.getId().equals("2.5.29.17")) for (GeneralName name : GeneralNames.getInstance(ASN1Object.fromByteArray(extension.getValue().getOctets())).getNames())
       System.out.println("SAN " + name.getTagNo() + " " + name.getName());
     }
    }
    break;
   }
   case "name": System.out.println("KALKAN NAME " + hex(name(args[1]).getEncoded())); break;
   case "request": {
    String generator, signature; int strength;
    switch (args[1]) {
     case "RSA": generator = "RSA"; strength = 2048; signature = "SHA256withRSA"; break;
     case "GOST256": generator = "ECGOST3410-2015"; strength = 256; signature = "1.2.398.3.10.1.1.2.3.1"; break;
     default: generator = "ECGOST3410-2015"; strength = 512; signature = "1.2.398.3.10.1.1.2.3.2"; break;
    }
    KeyPairGenerator keys = KeyPairGenerator.getInstance(generator, "KALKAN");
    keys.initialize(strength, new SecureRandom());
    KeyPair pair = keys.generateKeyPair();
    PKCS10CertificationRequest request = new PKCS10CertificationRequest(signature, name(args[2]), pair.getPublic(), null, pair.getPrivate(), "KALKAN");
    Files.write(Path.of(args[3]), request.getEncoded());
    System.out.println("KALKAN REQUEST OK");
    break;
   }
   case "issue": {
    PKCS10CertificationRequest request = new PKCS10CertificationRequest(Files.readAllBytes(Path.of(args[1])));
    if (!request.verify("KALKAN")) throw new Exception("Request signature invalid");
    KeyPairGenerator keys = KeyPairGenerator.getInstance("ECGOST3410-2015", "KALKAN");
    keys.initialize(512, new SecureRandom());
    KeyPair ca = keys.generateKeyPair();
    X509Name caName = new X509Name("CN=Tegin Kalkan synthetic root, C=KZ");
    long now = System.currentTimeMillis();
    X509V3CertificateGenerator root = new X509V3CertificateGenerator();
    root.setSerialNumber(BigInteger.valueOf(now)); root.setIssuerDN(caName); root.setSubjectDN(caName);
    root.setNotBefore(new Date(now - 86400000L)); root.setNotAfter(new Date(now + 2 * 86400000L));
    root.setPublicKey(ca.getPublic()); root.setSignatureAlgorithm("1.2.398.3.10.1.1.2.3.2");
    root.addExtension("2.5.29.19", true, new BasicConstraints(true));
    root.addExtension("2.5.29.15", true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    X509Certificate rootCertificate = root.generate(ca.getPrivate(), "KALKAN");
    X509V3CertificateGenerator leaf = new X509V3CertificateGenerator();
    leaf.setSerialNumber(BigInteger.valueOf(now + 1)); leaf.setIssuerDN(caName);
    leaf.setSubjectDN(request.getCertificationRequestInfo().getSubject());
    leaf.setNotBefore(new Date(now - 86400000L)); leaf.setNotAfter(new Date(now + 2 * 86400000L));
    leaf.setPublicKey(request.getPublicKey("KALKAN")); leaf.setSignatureAlgorithm("1.2.398.3.10.1.1.2.3.2");
    leaf.addExtension("2.5.29.15", true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
    leaf.addExtension("2.5.29.37", false, new DERSequence(new DERObjectIdentifier("1.3.6.1.5.5.7.3.4")));
    X509Certificate leafCertificate = leaf.generate(ca.getPrivate(), "KALKAN");
    leafCertificate.verify(rootCertificate.getPublicKey(), "KALKAN");
    Files.write(Path.of(args[2], "root.der"), rootCertificate.getEncoded());
    Files.write(Path.of(args[2], "leaf.der"), leafCertificate.getEncoded());
    System.out.println("KALKAN ISSUE OK " + leafCertificate.getPublicKey().getAlgorithm());
    break;
   }
   default: throw new Exception("Unknown command");
  }
 }

 static X509Name name(String path) throws IOException {
  Vector<DERObjectIdentifier> oids = new Vector<>();
  Vector<String> values = new Vector<>();
  for (String line : Files.readAllLines(Path.of(path), StandardCharsets.UTF_8)) {
   if (line.isEmpty()) continue;
   String[] parts = line.split("\t", 2);
   oids.add(new DERObjectIdentifier(parts[0])); values.add(parts[1]);
  }
  return new X509Name(oids, values);
 }
 static String hex(byte[] value) { StringBuilder out = new StringBuilder(); for (byte item : value) out.append(String.format("%02x", item)); return out.toString(); }
}
