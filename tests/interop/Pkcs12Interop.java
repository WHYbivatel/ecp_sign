import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

// Development-only PKCS#12 interop with the official Kalkan provider.
// The password is read from TEGIN_TEST_P12_PASSWORD and never printed.
public class Pkcs12Interop {
 public static void main(String[] args) throws Exception {
  Security.addProvider(new KalkanProvider());
  char[] password = System.getenv("TEGIN_TEST_P12_PASSWORD").toCharArray();
  if (args[0].equals("create")) { create(args[1], args[2], args[3], password); return; }
  KeyStore source = KeyStore.getInstance("PKCS12", "KALKAN");
  try (InputStream in = Files.newInputStream(Path.of(args[1]))) { source.load(in, password); }
  int keys = 0;
  for (String alias : Collections.list(source.aliases())) {
   if (!source.isKeyEntry(alias)) continue;
   Key key = source.getKey(alias, password);
   if (key == null) throw new Exception("Key entry without key");
   keys++;
   System.out.println("KALKAN KEY " + key.getAlgorithm());
  }
  if (keys == 0) throw new Exception("No key entries");
  if (args[0].equals("open")) { System.out.println("KALKAN OPEN OK"); return; }
  KeyStore target = KeyStore.getInstance("PKCS12", "KALKAN");
  target.load(null, null);
  for (String alias : Collections.list(source.aliases())) {
   if (!source.isKeyEntry(alias)) continue;
   Certificate[] chain = source.getCertificateChain(alias);
   if (chain == null) chain = new Certificate[] { source.getCertificate(alias) };
   target.setKeyEntry(alias, source.getKey(alias, password), password, chain);
  }
  try (OutputStream out = Files.newOutputStream(Path.of(args[2]))) { target.store(out, password); }
  System.out.println("KALKAN RESAVE OK");
 }

 // Disposable self-signed key generated and stored entirely by Kalkan.
 static void create(String family, String storeType, String path, char[] password) throws Exception {
  String generator, signature; int strength;
  switch (family) {
   case "RSA": generator = "RSA"; strength = 2048; signature = "SHA256withRSA"; break;
   case "GOST512": generator = "ECGOST3410-2015"; strength = 512; signature = "1.2.398.3.10.1.1.2.3.2"; break;
   case "GOST256": generator = "ECGOST3410-2015"; strength = 256; signature = "1.2.398.3.10.1.1.2.3.1"; break;
   default: generator = "ECGOST34310"; strength = 256; signature = "1.2.398.3.10.1.1.1.2"; break;
  }
  KeyPairGenerator keys = KeyPairGenerator.getInstance(generator, "KALKAN");
  keys.initialize(strength, new SecureRandom());
  KeyPair pair = keys.generateKeyPair();
  kz.gov.pki.kalkan.x509.X509V3CertificateGenerator certificates = new kz.gov.pki.kalkan.x509.X509V3CertificateGenerator();
  javax.security.auth.x500.X500Principal name = new javax.security.auth.x500.X500Principal("CN=Tegin Kalkan disposable test");
  certificates.setSerialNumber(java.math.BigInteger.valueOf(System.nanoTime()));
  certificates.setIssuerDN(name); certificates.setSubjectDN(name);
  certificates.setNotBefore(new Date(System.currentTimeMillis() - 86400000L));
  certificates.setNotAfter(new Date(System.currentTimeMillis() + 86400000L));
  certificates.setPublicKey(pair.getPublic());
  certificates.setSignatureAlgorithm(signature);
  java.security.cert.X509Certificate certificate = certificates.generate(pair.getPrivate(), "KALKAN");
  KeyStore store = KeyStore.getInstance(storeType, "KALKAN");
  store.load(null, null);
  store.setKeyEntry("tegin-test", pair.getPrivate(), password, new Certificate[] { certificate });
  try (OutputStream out = Files.newOutputStream(Path.of(path))) { store.store(out, password); }
  System.out.println("KALKAN CREATE OK " + pair.getPrivate().getAlgorithm());
 }
}
