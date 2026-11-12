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
  if (args[0].equals("compare")) { compare(args[1], password, args[2], System.getenv("TEGIN_TEST_NEW_PASSWORD").toCharArray()); return; }
  KeyStore source = KeyStore.getInstance("PKCS12", "KALKAN");
  try (InputStream in = Files.newInputStream(Paths.get(args[1]))) { source.load(in, password); }
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
  try (OutputStream out = Files.newOutputStream(Paths.get(args[2]))) { target.store(out, password); }
  System.out.println("KALKAN RESAVE OK");
 }

 // Password change: the original under the old password and the new file under the new one hold
 // the same keys, certificate chains and aliases, and the old password no longer opens the new file.
 static void compare(String original, char[] oldPassword, String changed, char[] newPassword) throws Exception {
  Map<String, String> before = entries(original, oldPassword), after = entries(changed, newPassword);
  if (before.isEmpty() || !before.values().stream().sorted().collect(java.util.stream.Collectors.toList()).equals(after.values().stream().sorted().collect(java.util.stream.Collectors.toList())))
   throw new Exception("Keys or certificates differ");
  System.out.println("KALKAN SAME KEY AND CERTIFICATES");
  System.out.println("KALKAN ALIAS " + (before.keySet().equals(after.keySet()) ? "SAME" : "CHANGED"));
  try { entries(changed, oldPassword); } catch (IOException expected) { System.out.println("KALKAN OLD PASSWORD REJECTED"); return; }
  throw new Exception("The old password still opens the new file");
 }
 static Map<String, String> entries(String path, char[] password) throws Exception {
  KeyStore store = KeyStore.getInstance("PKCS12", "KALKAN");
  try (InputStream in = Files.newInputStream(Paths.get(path))) { store.load(in, password); }
  Map<String, String> result = new TreeMap<>();
  Base64.Encoder base64 = Base64.getEncoder();
  for (String alias : Collections.list(store.aliases())) {
   if (!store.isKeyEntry(alias)) continue;
   StringBuilder text = new StringBuilder(base64.encodeToString(store.getKey(alias, password).getEncoded()));
   Certificate[] chain = store.getCertificateChain(alias);
   if (chain == null) chain = new Certificate[] { store.getCertificate(alias) };
   for (Certificate certificate : chain) text.append('|').append(base64.encodeToString(certificate.getEncoded()));
   result.put(alias, text.toString());
  }
  return result;
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
  try (OutputStream out = Files.newOutputStream(Paths.get(path))) { store.store(out, password); }
  System.out.println("KALKAN CREATE OK " + pair.getPrivate().getAlgorithm());
 }
}
