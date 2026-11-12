import java.io.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.knca.basics.data.ViewableCert;
import kz.gov.pki.knca.basics.data.request.SigningRequest;
import kz.gov.pki.osgi.layer.bundle.basics.PKIExtras;
import kz.gov.pki.osgi.layer.nlcommons.data.CommonResponse;
import kz.gov.pki.provider.utils.model.*;
import org.json.JSONObject;

// Development-only reference for tests/fixtures/ncalayer-basics-results.json: the body that NCALayer
// knca_applet 0.4.10 (PKIExtras.sign after key selection) and NCALayerServices 0.7.4 (CommonInvoker
// wrapping) send for a synthetic PKCS#12 key, with the selection dialog skipped.
// Classpath: ncalayer.sh (host jar with org.json), kalkancrypt, kalkancrypt_xmldsig, knca_provider_util,
// knca_applet and NCALayerServices from ncalayer.zip, with ncalayer-stub/Settings.java compiled first and
// knca_applet stripped of its jar signature so the stub may share its package.
// Arguments: <key.p12> <password> <cms|xml|raw|raw-cert> <data...>
public class BasicsReference {
  public static void main(String[] args) throws Exception {
    Security.addProvider(new KalkanProvider());
    kz.gov.pki.kalkan.xmldsig.KncaXS.loadXMLSecurity();
    KeyStore keyStore = KeyStore.getInstance("PKCS12", "KALKAN");
    try (InputStream in = Files.newInputStream(Path.of(args[0]))) { keyStore.load(in, args[1].toCharArray()); }
    String alias = Collections.list(keyStore.aliases()).get(0);
    SigningParams params = switch (args[2]) {
      case "cms" -> CmsSigningParams.builder().decode(true).encapsulate(true).digested(false).build();
      case "xml" -> XmlSigningParams.builder().build();
      case "raw" -> RawSigningParams.builder().decode(true).outputCert(false).build();
      case "raw-cert" -> RawSigningParams.builder().decode(true).outputCert(true).build();
      default -> throw new IllegalArgumentException(args[2]);
    };
    SigningRequest request = SigningRequest.builder().origin("https://example.kz").allowedStorages(new ArrayList<>())
      .data(Arrays.copyOfRange(args, 3, args.length)).signingParams(params).keyStore(keyStore).password(args[1].toCharArray()).build();
    ViewableCert cert = ViewableCert.builder().alias(alias).certificate((X509Certificate) keyStore.getCertificate(alias)).build();
    Constructor<PKIExtras> constructor = PKIExtras.class.getDeclaredConstructor();
    constructor.setAccessible(true);
    Method sign = PKIExtras.class.getDeclaredMethod("sign", SigningRequest.class, ViewableCert.class);
    sign.setAccessible(true);
    Object result = sign.invoke(constructor.newInstance(), request, cert);
    CommonResponse<Object> response = CommonResponse.builder().status(true).build();
    response.setBody(result);
    System.out.println(JSONObject.wrap(response).toString());
  }
}
