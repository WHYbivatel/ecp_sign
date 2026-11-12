package kz.gov.pki.osgi.layer.bundle.basics;

// Development-only stand-in for knca_applet's UI preferences, which need an OSGi bundle context.
// Put it before knca_applet on the classpath of BasicsReference; signing code stays official.
public enum Settings {
  INSTANCE;

  public String loadLocale() { return "ru"; }
  public String loadRecentPath() { return ""; }
  public void saveRecentPath(String path) {}
}
