package io.github.johnjcool.keycloak.broker.cas;

import java.io.Serial;
import org.keycloak.models.IdentityProviderModel;

public class CasIdentityProviderConfig extends IdentityProviderModel {

  @Serial private static final long serialVersionUID = 1L;

  private static final String DEFAULT_CAS_LOGIN_SUFFIX = "login";
  private static final String DEFAULT_CAS_LOGOUT_SUFFIX = "logout";
  private static final String CAS_SERVICE_VALIDATE_SUFFIX = "serviceValidate";
  private static final String CAS_3_PROTOCOL_PREFIX = "p3";

  public CasIdentityProviderConfig() {
    super();
  }

  public CasIdentityProviderConfig(final IdentityProviderModel model) {
    super(model);
  }

  public void setCasServerUrlPrefix(final String casServerUrlPrefix) {
    getConfig().put("casServerUrlPrefix", casServerUrlPrefix);
  }

  public String getCasServerUrlPrefix() {
    return getConfig().get("casServerUrlPrefix");
  }

  public void setGateway(final boolean gateway) {
    getConfig().put("gateway", String.valueOf(gateway));
  }

  public boolean isGateway() {
    return Boolean.parseBoolean(getConfig().get("gateway"));
  }

  public void setRenew(final boolean renew) {
    getConfig().put("renew", String.valueOf(renew));
  }

  public boolean isRenew() {
    return Boolean.parseBoolean(getConfig().get("renew"));
  }

  public void setCasLogout(final boolean casLogout) {
    getConfig().put("redirectToCasServerAfterLogout", String.valueOf(casLogout));
  }

  public boolean isCasLogout() {
    return Boolean.parseBoolean(getConfig().get("redirectToCasServerAfterLogout"));
  }

  public String getCasServerLoginUrl() {
    return String.format("%s/%s", getConfig().get("casServerUrlPrefix"), DEFAULT_CAS_LOGIN_SUFFIX);
  }

  public String getCasServerLogoutUrl() {
    return String.format("%s/%s", getConfig().get("casServerUrlPrefix"), DEFAULT_CAS_LOGOUT_SUFFIX);
  }

  public String getCasServiceValidateUrl() {
    return String.format(
        "%s/%s/%s",
        getConfig().get("casServerUrlPrefix"), CAS_3_PROTOCOL_PREFIX, CAS_SERVICE_VALIDATE_SUFFIX);
  }
}
