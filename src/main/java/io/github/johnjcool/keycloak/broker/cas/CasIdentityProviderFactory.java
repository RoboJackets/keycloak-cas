package io.github.johnjcool.keycloak.broker.cas;

import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class CasIdentityProviderFactory extends AbstractIdentityProviderFactory<CasIdentityProvider>
    implements ConfiguredProvider {

  public static final String PROVIDER_ID = "cas";

  @Override
  public String getName() {
    return "CAS";
  }

  @Override
  public CasIdentityProvider create(
      final KeycloakSession session, final IdentityProviderModel model) {
    return new CasIdentityProvider(session, new CasIdentityProviderConfig(model));
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public IdentityProviderModel createConfig() {
    return new CasIdentityProviderConfig();
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name("casServerUrlPrefix")
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("CAS server URL prefix")
        .helpText("The start of the CAS server URL, i.e. https://localhost:8443/cas")
        .add()
        .property()
        .name("renew")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("CAS renew")
        .helpText("Force users to reauthenticate.")
        .add()
        .property()
        .name("gateway")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("CAS gateway")
        .helpText("Do not force users to authenticate if they are not already authenticated.")
        .add()
        .property()
        .name("redirectToCasServerAfterLogout")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("CAS Logout")
        .helpText("Should the user also be logged out of CAS when they log out of Keycloak?")
        .add()
        .build();
  }
}
