package io.github.johnjcool.keycloak.broker.cas;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.services.messages.Messages;

public class CasEssentialClaimTest {

  @Test
  public void disabledFilterAlwaysPasses() {
    CasIdentityProviderConfig config =
        config(false, "credentialType", "DuoSecurityUniversalPromptCredential");
    CasIdentityProvider.validateEssentialClaim(config, Collections.emptyMap());
    CasIdentityProvider.validateEssentialClaim(config, null);
  }

  @Test
  public void matchingCredentialTypePasses() {
    CasIdentityProviderConfig config =
        config(true, "credentialType", "DuoSecurityUniversalPromptCredential");
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put(
        "credentialType", Collections.singletonList("DuoSecurityUniversalPromptCredential"));

    CasIdentityProvider.validateEssentialClaim(config, attributes);
  }

  @Test
  public void regexMatchAgainstAuthenticationMethodPasses() {
    CasIdentityProviderConfig config = config(true, "authenticationMethod", "^DUO-.*");
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put("authenticationMethod", Collections.singletonList("DUO-L100"));

    CasIdentityProvider.validateEssentialClaim(config, attributes);
  }

  @Test
  public void multiValueAnyMatchPasses() {
    CasIdentityProviderConfig config = config(true, "successfulAuthenticationHandlers", "DUO-L100");
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put(
        "successfulAuthenticationHandlers", Arrays.asList("LdapAuthenticationHandler", "DUO-L100"));

    CasIdentityProvider.validateEssentialClaim(config, attributes);
  }

  @Test
  public void missingAttributeFails() {
    CasIdentityProviderConfig config =
        config(true, "credentialType", "DuoSecurityUniversalPromptCredential");

    IdentityBrokerException thrown =
        Assert.assertThrows(
            IdentityBrokerException.class,
            () -> CasIdentityProvider.validateEssentialClaim(config, Collections.emptyMap()));

    Assert.assertEquals(
        Messages.IDENTITY_PROVIDER_UNMATCHED_ESSENTIAL_CLAIM_ERROR, thrown.getMessageCode());
  }

  @Test
  public void nonMatchingValueFails() {
    CasIdentityProviderConfig config =
        config(true, "credentialType", "DuoSecurityUniversalPromptCredential");
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put("credentialType", Collections.singletonList("UsernamePasswordCredential"));

    IdentityBrokerException thrown =
        Assert.assertThrows(
            IdentityBrokerException.class,
            () -> CasIdentityProvider.validateEssentialClaim(config, attributes));

    Assert.assertEquals(
        Messages.IDENTITY_PROVIDER_UNMATCHED_ESSENTIAL_CLAIM_ERROR, thrown.getMessageCode());
  }

  private static CasIdentityProviderConfig config(
      final boolean filtered, final String claimName, final String claimValue) {
    CasIdentityProviderConfig config = new CasIdentityProviderConfig();
    config.setFilteredByClaims(filtered);
    config.getConfig().put(IdentityProviderModel.CLAIM_FILTER_NAME, claimName);
    config.getConfig().put(IdentityProviderModel.CLAIM_FILTER_VALUE, claimValue);
    return config;
  }
}
