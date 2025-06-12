package io.github.johnjcool.keycloak.broker.cas;

import static io.github.johnjcool.keycloak.broker.cas.util.UrlHelper.PROVIDER_PARAMETER_TICKET;
import static io.github.johnjcool.keycloak.broker.cas.util.UrlHelper.createAuthenticationUrl;
import static io.github.johnjcool.keycloak.broker.cas.util.UrlHelper.createLogoutUrl;
import static io.github.johnjcool.keycloak.broker.cas.util.UrlHelper.createValidateServiceUrl;

import io.github.johnjcool.keycloak.broker.cas.model.ServiceResponse;
import io.github.johnjcool.keycloak.broker.cas.model.Success;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.*;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.io.IOException;
import java.io.StringReader;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

public class CasIdentityProvider extends AbstractIdentityProvider<CasIdentityProviderConfig> {

  protected static final Logger logger = Logger.getLogger(CasIdentityProvider.class);

  public static final String USER_ATTRIBUTES = "UserAttributes";

  private static final String STATE_COOKIE_NAME = "__Host-cas_state";

  private static final Unmarshaller unmarshaller;

  static {
    try {
      unmarshaller = JAXBContext.newInstance(ServiceResponse.class).createUnmarshaller();
    } catch (JAXBException e) {
      throw new RuntimeException(e);
    }
  }

  public CasIdentityProvider(
      final KeycloakSession session, final CasIdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  public Response performLogin(final AuthenticationRequest request) {
    return Response.seeOther(createAuthenticationUrl(getConfig(), request).build())
        .cookie(
            new NewCookie.Builder(STATE_COOKIE_NAME)
                .value(request.getState().getEncoded())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .build())
        .build();
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(
      final KeycloakSession session,
      final UserSessionModel userSession,
      final UriInfo uriInfo,
      final RealmModel realm) {
    CasIdentityProviderConfig config = getConfig();
    Response res = AuthenticationManager.finishBrowserLogout(
      session, realm, userSession, uriInfo, session.getContext().getConnection(), null);
    if (res.getStatus() != 302) {
      logger.error("Failed to logout user session: " + userSession.getId());
      EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
      event.event(EventType.LOGOUT);
      event.error(Errors.USER_SESSION_NOT_FOUND);
      return ErrorPage.error(
        session, null, Response.Status.INTERNAL_SERVER_ERROR, "CAS KC Logout Failed");
    }
    if(config.isCasLogout()){
      return Response.status(302)
        .location(createLogoutUrl(getConfig(), realm, uriInfo).build())
        .build();
    }
    return res;
  }


  @Override
  public Response retrieveToken(
      final KeycloakSession session, final FederatedIdentityModel identity) {
    return Response.ok(identity.getToken()).type(MediaType.APPLICATION_JSON).build();
  }

  @Override
  public Endpoint callback(
      final RealmModel realm,
      final org.keycloak.broker.provider.IdentityProvider.AuthenticationCallback callback,
      final EventBuilder event) {
    return new Endpoint(callback, realm, this);
  }

  public static final class Endpoint {
    private final AuthenticationCallback callback;
    private final RealmModel realm;
    private final KeycloakSession session;
    private final ClientConnection clientConnection;
    private final HttpHeaders headers;
    private final CasIdentityProvider provider;
    private final CasIdentityProviderConfig config;

    Endpoint(
        final AuthenticationCallback callback,
        final RealmModel realm,
        final CasIdentityProvider provider) {
      this.callback = callback;
      this.realm = realm;
      this.provider = provider;
      this.session = provider.session;
      this.headers = session.getContext().getRequestHeaders();
      this.clientConnection = session.getContext().getConnection();
      this.config = provider.getConfig();
    }

    @GET
    public Response authResponse(
        @QueryParam(PROVIDER_PARAMETER_TICKET) final String ticket,
        @CookieParam(STATE_COOKIE_NAME) final Cookie stateCookie) {
      return callback.authenticated(
          getFederatedIdentity(
              config, ticket, session.getContext().getUri(), stateCookie.getValue()));
    }

    @GET
    @Path("logout_response")
    public Response logoutResponse(
        @Context final UriInfo uriInfo, @QueryParam("state") final String state) {
      UserSessionModel userSession = session.sessions().getUserSession(realm, state);
      if (userSession == null) {
        logger.error("no valid user session");
        EventBuilder e = new EventBuilder(realm, session, clientConnection);
        e.event(EventType.LOGOUT);
        e.error(Errors.USER_SESSION_NOT_FOUND);
        return ErrorPage.error(
            session,
            null,
            Response.Status.BAD_REQUEST,
            Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
      }
      if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
        logger.error("usersession in different state");
        EventBuilder e = new EventBuilder(realm, session, clientConnection);
        e.event(EventType.LOGOUT);
        e.error(Errors.USER_SESSION_NOT_FOUND);
        return ErrorPage.error(
            session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
      }
      return AuthenticationManager.finishBrowserLogout(
          session, realm, userSession, uriInfo, clientConnection, headers);
    }

    private BrokeredIdentityContext getFederatedIdentity(
        final CasIdentityProviderConfig config,
        final String ticket,
        final UriInfo uriInfo,
        final String state) {
      logger.debug("Current state value: " + state);
      try (SimpleHttp.Response response =
          SimpleHttp.doGet(
                  createValidateServiceUrl(config, ticket, uriInfo).build().toURL().toString(),
                  session)
              .asResponse()) {
        if (response.getStatus() != 200) {
          logger.error(response.asString());
          throw new IdentityBrokerException(
              "CAS returned a non-200 response code: " + response.getStatus());
        }

        if (logger.isDebugEnabled()) {
          logger.debug("Raw XML from CAS: " + response.asString());
        }

        ServiceResponse serviceResponse =
            (ServiceResponse) unmarshaller.unmarshal(new StringReader(response.asString()));

        if (logger.isDebugEnabled()) {
          logger.debug("Parsed response: " + serviceResponse);
        }

        if (serviceResponse.getFailure() != null) {
          throw new IdentityBrokerException(
              "Failure response from CAS: "
                  + serviceResponse.getFailure().getCode()
                  + "("
                  + serviceResponse.getFailure().getDescription()
                  + ")");
        }
        Success success = serviceResponse.getSuccess();

        BrokeredIdentityContext user = new BrokeredIdentityContext(success.getUser(), config);
        user.setUsername(success.getUser());
        user.getContextData().put(USER_ATTRIBUTES, success.getAttributes());
        user.setIdp(provider);
        AuthenticationSessionModel authSession =
            this.callback.getAndVerifyAuthenticationSession(state);
        session.getContext().setAuthenticationSession(authSession);
        user.setAuthenticationSession(authSession);
        return user;
      } catch (IOException | JAXBException e) {
        throw new IdentityBrokerException("Failed to complete CAS authentication", e);
      }
    }
  }
}
