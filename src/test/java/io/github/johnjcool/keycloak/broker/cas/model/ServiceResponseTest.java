package io.github.johnjcool.keycloak.broker.cas.model;

import io.undertow.Undertow;
import io.undertow.util.Headers;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.io.StringReader;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ServiceResponseTest {

  private static Undertow server;

  @Test
  public void testReadWithAttributes() throws JAXBException {
    Client client = ResteasyClientBuilder.newClient(ResteasyProviderFactory.getInstance());
    WebTarget target =
        client.target(String.format("http://%s:%d%s", "localhost", 9999, "/with-attributes"));
    Response response = target.request().get();
    Assert.assertEquals(200, response.getStatus());
    response.bufferEntity();

    String stringResponse = response.readEntity(String.class);

    Unmarshaller um = JAXBContext.newInstance(ServiceResponse.class).createUnmarshaller();
    um.setEventHandler(new jakarta.xml.bind.helpers.DefaultValidationEventHandler());

    ServiceResponse serviceResponse =
        (ServiceResponse) um.unmarshal(new StringReader(stringResponse));

    System.out.println(serviceResponse);
    System.out.println(serviceResponse.getSuccess());
    System.out.println(serviceResponse.getSuccess().getAttributes());
    Success success = serviceResponse.getSuccess();

    Assert.assertEquals("test", success.getUser());
    Assert.assertFalse(success.getAttributes().isEmpty());
    Assert.assertEquals(
        Collections.singletonList("test.test@test.test"), success.getAttributes().get("mail"));
    Assert.assertEquals(Collections.singletonList("tets"), success.getAttributes().get("sn"));
    Assert.assertEquals(Collections.singletonList("test"), success.getAttributes().get("cn"));
  }

  @Test
  public void testReadWithMultiValAttributes() throws JAXBException {
    Client client = ResteasyClientBuilder.newClient(ResteasyProviderFactory.getInstance());
    WebTarget target =
        client.target(
            String.format("http://%s:%d%s", "localhost", 9999, "/with-multival-attributes"));
    Response response = target.request().get();
    Assert.assertEquals(200, response.getStatus());
    response.bufferEntity();

    String stringResponse = response.readEntity(String.class);

    Unmarshaller um = JAXBContext.newInstance(ServiceResponse.class).createUnmarshaller();
    um.setEventHandler(new jakarta.xml.bind.helpers.DefaultValidationEventHandler());

    ServiceResponse serviceResponse =
        (ServiceResponse) um.unmarshal(new StringReader(stringResponse));

    System.out.println(serviceResponse);
    System.out.println(serviceResponse.getSuccess());
    System.out.println(serviceResponse.getSuccess().getAttributes());
    Success success = serviceResponse.getSuccess();

    Assert.assertEquals("test", success.getUser());
    Assert.assertFalse(success.getAttributes().isEmpty());
    Assert.assertEquals(
        Collections.singletonList("test.test@test.test"), success.getAttributes().get("mail"));
    Assert.assertEquals(Collections.singletonList("tets"), success.getAttributes().get("sn"));
    Assert.assertEquals(Collections.singletonList("test"), success.getAttributes().get("cn"));
    Assert.assertEquals(
        Arrays.asList("LdapAuthenticationHandler", "mfa-duo"),
        success.getAttributes().get("successfulAuthenticationHandlers"));
  }

  @Test
  public void testReadWithoutAttributes() throws JAXBException {
    Client client = ResteasyClientBuilder.newClient(ResteasyProviderFactory.getInstance());
    WebTarget target =
        client.target(String.format("http://%s:%d%s", "localhost", 9999, "/without-attributes"));
    Response response = target.request().get();
    Assert.assertEquals(200, response.getStatus());
    response.bufferEntity();

    String stringResponse = response.readEntity(String.class);

    Unmarshaller um = JAXBContext.newInstance(ServiceResponse.class).createUnmarshaller();
    um.setEventHandler(new jakarta.xml.bind.helpers.DefaultValidationEventHandler());

    ServiceResponse serviceResponse =
        (ServiceResponse) um.unmarshal(new StringReader(stringResponse));

    System.out.println(serviceResponse);
    System.out.println(serviceResponse.getSuccess());
    System.out.println(serviceResponse.getSuccess().getAttributes());
    Success success = serviceResponse.getSuccess();

    Assert.assertEquals("test", success.getUser());
    Assert.assertTrue(success.getAttributes().isEmpty());
  }

  @BeforeClass
  public static void init() {
    server =
        Undertow.builder()
            .addHttpListener(9999, "localhost")
            .setHandler(
                httpServerExchange -> {
                  switch (httpServerExchange.getRequestURI()) {
                    case "/without-attributes":
                      httpServerExchange
                          .getResponseHeaders()
                          .put(Headers.CONTENT_TYPE, "application/xml");
                      httpServerExchange
                          .getResponseSender()
                          .send(
                              Charset.defaultCharset()
                                  .encode(
                                      CharBuffer.wrap(
"""
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationSuccess>
        <cas:user>test</cas:user>
    </cas:authenticationSuccess>
</cas:serviceResponse>
                            """)));
                      break;
                    case "/with-attributes":
                      httpServerExchange
                          .getResponseHeaders()
                          .put(Headers.CONTENT_TYPE, "application/xml");
                      httpServerExchange
                          .getResponseSender()
                          .send(
                              Charset.defaultCharset()
                                  .encode(
                                      CharBuffer.wrap(
"""
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationSuccess>
        <cas:user>test</cas:user>
        <!-- Begin Ldap Attributes -->
        <cas:attributes>

                <cas:mail>test.test@test.test</cas:mail>

                <cas:sn>tets</cas:sn>

                <cas:cn>test</cas:cn>

        </cas:attributes>
        <!-- End Ldap Attributes -->


    </cas:authenticationSuccess>
</cas:serviceResponse>
                            """)));
                      break;
                    case "/with-multival-attributes":
                      httpServerExchange
                          .getResponseHeaders()
                          .put(Headers.CONTENT_TYPE, "application/xml");
                      httpServerExchange
                          .getResponseSender()
                          .send(
                              Charset.defaultCharset()
                                  .encode(
                                      CharBuffer.wrap(
"""
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationSuccess>
        <cas:user>test</cas:user>
        <!-- Begin Ldap Attributes -->
        <cas:attributes>

            <cas:mail>test.test@test.test</cas:mail>

            <cas:sn>tets</cas:sn>

            <cas:cn>test</cas:cn>

            <cas:successfulAuthenticationHandlers>LdapAuthenticationHandler</cas:successfulAuthenticationHandlers>
            <cas:successfulAuthenticationHandlers>mfa-duo</cas:successfulAuthenticationHandlers>

        </cas:attributes>
        <!-- End Ldap Attributes -->


    </cas:authenticationSuccess>
</cas:serviceResponse>
                                  """)));
                      break;
                    default:
                      throw new IllegalStateException(
                          "Unexpected value: " + httpServerExchange.getRequestURI());
                  }
                })
            .build();

    server.start();
  }

  @AfterClass
  public static void stop() {
    server.stop();
  }
}
