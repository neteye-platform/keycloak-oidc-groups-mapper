package com.wuerthit.keycloak.broker.oidc.mappers.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A thin wrapper over the Keycloak Admin REST API.
 *
 * <p>Deliberately plain HTTP rather than {@code keycloak-admin-client}: the test only needs a
 * handful of calls, and this keeps the RESTEasy stack out of the test classpath.
 */
public class KeycloakAdminApi {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient http = HttpClient.newHttpClient();
    private final String baseUrl;
    private final String username;
    private final String password;

    public KeycloakAdminApi(String baseUrl, String username, String password) {
        this.baseUrl = baseUrl;
        this.username = username;
        this.password = password;
    }

    private String accessToken() throws IOException, InterruptedException {
        String form =
                "grant_type=password&client_id=admin-cli"
                        + "&username="
                        + URLEncoder.encode(username, StandardCharsets.UTF_8)
                        + "&password="
                        + URLEncoder.encode(password, StandardCharsets.UTF_8);

        HttpResponse<String> response =
                http.send(
                        HttpRequest.newBuilder(
                                        URI.create(
                                                baseUrl
                                                        + "/realms/master/protocol/openid-connect/token"))
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .POST(HttpRequest.BodyPublishers.ofString(form))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException(
                    "Admin authentication failed: "
                            + response.statusCode()
                            + " "
                            + response.body());
        }
        return JSON.readTree(response.body()).get("access_token").asText();
    }

    private HttpResponse<String> send(String method, String path, Object body)
            throws IOException, InterruptedException {

        HttpRequest.BodyPublisher payload =
                body == null
                        ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(body));

        return http.send(
                HttpRequest.newBuilder(URI.create(baseUrl + path))
                        .header("Authorization", "Bearer " + accessToken())
                        .header("Content-Type", "application/json")
                        .method(method, payload)
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode post(String path, Object body) throws IOException, InterruptedException {
        HttpResponse<String> response = send("POST", path, body);
        if (response.statusCode() / 100 != 2) {
            throw new IOException(
                    "POST " + path + " failed: " + response.statusCode() + " " + response.body());
        }
        return response.body().isEmpty() ? JSON.nullNode() : JSON.readTree(response.body());
    }

    /** Creation calls return no body: the new id is the last segment of the Location header. */
    private String postForId(String path, Object body) throws IOException, InterruptedException {
        HttpResponse<String> response = send("POST", path, body);
        if (response.statusCode() / 100 != 2) {
            throw new IOException(
                    "POST " + path + " failed: " + response.statusCode() + " " + response.body());
        }
        String location =
                response.headers()
                        .firstValue("Location")
                        .orElseThrow(
                                () ->
                                        new IOException(
                                                "POST " + path + " returned no Location header"));
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private JsonNode get(String path) throws IOException, InterruptedException {
        HttpResponse<String> response = send("GET", path, null);
        if (response.statusCode() != 200) {
            throw new IOException(
                    "GET " + path + " failed: " + response.statusCode() + " " + response.body());
        }
        return JSON.readTree(response.body());
    }

    public void createRealm(String realm) throws IOException, InterruptedException {
        post("/admin/realms", Map.of("realm", realm, "enabled", true));
    }

    public void deleteRealm(String realm) throws IOException, InterruptedException {
        send("DELETE", "/admin/realms/" + realm, null);
    }

    /** Creates the brokered identity provider pointing at the mock. */
    public void createIdentityProvider(
            String realm, String alias, String clientId, String idpBaseUrl)
            throws IOException, InterruptedException {

        // More than ten entries, so Map.of is not an option here.
        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", clientId);
        config.put("clientSecret", "fake_secret");
        config.put("clientAuthMethod", "client_secret_post");
        config.put("issuer", idpBaseUrl);
        config.put("authorizationUrl", idpBaseUrl + "/authorize");
        config.put("tokenUrl", idpBaseUrl + "/token");
        config.put("jwksUrl", idpBaseUrl + "/jwks");
        config.put("userInfoUrl", idpBaseUrl + "/userinfo");
        config.put("useJwksUrl", "true");
        config.put("validateSignature", "true");
        config.put("syncMode", "FORCE");

        Map<String, Object> idp = new LinkedHashMap<>();
        idp.put("alias", alias);
        idp.put("providerId", "oidc");
        idp.put("enabled", true);
        // Skip the "Review Profile" screen so the redirect chain never stops on
        // an interactive page.
        idp.put("firstBrokerLoginFlowAlias", "");
        idp.put("config", config);

        post("/admin/realms/" + realm + "/identity-provider/instances", idp);
    }

    /**
     * Attaches the mapper under test to the identity provider.
     *
     * @param overrideGroupPath the {@code override_group_path} config, or {@code null} to leave it
     *     unset so the mapper falls back to the IdP alias
     */
    public void createGroupMapper(
            String realm, String alias, String groupClaim, String overrideGroupPath)
            throws IOException, InterruptedException {

        Map<String, String> config = new LinkedHashMap<>();
        config.put("syncMode", "INHERIT");
        config.put("group_claim", groupClaim);
        if (overrideGroupPath != null) {
            config.put("override_group_path", overrideGroupPath);
        }

        Map<String, Object> mapper = new LinkedHashMap<>();
        mapper.put("name", "groups");
        mapper.put("identityProviderAlias", alias);
        mapper.put("identityProviderMapper", "oidc-groups-mapper");
        mapper.put("config", config);

        post(
                "/admin/realms/" + realm + "/identity-provider/instances/" + alias + "/mappers",
                mapper);
    }

    /** Creates the public client the test uses to trigger a login. */
    public void createPublicClient(String realm, String clientId, String redirectUri)
            throws IOException, InterruptedException {

        Map<String, Object> client = new LinkedHashMap<>();
        client.put("clientId", clientId);
        client.put("enabled", true);
        client.put("publicClient", true);
        client.put("standardFlowEnabled", true);
        client.put("redirectUris", List.of(redirectUri));
        client.put("webOrigins", List.of("*"));

        post("/admin/realms/" + realm + "/clients", client);
    }

    public String findUserId(String realm, String username)
            throws IOException, InterruptedException {
        JsonNode users =
                get(
                        "/admin/realms/"
                                + realm
                                + "/users?exact=true&username="
                                + URLEncoder.encode(username, StandardCharsets.UTF_8));
        return users.isEmpty() ? null : users.get(0).get("id").asText();
    }

    /** The full paths of the groups the user belongs to, e.g. {@code /parent-group/group1}. */
    public List<String> findUserGroupPaths(String realm, String username)
            throws IOException, InterruptedException {
        String userId = findUserId(realm, username);
        if (userId == null) {
            throw new IOException("No user named " + username + " in realm " + realm);
        }

        List<String> paths = new ArrayList<>();
        get("/admin/realms/" + realm + "/users/" + userId + "/groups")
                .forEach(group -> paths.add(group.get("path").asText()));
        return paths;
    }

    /** Puts the user in a group by path, used to set up state a login should not touch. */
    public void joinGroupByPath(String realm, String username, String groupPath)
            throws IOException, InterruptedException {

        String userId = findUserId(realm, username);
        String groupId = null;
        for (JsonNode group :
                get("/admin/realms/" + realm + "/groups?populateHierarchy=false&max=1000")) {
            if (group.get("path").asText().equals(groupPath)) {
                groupId = group.get("id").asText();
                break;
            }
        }
        if (groupId == null) {
            groupId =
                    postForId(
                            "/admin/realms/" + realm + "/groups",
                            Map.of("name", groupPath.substring(groupPath.lastIndexOf('/') + 1)));
        }
        send("PUT", "/admin/realms/" + realm + "/users/" + userId + "/groups/" + groupId, null);
    }
}
