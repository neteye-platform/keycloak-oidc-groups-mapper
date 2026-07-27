package com.wuerthit.keycloak.broker.oidc.mappers.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A minimal OIDC provider used as the upstream identity provider under test.
 *
 * <p>It replaces the Flask {@code test-oidc.py} that used to run as a systemd unit inside a NetEye
 * box: it runs in the test JVM, needs no external process, and lets each test decide exactly which
 * claims the id_token carries.
 *
 * <p>The {@code /authorize} endpoint redirects straight back with a code — no login form and no
 * consent screen — so the whole flow can be driven by an HTTP client rather than a browser.
 *
 * <p>State is keyed by {@code client_id}, so a single instance can serve every test realm at once:
 * {@link #registerClient} declares what a given client's user looks like.
 */
public class MockOidcProvider implements Closeable {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpServer server;
    private final RSAKey signingKey;
    private final RSASSASigner signer;

    /** client_id -> the claims the id_token should carry for that client. */
    private final Map<String, Map<String, Object>> clients = new ConcurrentHashMap<>();

    /** authorization code -> the pending authorization it was issued for. */
    private final Map<String, PendingAuthorization> codes = new ConcurrentHashMap<>();

    /**
     * The externally visible base URL. Keycloak runs in a container, so it must be an address that
     * resolves from inside one; the same URL is used as the issuer on both sides so the token
     * validation lines up.
     */
    private String baseUrl;

    private record PendingAuthorization(String clientId, String nonce) {}

    public MockOidcProvider() throws IOException {
        try {
            this.signingKey =
                    new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
            this.signer = new RSASSASigner(this.signingKey);
        } catch (Exception e) {
            throw new IOException("Could not generate the signing key", e);
        }

        this.server = HttpServer.create(new InetSocketAddress(0), 0);
        this.server.createContext("/.well-known/openid-configuration", this::openidConfiguration);
        this.server.createContext("/authorize", this::authorize);
        this.server.createContext("/token", this::token);
        this.server.createContext("/jwks", this::jwks);
        this.server.createContext("/userinfo", this::userinfo);
        this.server.start();

        this.baseUrl = "http://localhost:" + port();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public String baseUrl() {
        return baseUrl;
    }

    /** Overrides the advertised base URL, e.g. once the port is exposed to containers. */
    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Declares the user that logging in with {@code clientId} produces.
     *
     * <p>The profile claims are always filled in, because a brokered user missing a username or an
     * email sends Keycloak to the "Review Profile" page and stalls the redirect chain.
     *
     * @param groupsClaim the value of the groups claim, or {@code null} to omit the claim entirely
     */
    public void registerClient(String clientId, String username, Object groupsClaim) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", username);
        claims.put("preferred_username", username);
        claims.put("email", username + "@example.test");
        claims.put("email_verified", true);
        claims.put("given_name", "Test");
        claims.put("family_name", "User");
        if (groupsClaim != null) {
            claims.put("groups", groupsClaim);
        }
        clients.put(clientId, claims);
    }

    private void openidConfiguration(HttpExchange exchange) throws IOException {
        respondJson(
                exchange,
                200,
                Map.of(
                        "issuer",
                        baseUrl,
                        "authorization_endpoint",
                        baseUrl + "/authorize",
                        "token_endpoint",
                        baseUrl + "/token",
                        "userinfo_endpoint",
                        baseUrl + "/userinfo",
                        "jwks_uri",
                        baseUrl + "/jwks",
                        "response_types_supported",
                        List.of("code"),
                        "subject_types_supported",
                        List.of("public"),
                        "id_token_signing_alg_values_supported",
                        List.of("RS256"),
                        "scopes_supported",
                        List.of("openid", "profile", "email", "groups")));
    }

    private void authorize(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI().getRawQuery());

        String clientId = params.get("client_id");
        String state = params.get("state");
        String redirectUri = params.get("redirect_uri");
        if (clientId == null || state == null || redirectUri == null) {
            respondText(exchange, 400, "Missing client_id, state or redirect_uri");
            return;
        }
        if (!clients.containsKey(clientId)) {
            respondText(exchange, 400, "Unknown client_id: " + clientId);
            return;
        }

        String code = UUID.randomUUID().toString();
        codes.put(code, new PendingAuthorization(clientId, params.get("nonce")));

        String separator = redirectUri.contains("?") ? "&" : "?";
        exchange.getResponseHeaders()
                .add("Location", redirectUri + separator + "code=" + code + "&state=" + state);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    private void token(HttpExchange exchange) throws IOException {
        Map<String, String> form =
                parseQuery(
                        new String(
                                exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));

        // The code is single use, which also keeps a replay from silently succeeding.
        PendingAuthorization pending = codes.remove(form.get("code"));
        if (pending == null) {
            respondJson(exchange, 400, Map.of("error", "invalid_grant"));
            return;
        }

        String idToken;
        try {
            idToken = signIdToken(pending);
        } catch (Exception e) {
            throw new IOException("Could not sign the id_token", e);
        }

        // The access token doubles as the handle the /userinfo endpoint looks up.
        String accessToken = UUID.randomUUID().toString();
        codes.put(accessToken, pending);

        respondJson(
                exchange,
                200,
                Map.of(
                        "access_token",
                        accessToken,
                        "token_type",
                        "Bearer",
                        "expires_in",
                        300,
                        "id_token",
                        idToken));
    }

    private void userinfo(HttpExchange exchange) throws IOException {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        PendingAuthorization pending =
                authorization == null
                        ? null
                        : codes.get(authorization.replaceFirst("(?i)^Bearer ", ""));
        if (pending == null) {
            respondJson(exchange, 401, Map.of("error", "invalid_token"));
            return;
        }
        respondJson(exchange, 200, clients.get(pending.clientId()));
    }

    private void jwks(HttpExchange exchange) throws IOException {
        respondJson(
                exchange,
                200,
                Map.of(
                        "keys",
                        List.of(
                                JSON.readValue(
                                        signingKey.toPublicJWK().toJSONString(), Map.class))));
    }

    private String signIdToken(PendingAuthorization pending) throws Exception {
        long now = System.currentTimeMillis();

        JWTClaimsSet.Builder claims =
                new JWTClaimsSet.Builder()
                        .issuer(baseUrl)
                        .audience(pending.clientId())
                        .issueTime(new Date(now))
                        .expirationTime(new Date(now + 300_000));
        if (pending.nonce() != null) {
            claims.claim("nonce", pending.nonce());
        }
        clients.get(pending.clientId()).forEach(claims::claim);

        SignedJWT jwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID(signingKey.getKeyID())
                                .type(JOSEObjectType.JWT)
                                .build(),
                        claims.build());
        jwt.sign(signer);
        return jwt.serialize();
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> params = new HashMap<>();
        if (raw == null || raw.isEmpty()) {
            return params;
        }
        for (String pair : raw.split("&")) {
            int split = pair.indexOf('=');
            if (split < 0) {
                continue;
            }
            params.put(
                    URLDecoder.decode(pair.substring(0, split), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(split + 1), StandardCharsets.UTF_8));
        }
        return params;
    }

    private static void respondJson(HttpExchange exchange, int status, Object body)
            throws IOException {
        byte[] payload = JSON.writeValueAsBytes(body);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        exchange.getResponseBody().write(payload);
        exchange.close();
    }

    private static void respondText(HttpExchange exchange, int status, String body)
            throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain");
        exchange.sendResponseHeaders(status, payload.length);
        exchange.getResponseBody().write(payload);
        exchange.close();
    }

    /** Rewrites a URI so the test JVM can reach the address containers use. */
    public URI toLocalAddress(URI uri) {
        if (uri.getHost() == null || uri.getHost().equals("localhost")) {
            return uri;
        }
        if (!baseUrl.contains(uri.getHost())) {
            return uri;
        }
        return URI.create(uri.toString().replace(uri.getHost(), "localhost"));
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
