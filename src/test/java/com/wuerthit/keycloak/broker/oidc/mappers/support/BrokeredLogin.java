package com.wuerthit.keycloak.broker.oidc.mappers.support;

import java.io.IOException;
import java.net.CookieHandler;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Drives a full brokered login by following the redirect chain by hand.
 *
 * <p>No browser is involved: the mock identity provider redirects straight back with an
 * authorization code, so every hop in the flow is a 302 that an HTTP client can follow — as long as
 * it keeps the Keycloak session cookies, which is why redirects are followed manually rather than
 * by the client's built-in policy.
 */
public class BrokeredLogin {

    /** Where the flow is expected to land; never actually served. */
    public static final String REDIRECT_URI = "http://localhost:9999/callback";

    private static final int MAX_HOPS = 12;

    private final String keycloakBaseUrl;
    private final MockOidcProvider idp;

    public BrokeredLogin(String keycloakBaseUrl, MockOidcProvider idp) {
        this.keycloakBaseUrl = keycloakBaseUrl;
        this.idp = idp;
    }

    /**
     * Logs in through the given identity provider and returns once Keycloak has issued its
     * authorization code — by which point the mapper has already run.
     *
     * @throws AssertionError if the chain stops on a Keycloak page instead of reaching the redirect
     *     URI; the page body is included, because a flow that silently stalls on an interactive
     *     screen is otherwise very hard to debug
     */
    public void login(String realm, String clientId, String idpAlias)
            throws IOException, InterruptedException {
        HttpClient http =
                HttpClient.newBuilder()
                        .cookieHandler(new PlainCookieJar())
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build();

        URI next =
                URI.create(
                        keycloakBaseUrl
                                + "/realms/"
                                + realm
                                + "/protocol/openid-connect/auth"
                                + "?client_id="
                                + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                                + "&redirect_uri="
                                + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                                + "&response_type=code"
                                + "&scope=openid"
                                + "&state="
                                + UUID.randomUUID()
                                + "&kc_idp_hint="
                                + URLEncoder.encode(idpAlias, StandardCharsets.UTF_8));

        for (int hop = 0; hop < MAX_HOPS; hop++) {
            URI current = next;
            HttpResponse<String> response =
                    http.send(
                            HttpRequest.newBuilder(idp.toLocalAddress(current)).GET().build(),
                            HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() / 100 != 3) {
                throw new AssertionError(
                        "The login flow stopped at "
                                + current
                                + " with HTTP "
                                + response.statusCode()
                                + " instead of reaching "
                                + REDIRECT_URI
                                + ". Body:\n"
                                + response.body());
            }

            String location =
                    response.headers()
                            .firstValue("Location")
                            .orElseThrow(
                                    () ->
                                            new AssertionError(
                                                    "Redirect without a Location header at "
                                                            + current));

            if (location.startsWith(REDIRECT_URI)) {
                if (location.contains("error=")) {
                    throw new AssertionError("The login flow failed: " + location);
                }
                return;
            }

            next = URI.create(location);
        }

        throw new AssertionError("The login flow did not settle within " + MAX_HOPS + " redirects");
    }

    /**
     * A cookie jar that keeps every cookie and replays it on every request, ignoring the attributes
     * entirely.
     *
     * <p>{@code CookieManager} cannot be used here: Keycloak marks {@code KC_RESTART} as {@code
     * Secure; SameSite=None}, and a secure cookie is never sent back over the plain HTTP the
     * container is reached on, so the flow dies on "Restart login cookie not found". Ignoring the
     * attributes is safe because this client only ever talks to one host.
     */
    private static class PlainCookieJar extends CookieHandler {

        private final Map<String, String> cookies = new LinkedHashMap<>();

        @Override
        public void put(URI uri, Map<String, List<String>> responseHeaders) {
            responseHeaders.forEach(
                    (header, values) -> {
                        if (header == null || !header.equalsIgnoreCase("Set-Cookie")) {
                            return;
                        }
                        for (String value : values) {
                            String pair = value.split(";", 2)[0];
                            int split = pair.indexOf('=');
                            if (split < 0) {
                                continue;
                            }
                            String name = pair.substring(0, split).trim();
                            String content = pair.substring(split + 1).trim();
                            // Keycloak clears a cookie by sending it back empty.
                            if (content.isEmpty()) {
                                cookies.remove(name);
                            } else {
                                cookies.put(name, content);
                            }
                        }
                    });
        }

        @Override
        public Map<String, List<String>> get(URI uri, Map<String, List<String>> requestHeaders) {
            if (cookies.isEmpty()) {
                return Map.of();
            }
            String header =
                    cookies.entrySet().stream()
                            .map(cookie -> cookie.getKey() + "=" + cookie.getValue())
                            .collect(Collectors.joining("; "));
            return Map.of("Cookie", List.of(header));
        }
    }
}
