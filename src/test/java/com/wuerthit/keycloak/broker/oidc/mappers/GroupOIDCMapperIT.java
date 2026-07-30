package com.wuerthit.keycloak.broker.oidc.mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.wuerthit.keycloak.broker.oidc.mappers.support.BrokeredLogin;
import com.wuerthit.keycloak.broker.oidc.mappers.support.KeycloakAdminApi;
import com.wuerthit.keycloak.broker.oidc.mappers.support.MockOidcProvider;
import java.io.File;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * Integration tests for the mapper against a real Keycloak.
 *
 * <p>Everything the test needs runs locally: a Keycloak container with the packaged jar dropped
 * into {@code /opt/keycloak/providers}, and an in-JVM mock identity provider. There is no NetEye,
 * no Icingaweb2 and no browser — the mapper's contract is the group membership it produces in
 * Keycloak, and that is what is asserted here.
 *
 * <p>Keycloak is started once for the whole class; each test gets its own realm so the cases cannot
 * contaminate one another.
 */
class GroupOIDCMapperIT {

    private static final String KEYCLOAK_IMAGE =
            "quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version", "26.6.2");
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "admin";
    private static final String IDP_ALIAS = "neteye-test-oidc";
    private static final String USERNAME = "test-user";

    private static GenericContainer<?> keycloak;
    private static MockOidcProvider idp;
    private static KeycloakAdminApi admin;
    private static BrokeredLogin login;

    /** Realm of the test currently running; dropped afterwards. */
    private String realm;

    @BeforeAll
    static void startFixture() throws Exception {
        idp = new MockOidcProvider();

        // Keycloak calls the identity provider from inside its container, and
        // the issuer must be identical on both sides, so both use the address
        // Testcontainers exposes; MockOidcProvider maps it back to localhost
        // for the calls the test JVM makes itself.
        Testcontainers.exposeHostPorts(idp.port());
        idp.setBaseUrl("http://host.testcontainers.internal:" + idp.port());

        File mapperJar = new File(System.getProperty("mapper.jar"));
        assertTrue(
                mapperJar.isFile(),
                "The mapper jar is missing at " + mapperJar + "; run `mvn verify`, not `mvn test`");

        keycloak =
                new GenericContainer<>(KEYCLOAK_IMAGE)
                        .withCopyFileToContainer(
                                MountableFile.forHostPath(mapperJar.toPath()),
                                "/opt/keycloak/providers/keycloak-oidc-group-mapper.jar")
                        .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USERNAME)
                        .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
                        .withEnv("KC_HOSTNAME_STRICT", "false")
                        .withEnv("KC_HTTP_ENABLED", "true")
                        .withCommand("start-dev")
                        .withExposedPorts(8080)
                        .waitingFor(Wait.forHttp("/realms/master").forPort(8080).forStatusCode(200))
                        .withStartupTimeout(Duration.ofMinutes(3));
        keycloak.start();

        String keycloakBaseUrl =
                "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        admin = new KeycloakAdminApi(keycloakBaseUrl, ADMIN_USERNAME, ADMIN_PASSWORD);
        login = new BrokeredLogin(keycloakBaseUrl, idp);
    }

    @AfterAll
    static void stopFixture() {
        if (keycloak != null) {
            keycloak.stop();
        }
        if (idp != null) {
            idp.close();
        }
    }

    @AfterEach
    void dropRealm() throws Exception {
        if (realm != null) {
            admin.deleteRealm(realm);
            realm = null;
        }
    }

    /**
     * Builds an isolated realm wired to the mock provider.
     *
     * <p>The realm name doubles as the OIDC client_id at the mock, which is how a single mock
     * instance can serve every test with different claims.
     *
     * @param groupsClaim value of the groups claim, or {@code null} to omit it
     */
    private void givenRealm(TestInfo testInfo, Object groupsClaim, String overrideGroupPath)
            throws Exception {
        realm = testInfo.getTestMethod().orElseThrow().getName().toLowerCase(Locale.ROOT);

        idp.registerClient(realm, USERNAME, groupsClaim);
        admin.createRealm(realm);
        admin.createIdentityProvider(realm, IDP_ALIAS, realm, idp.baseUrl());
        admin.createGroupMapper(realm, IDP_ALIAS, "groups", overrideGroupPath);
        admin.createPublicClient(realm, "test-client", BrokeredLogin.REDIRECT_URI);
    }

    private void whenUserLogsIn() throws Exception {
        login.login(realm, "test-client", IDP_ALIAS);
    }

    private List<String> userGroupPaths() throws Exception {
        List<String> paths = admin.findUserGroupPaths(realm, USERNAME);
        paths.sort(String::compareTo);
        return paths;
    }

    @Test
    @DisplayName("A first login creates the claimed groups under the parent path and joins them")
    void firstLoginCreatesAndJoinsTheClaimedGroups(TestInfo testInfo) throws Exception {
        givenRealm(testInfo, List.of("group1", "group2"), "/parent-group");

        whenUserLogsIn();

        assertIterableEquals(
                List.of("/parent-group/group1", "/parent-group/group2"), userGroupPaths());
    }

    @Test
    @DisplayName("A slash inside a claimed group name is flattened, not read as nesting")
    void aSlashInTheGroupNameIsFlattened(TestInfo testInfo) throws Exception {
        givenRealm(testInfo, List.of("team/sub"), "/parent-group");

        whenUserLogsIn();

        assertIterableEquals(List.of("/parent-group/team-sub"), userGroupPaths());
    }

    @Test
    @DisplayName("Without override_group_path the IdP alias is used as the parent path")
    void withoutAnOverrideTheIdpAliasIsTheParentPath(TestInfo testInfo) throws Exception {
        givenRealm(testInfo, List.of("group1"), null);

        whenUserLogsIn();

        assertIterableEquals(List.of("/" + IDP_ALIAS + "/group1"), userGroupPaths());
    }

    @Test
    @DisplayName("A missing groups claim leaves the user without groups but still logs them in")
    void aMissingClaimLeavesTheUserWithoutGroups(TestInfo testInfo) throws Exception {
        givenRealm(testInfo, null, "/parent-group");

        whenUserLogsIn();

        assertEquals(List.of(), userGroupPaths());
    }

    /**
     * {@code updateBrokeredUser} re-syncs only the memberships below the parent path it manages: a
     * group the token no longer claims is dropped, while a group assigned elsewhere (by an
     * administrator, by another mapper) survives the login.
     */
    @Test
    @DisplayName("A re-login re-syncs the claimed groups and keeps unrelated memberships")
    void aReloginResyncsGroupsAndKeepsUnrelatedMemberships(TestInfo testInfo) throws Exception {
        givenRealm(testInfo, List.of("group1"), "/parent-group");
        whenUserLogsIn();
        assertIterableEquals(List.of("/parent-group/group1"), userGroupPaths());

        // A membership this mapper does not manage, plus a change upstream.
        admin.joinGroupByPath(realm, USERNAME, "/manually-assigned");
        idp.registerClient(realm, USERNAME, List.of("group2"));

        whenUserLogsIn();

        assertIterableEquals(
                List.of("/manually-assigned", "/parent-group/group2"), userGroupPaths());
    }
}
