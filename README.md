# Keycloak OIDC Groups Mapper

A Keycloak identity provider mapper that turns a groups claim from an upstream
OIDC provider into real Keycloak groups, nested under a parent path so groups
from different providers cannot collide: two providers both emitting `admins`
become `/provider-a/admins` and `/provider-b/admins` instead of one shared
group.

Packaged as a jar that you drop into Keycloak's `providers` directory.

## Build and test

```sh
mvn clean package   # jar in target/
mvn test            # unit tests, no containers, seconds
mvn verify          # also integration tests, needs a container runtime
```

Requires Java 21. `mvn verify` starts a real Keycloak via Testcontainers, so it
needs Docker or Podman available; `mvn test` does not.

Without a local JDK, `scripts/test.sh` takes the same goals and runs Maven in a
container, handing it the host's container socket so the integration tests
still work. It uses local Maven when there is one, so it is safe to use either
way — the pre-commit formatting hook goes through it for that reason.

```sh
scripts/test.sh                  # clean verify
scripts/test.sh test             # unit tests only
scripts/test.sh spotless:apply   # fix formatting
```

## Layout

```text
src/main/java/.../mappers/
  GroupOIDCMapper.java          the SPI: importNewUser / updateBrokeredUser
  GroupOIDCMapperUtil.java      path building and group creation
  GroupOIDCMapperConstant.java  config property names
src/main/resources/META-INF/services/
  org.keycloak.broker.provider.IdentityProviderMapper   <- registers the SPI

src/test/java/.../mappers/
  GroupOIDCMapperUtilTest.java  unit tests on the path logic
  GroupOIDCMapperIT.java        integration tests against a real Keycloak
  support/                      mock OIDC provider, admin API, login driver
```

Adding a config property means touching `GroupOIDCMapperConstant` and the
static block in `GroupOIDCMapper` that builds `mapperConfigProperties`.

## Releasing

To release, update `<version>` in `pom.xml` and merge the change to `main`. The
workflow reads that version. If a GitHub Release for `vX.Y.Z` already exists,
the workflow does nothing. Otherwise it builds the jar, retains an existing tag
or creates a missing one, then creates the GitHub Release.
Keycloak itself is pinned by the `keycloak.version` property, which drives both
the compile dependencies and the container image the tests run against.

## License

Dual-licensed under [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option. Security issues: [SECURITY.md](SECURITY.md).
