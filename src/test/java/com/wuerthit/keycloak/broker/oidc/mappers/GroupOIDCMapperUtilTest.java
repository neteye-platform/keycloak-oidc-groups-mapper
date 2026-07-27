package com.wuerthit.keycloak.broker.oidc.mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the path handling of the mapper. These need no Keycloak instance and run in the
 * `test` phase; the behaviour that requires a real Keycloak lives in {@link GroupOIDCMapperIT}.
 */
class GroupOIDCMapperUtilTest {

    @Nested
    @DisplayName("normalizeGroupPath")
    class NormalizeGroupPath {

        @Test
        void addsTheLeadingSlash() {
            assertEquals("/parent-group", GroupOIDCMapperUtil.normalizeGroupPath("parent-group"));
        }

        @Test
        void keepsAnAlreadyLeadingSlash() {
            assertEquals("/parent-group", GroupOIDCMapperUtil.normalizeGroupPath("/parent-group"));
        }

        @Test
        void stripsTheTrailingSlash() {
            assertEquals("/parent-group", GroupOIDCMapperUtil.normalizeGroupPath("/parent-group/"));
        }

        @Test
        void normalizesBothEndsAtOnce() {
            assertEquals("/a/b/c", GroupOIDCMapperUtil.normalizeGroupPath("a/b/c/"));
        }

        @Test
        void leavesInnerSlashesUntouched() {
            assertEquals("/a/b/c/d", GroupOIDCMapperUtil.normalizeGroupPath("/a/b/c/d"));
        }

        @Test
        void returnsNullForNoPath() {
            assertNull(GroupOIDCMapperUtil.normalizeGroupPath(null));
            assertNull(GroupOIDCMapperUtil.normalizeGroupPath(""));
        }
    }

    @Nested
    @DisplayName("joinGroupPaths")
    class JoinGroupPaths {

        @Test
        void joinsBaseAndGroupWithASingleSlash() {
            assertEquals(
                    "/parent-group/group1",
                    GroupOIDCMapperUtil.joinGroupPaths("/parent-group", "group1"));
        }

        @Test
        void addsTheLeadingSlashToAnUnprefixedBase() {
            assertEquals(
                    "/parent-group/group1",
                    GroupOIDCMapperUtil.joinGroupPaths("parent-group", "group1"));
        }

        /**
         * Only the ends of the joined path are normalized, so a base that still carries a trailing
         * slash leaves a double slash behind. The mapper never gets there: the constructor
         * normalizes the parent path before it is ever joined, which is the invariant this test
         * records.
         */
        @Test
        void doesNotCollapseASlashLeftInTheMiddle() {
            assertEquals(
                    "/parent-group//group1",
                    GroupOIDCMapperUtil.joinGroupPaths("parent-group/", "group1"));
            assertEquals(
                    "/parent-group/group1",
                    GroupOIDCMapperUtil.joinGroupPaths(
                            GroupOIDCMapperUtil.normalizeGroupPath("parent-group/"), "group1"));
        }

        @Test
        void buildsDeeplyNestedPaths() {
            assertEquals("/a/b/c/d/e", GroupOIDCMapperUtil.joinGroupPaths("/a/b/c", "d/e"));
        }

        @Test
        void fallsBackToTheGroupWhenThereIsNoBase() {
            assertEquals("/group1", GroupOIDCMapperUtil.joinGroupPaths(null, "group1"));
            assertEquals("/group1", GroupOIDCMapperUtil.joinGroupPaths("", "group1"));
        }

        @Test
        void fallsBackToTheBaseWhenThereIsNoGroup() {
            assertEquals(
                    "/parent-group", GroupOIDCMapperUtil.joinGroupPaths("/parent-group", null));
            assertEquals("/parent-group", GroupOIDCMapperUtil.joinGroupPaths("/parent-group", ""));
        }
    }

    @Nested
    @DisplayName("sanitizeGroupName")
    class SanitizeGroupName {

        @Test
        void flattensSlashesSoTheNameStaysOneLevel() {
            assertEquals("team-sub", GroupOIDCMapperUtil.sanitizeGroupName("team/sub"));
            assertEquals("-a-b-", GroupOIDCMapperUtil.sanitizeGroupName("/a/b/"));
        }

        @Test
        void leavesAPlainNameAlone() {
            assertEquals("group1", GroupOIDCMapperUtil.sanitizeGroupName("group1"));
        }
    }
}
