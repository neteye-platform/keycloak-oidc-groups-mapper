package com.wuerthit.keycloak.broker.oidc.mappers;

import java.util.ArrayList;
import java.util.Map;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;

public class GroupOIDCMapperUtil {

    private Map<String, String> config;
    private KeycloakSession session;
    private RealmModel realm;
    private String normalizedParentGroupPath;

    public GroupOIDCMapperUtil(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            String idpAlias) {
        this.session = session;
        this.realm = realm;
        this.config = mapperModel.getConfig();

        String override_base_group =
                config.get(GroupOIDCMapperConstant.OVERRIDE_BASE_GROUP_PATH_PROPERTY);

        // Determine parent group path
        String parentGroupPath;
        if (override_base_group == null || override_base_group.isEmpty()) {
            parentGroupPath = idpAlias;
        } else {
            parentGroupPath = override_base_group.trim();
        }

        this.normalizedParentGroupPath = normalizeGroupPath(parentGroupPath);
    }

    private static GroupModel getOrRecursevlyCreateGroupByPath(
            KeycloakSession session, RealmModel realm, String groupPath) {
        if (groupPath == null || groupPath.isEmpty()) {
            return null;
        }

        GroupModel group = KeycloakModelUtils.findGroupByPath(session, realm, groupPath);
        if (group != null) {
            return group;
        }

        String parentPath = groupPath.substring(0, groupPath.lastIndexOf('/'));
        String groupName = groupPath.substring(groupPath.lastIndexOf('/') + 1);

        GroupModel parentGroup = getOrRecursevlyCreateGroupByPath(session, realm, parentPath);
        return session.groups().createGroup(realm, groupName, parentGroup);
    }

    public ArrayList<GroupModel> createGroupsIfNotExist(ArrayList<String> oidcGroupsNames) {
        ArrayList<GroupModel> res = new ArrayList<GroupModel>();

        for (String groupName : oidcGroupsNames) {
            String safeGroupName = sanitizeGroupName(groupName);
            res.add(
                    getOrRecursevlyCreateGroupByPath(
                            session,
                            realm,
                            joinGroupPaths(normalizedParentGroupPath, safeGroupName)));
        }

        return res;
    }

    /**
     * Tells whether a group lives below the parent path this mapper manages. Memberships outside of
     * it belong to somebody else (an administrator, another mapper) and must be left alone.
     */
    public boolean isManagedGroup(GroupModel group) {
        if (group == null || normalizedParentGroupPath == null) {
            return false;
        }

        return buildGroupPath(group).startsWith(normalizedParentGroupPath + "/");
    }

    static String buildGroupPath(GroupModel group) {
        StringBuilder path = new StringBuilder();

        for (GroupModel current = group; current != null; current = current.getParent()) {
            path.insert(0, current.getName()).insert(0, '/');
        }

        return path.toString();
    }

    /**
     * A group name coming from the token is a single path segment, so any slash it contains would
     * otherwise be read as a nesting level.
     */
    static String sanitizeGroupName(String groupName) {
        return groupName.replace('/', '-');
    }

    static String normalizeGroupPath(String groupPath) {
        if (groupPath == null || groupPath.isEmpty()) {
            return null;
        }

        if (!groupPath.startsWith("/")) {
            groupPath = "/" + groupPath;
        }
        if (groupPath.endsWith("/")) {
            groupPath = groupPath.substring(0, groupPath.length() - 1);
        }

        return groupPath;
    }

    static String joinGroupPaths(String basePath, String groupPath) {
        if (basePath == null || basePath.isEmpty()) {
            return normalizeGroupPath(groupPath);
        }
        if (groupPath == null || groupPath.isEmpty()) {
            return normalizeGroupPath(basePath);
        }

        return normalizeGroupPath(basePath + "/" + groupPath);
    }
}
