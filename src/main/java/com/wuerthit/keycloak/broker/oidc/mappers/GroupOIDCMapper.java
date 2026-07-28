package com.wuerthit.keycloak.broker.oidc.mappers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

public class GroupOIDCMapper extends AbstractClaimMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {
        KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID
    };
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
            new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));
    private static final List<ProviderConfigProperty> mapperConfigProperties =
            new ArrayList<ProviderConfigProperty>();

    static {
        // Claim in the token that contains the groups
        ProviderConfigProperty claimsProperty = new ProviderConfigProperty();
        claimsProperty.setName(GroupOIDCMapperConstant.GROUP_CLAIM_NAME_PROPERTY);
        claimsProperty.setLabel("Claim for group array");
        claimsProperty.setType(ProviderConfigProperty.STRING_TYPE);
        claimsProperty.setDefaultValue(GroupOIDCMapperConstant.GROUP_CLAIM_NAME_DEFAULT);
        claimsProperty.setHelpText("The token's claim that contains the groups.");
        claimsProperty.setRequired(true);
        mapperConfigProperties.add(claimsProperty);

        // Path to the groups in the token. Note that this group must be created
        // if it does not exist.
        ProviderConfigProperty overrideGroupsPath = new ProviderConfigProperty();
        overrideGroupsPath.setName(GroupOIDCMapperConstant.OVERRIDE_BASE_GROUP_PATH_PROPERTY);
        overrideGroupsPath.setLabel("Override base groups path");
        overrideGroupsPath.setType(ProviderConfigProperty.STRING_TYPE);
        overrideGroupsPath.setRequired(false);
        overrideGroupsPath.setHelpText(
                "Override group suffix path for the imported groups. If not specified, the IdP alias will be used. Note that already imported groups will not be removed if this parameter is changed.");
        mapperConfigProperties.add(overrideGroupsPath);
    }

    public static final String PROVIDER_ID = "oidc-groups-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return mapperConfigProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Group Mapper";
    }

    @Override
    public String getDisplayType() {
        return "OIDC Group Path Mapper";
    }

    @Override
    public String getHelpText() {
        return "This mapper allow to map groups from a claim in the OIDC token to a full Keycloak group path in the realm.";
    }

    public void importNewUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        GroupOIDCMapperUtil factory =
                new GroupOIDCMapperUtil(
                        session, realm, mapperModel, context.getIdpConfig().getAlias());

        ArrayList<GroupModel> kcGroups =
                factory.createGroupsIfNotExist(getGroups(context, mapperModel));

        for (GroupModel kcGroup : kcGroups) {
            user.joinGroup(kcGroup);
        }
    }

    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        GroupOIDCMapperUtil factory =
                new GroupOIDCMapperUtil(
                        session, realm, mapperModel, context.getIdpConfig().getAlias());

        ArrayList<GroupModel> kcGroups =
                factory.createGroupsIfNotExist(getGroups(context, mapperModel));

        user.getGroupsStream().forEach(user::leaveGroup);

        for (GroupModel kcGroup : kcGroups) {
            user.joinGroup(kcGroup);
        }
    }

    private ArrayList<String> getGroups(
            BrokeredIdentityContext context, IdentityProviderMapperModel mapperModel) {
        Map<String, String> config = mapperModel.getConfig();
        String group_mapper = config.get(GroupOIDCMapperConstant.GROUP_CLAIM_NAME_PROPERTY);

        Object groups = getClaimValue(context, group_mapper);
        ArrayList<String> groupsString = new ArrayList<String>();

        if (groups instanceof ArrayList) {
            for (Object group : (ArrayList<?>) groups) {
                if (group instanceof String) {
                    groupsString.add((String) group);
                }
            }
        } else if (groups instanceof String) {
            groupsString.add((String) groups);
        }
        return groupsString;
    }
}
