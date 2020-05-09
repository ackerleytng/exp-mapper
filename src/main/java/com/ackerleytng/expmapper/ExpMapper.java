package com.ackerleytng.expmapper;

import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ExpMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    private static final Logger LOG = Logger.getLogger(ExpMapper.class);
    public static final List<ProviderConfigProperty> configProperties =
            new ArrayList<ProviderConfigProperty>();
    private static final String CONFIG_PARAM_EXTENSION = "extension";
    private static final String CONFIG_PARAM_CLIENT = "client";

    static {
        ProviderConfigProperty extensionProperty;
        extensionProperty = new ProviderConfigProperty();
        extensionProperty.setName(CONFIG_PARAM_EXTENSION);
        extensionProperty.setLabel("Expiration time extension (days)");
        extensionProperty.setHelpText(
                "Expiration time extension to add to the original expiration time (exp) on a token. " +
                "Defaults to 1 day if Integer.parseInt() throws an exception on parsing input");
        extensionProperty.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(extensionProperty);

        ProviderConfigProperty clientProperty;
        clientProperty = new ProviderConfigProperty();
        clientProperty.setName(CONFIG_PARAM_CLIENT);
        clientProperty.setLabel("Permitted client");
        clientProperty.setHelpText("Only apply extension of expiration time for this client");
        clientProperty.setType(ProviderConfigProperty.CLIENT_LIST_TYPE);
        configProperties.add(clientProperty);
    }

    public static final String PROVIDER_ID = "oidc-exp-mapper";

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Expiration time (exp) extension (days)";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Override exp in token with new expiration time (exp + extension)";
    }

    private int parseExtension(String extension) {
        try {
            return Integer.parseInt(extension);
        } catch (NumberFormatException e) {
            return 1;
        }
    }

    private IDToken extend(IDToken token, ClientModel client, ProtocolMapperModel mappingModel) {
        String permittedClientName = mappingModel.getConfig().get(CONFIG_PARAM_CLIENT);

        // Only extend expiry for tokens from the permitted client
        if (!permittedClientName.equals(client.getName())) {
            LOG.infof("Client %s not permitted, needed %s", client.getName(), permittedClientName);
            return token;
        }

        int days = parseExtension(mappingModel.getConfig().get(CONFIG_PARAM_EXTENSION));
        long override = token.getExp() + days * 86400;
        token.exp(override);

        LOG.infof("Overrode exp in %s to %d", token.getClass().getName(), override);
        return token;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token,
                                            ProtocolMapperModel mappingModel,
                                            KeycloakSession session,
                                            UserSessionModel userSession,
                                            ClientSessionContext clientSessionCtx) {
        return (AccessToken) extend(token, session.getContext().getClient(), mappingModel);
    }

    @Override
    public IDToken transformIDToken(IDToken token,
                                    ProtocolMapperModel mappingModel,
                                    KeycloakSession session,
                                    UserSessionModel userSession,
                                    ClientSessionContext clientSessionCtx) {
        return extend(token, session.getContext().getClient(), mappingModel);
    }

    public static ProtocolMapperModel create(String name, String extension, String client) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<String, String>();
        config.put(CONFIG_PARAM_EXTENSION, extension);
        config.put(CONFIG_PARAM_CLIENT, client);
        mapper.setConfig(config);

        LOG.infof("ExpMapper (%s) %s = %s", name, CONFIG_PARAM_EXTENSION, extension);
        LOG.infof("ExpMapper (%s) %s = %s", name, CONFIG_PARAM_CLIENT, client);
        return mapper;
    }
}
