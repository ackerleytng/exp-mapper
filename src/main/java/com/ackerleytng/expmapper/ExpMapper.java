package com.ackerleytng.expmapper;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import static org.keycloak.common.util.Time.currentTime;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ExpMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    private static final Logger LOG = Logger.getLogger(ExpMapper.class);
    public static final List<ProviderConfigProperty> configProperties =
            new ArrayList<ProviderConfigProperty>();
    private static final String CONFIG_PARAM_VALIDITY = "validity";

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(CONFIG_PARAM_VALIDITY);
        property.setLabel("Validity period (days)");
        property.setHelpText(
                "Validity period you want to use, to set expiration time (exp) on a token. " +
                "Defaults to 1 day if Integer.parseInt() throws an exception on parsing input");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
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
        return "Overridden validity period (exp)";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Override exp in token with new expiration time (now + validity period)";
    }

    private int parseValidity(String validity) {
        try {
            return Integer.parseInt(validity);
        } catch (NumberFormatException e) {
            return 1;
        }
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token,
                                            ProtocolMapperModel mappingModel,
                                            KeycloakSession session,
                                            UserSessionModel userSession,
                                            ClientSessionContext clientSessionCtx) {
        int days = parseValidity(mappingModel.getConfig().get(CONFIG_PARAM_VALIDITY));
        long override = currentTime() + days * 86400;
        token.exp(override);

        LOG.infof("Overrode exp to %d", override);
        return token;
    }

    @Override
    public IDToken transformIDToken(IDToken token,
                                    ProtocolMapperModel mappingModel,
                                    KeycloakSession session,
                                    UserSessionModel userSession,
                                    ClientSessionContext clientSessionCtx) {
        int days = parseValidity(mappingModel.getConfig().get(CONFIG_PARAM_VALIDITY));
        long override = currentTime() + days * 86400;
        token.exp(override);

        LOG.infof("Overrode exp to %d", override);
        return token;
    }

    public static ProtocolMapperModel create(String name, String validity) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<String, String>();
        config.put(CONFIG_PARAM_VALIDITY, validity);
        mapper.setConfig(config);

        LOG.infof("Set config for ExpMapper, %s = %s", CONFIG_PARAM_VALIDITY, validity);
        return mapper;
    }
}
