package com.dotcms.osgi.oauth.viewtool;

import com.dotcms.osgi.oauth.app.velocity.DotVelocitySecretAppConfig;
import com.dotcms.osgi.oauth.provider.MicrosoftAzureActiveDirectoryApi;
import com.dotcms.rendering.velocity.viewtools.JSONTool;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import com.liferay.util.StringPool;
import org.apache.velocity.tools.view.tools.ViewTool;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class ADFSTool implements ViewTool {

	private static final int TIMEOUT = Config.getIntProperty("URL_CONNECTION_TIMEOUT", 5000);
	private static final String CONFIG_PREFIX = "adfs_";
	private final JSONTool jsonTool = new JSONTool();
	@Override
	public void init(Object initData) {
	}

	public String getAccessToken (final HttpServletRequest request) {

		String accessToken = null;
		final Optional<DotVelocitySecretAppConfig> config = DotVelocitySecretAppConfig.config(request);

		if (config.isPresent()) {

			try {
				Logger.debug(this.getClass().getName(), ()-> "Getting the access token from config: " + config.get().title +
						" with prefix: " + CONFIG_PREFIX);

				final Map<String, Object> configMap = config.get().extraParameters.entrySet().stream().filter(
						entry -> entry.getKey().startsWith(CONFIG_PREFIX))
						.collect(Collectors.toMap(entry-> entry.getKey().replace(CONFIG_PREFIX, StringPool.BLANK), entry-> entry.getValue()));

				if (!configMap.isEmpty()) {

					final String endpoint     = (String)configMap.get("endpoint");
					final String grantType    = (String)configMap.get("grant_type");
					final String scope        = (String)configMap.get("scope");
					final String clientId     = (String)configMap.get("client_id");
					final String clientSecret = (String)configMap.get("client_secret");
					final String url 		  = MicrosoftAzureActiveDirectoryApi.MSFT_ENDPOINT + "/" + endpoint;

					final Map<String, String> headers = new HashMap<>();
					headers.put("Accept", "application/json");
					headers.put("Content-Type", "application/x-www-form-urlencoded");

					// final String bodyRaw = "grant_type=${grant_type}&scope=${scope}&client_id=${client_id}&client_secret=${client_secret}";
					final String bodyRaw = "grant_type="+grantType+"&scope="+scope+"&client_id="+clientId+"&client_secret="+clientSecret;
					final Map resultMap = (Map) jsonTool.post(url, TIMEOUT, headers, bodyRaw);
					accessToken = (String)resultMap.get("access_token");
				}
			}catch (Exception e) {

				Logger.error(this, e.getMessage(), e);
			}
		}

		return accessToken;
	}
}
