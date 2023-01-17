package com.dotcms.osgi.oauth.viewtool;

import com.dotcms.osgi.oauth.app.velocity.DotVelocitySecretAppConfig;
import com.dotcms.osgi.oauth.provider.MicrosoftAzureActiveDirectoryApi;
import com.dotcms.osgi.oauth.viewtool.cache.BlockDirectiveCache;
import com.dotcms.osgi.oauth.viewtool.cache.BlockDirectiveCacheImpl;
import com.dotcms.osgi.oauth.viewtool.cache.DotCacheTool;
import com.dotcms.rendering.velocity.viewtools.JSONTool;
import com.dotcms.util.CollectionsUtils;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UtilMethods;
import com.liferay.util.StringPool;
import io.vavr.Function0;
import io.vavr.Lazy;
import org.apache.velocity.tools.view.tools.ViewTool;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class ADFSTool implements ViewTool {

	final Lazy<BlockDirectiveCache> cache;
	private static final int TIMEOUT = Config.getIntProperty("URL_CONNECTION_TIMEOUT", 5000);
	private static final int CACHE_TTL = Config.getIntProperty("VELOCITY_CACHE_TOKEN_TTL", 1800);
	private static final String API_ACCESS_TOKEN_KEY = Config.getStringProperty("VELOCITY_ADFS_API_ACCESS_TOKEN_KEY", "apiAccessToken");
	private static final String CONFIG_PREFIX = "adfs_";
	private final JSONTool jsonTool = new JSONTool();

	public ADFSTool() {
		this.cache = Lazy.of(Function0.of(BlockDirectiveCacheImpl::new));
		cache.get();
	}

	@Override
	public void init(Object initData) {
	}

	public String getAccessToken (final HttpServletRequest request) {

		return getAccessToken (request, TIMEOUT, CACHE_TTL);
	}
	public String getAccessToken (final HttpServletRequest request, final int timeout, final int cacheTTL) {

		final Map<String, Serializable> cacheEntry = this.cache.get().get(DotCacheTool.DOT_CACHE_PREFIX + API_ACCESS_TOKEN_KEY);
		String accessToken = (String)cacheEntry.get(API_ACCESS_TOKEN_KEY);
		if (!UtilMethods.isSet(accessToken)) {

			final Optional<DotVelocitySecretAppConfig> config = DotVelocitySecretAppConfig.config(request);

			if (config.isPresent()) {

				accessToken = this.getAccessToken(config, timeout, cacheTTL);
			}
		}

		return accessToken;
	}

	private String getAccessToken (final Optional<DotVelocitySecretAppConfig> config, final int timeout, int cacheTTL) {

		String accessToken = null;

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
				final Map resultMap = (Map) jsonTool.post(url, timeout, headers, bodyRaw);
				accessToken = (String)resultMap.get("access_token");
				if (UtilMethods.isSet(accessToken)) {

					if (cacheTTL <= 0) {
						cache.get().remove(DotCacheTool.DOT_CACHE_PREFIX + API_ACCESS_TOKEN_KEY);
						return accessToken;
					}

					final Map<String, Serializable> map = CollectionsUtils.map(API_ACCESS_TOKEN_KEY, accessToken);
					cache.get().add(DotCacheTool.DOT_CACHE_PREFIX + API_ACCESS_TOKEN_KEY, map, cacheTTL);
				}
			}
		}catch (Exception e) {

			Logger.error(this, e.getMessage(), e);
		}

		return accessToken;
	}
}
