package com.dotcms.osgi.oauth.viewtool;

import com.dotcms.api.vtl.model.DotJSON;
import com.dotcms.osgi.oauth.app.velocity.DotVelocitySecretAppConfig;
import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;

import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.dotcms.rendering.engine.ScriptEngine;
import com.dotcms.rendering.engine.ScriptEngineFactory;
import com.dotcms.util.CollectionsUtils;
import com.dotmarketing.util.Logger;
import com.liferay.util.StringPool;
import org.apache.velocity.tools.view.tools.ViewTool;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuthTool implements ViewTool {

	private final String NOTSET="xxxxxx";

	@Override
	public void init(Object initData) {
	}

	public List<String> getProviders() {

		java.util.List<String> providers = new ArrayList<>();

		String google = OAuthPropertyBundle.getProperty("Google20Api_API_KEY", NOTSET);
		String facebook = OAuthPropertyBundle.getProperty("Facebook20Api_API_KEY", NOTSET);
		String okta = OAuthPropertyBundle.getProperty("Okta20Api_API_KEY", NOTSET);
		String ping = OAuthPropertyBundle.getProperty("Ping20Api_API_KEY", NOTSET);

		if(!NOTSET.equals(google)){
			providers.add(google);
		}

		if(!NOTSET.equals(facebook)){
			providers.add(facebook);
		}

		if (!NOTSET.equals(okta)) {
			providers.add(okta);
		}

		if (!NOTSET.equals(ping)) {
			providers.add(ping);
		}

		return providers;
	}

	public String getAccessToken (final String configPrefix,
								  final HttpServletRequest request,
								  final HttpServletResponse response) {

		String accessToken = null;

		final Optional<DotVelocitySecretAppConfig> config = DotVelocitySecretAppConfig.config(request);
		if (config.isPresent()) {

			Logger.debug(this.getClass().getName(), ()-> "Getting the access token from config: " + config.get().title +
					" with prefix: " + configPrefix);

			final Map<String, Object> configMap = config.get().extraParameters.entrySet().stream().filter(
					entry -> entry.getKey().startsWith(configPrefix))
					.collect(Collectors.toMap(entry-> entry.getKey().replace(configPrefix, StringPool.BLANK), entry-> entry.getValue()));

			if (!configMap.isEmpty()) {

				final ScriptEngine engine = ScriptEngineFactory.getInstance().getEngine("Velocity");
				final String code   = (String)configMap.get("code");
				final Reader reader = new StringReader(code);
				final Map<String, Object> resultMap = (Map<String, Object>)engine.eval(request, response, reader, configMap);
				final DotJSON dotJSON = (DotJSON) resultMap.get("dotJSON");
				accessToken = (String)dotJSON.get("apiAccessToken");
			}
		}

		return accessToken;
	}
}
