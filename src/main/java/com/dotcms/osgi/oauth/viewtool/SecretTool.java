package com.dotcms.osgi.oauth.viewtool;

import com.dotcms.osgi.oauth.app.velocity.DotVelocitySecretAppConfig;
import org.apache.velocity.tools.view.tools.ViewTool;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * This view tool expose the dot velocity secrets app to velocity
 * @author jsanca
 */
public class SecretTool implements ViewTool {

	@Override
	public void init(Object initData) {
	}

	public Object getSecret (final String key,
							 final HttpServletRequest request) {

		return getSecret(key, request, null);
	}

	public Object getSecret (final String key,
								  final HttpServletRequest request,
								  final Object defaultValue) {

		Object value = defaultValue;

		final Optional<DotVelocitySecretAppConfig> config = DotVelocitySecretAppConfig.config(request);
		if (config.isPresent() && config.get().extraParameters.containsKey(key)) {

			value = config.get().extraParameters.get(key);
		}

		return value;
	}
}
