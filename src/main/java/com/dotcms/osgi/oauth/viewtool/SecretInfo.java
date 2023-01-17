package com.dotcms.osgi.oauth.viewtool;

import org.apache.velocity.tools.view.context.ViewContext;
import org.apache.velocity.tools.view.servlet.ServletToolInfo;

public class SecretInfo extends ServletToolInfo {

    @Override
    public String getKey () {
        return "dotsecrets";
    }

    @Override
    public String getScope () {
        return ViewContext.APPLICATION;
    }

    @Override
    public String getClassname () {
        return SecretTool.class.getName();
    }

    @Override
    public Object getInstance ( Object initData ) {

        SecretTool viewTool = new SecretTool();
        viewTool.init( initData );

        setScope( ViewContext.APPLICATION );

        return viewTool;
    }

}
