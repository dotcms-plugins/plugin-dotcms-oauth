package com.dotcms.osgi.oauth.viewtool.cache;

import org.apache.velocity.tools.view.context.ViewContext;
import org.apache.velocity.tools.view.servlet.ServletToolInfo;

public class DotCacheToolInfo extends ServletToolInfo {

    @Override
    public String getKey () {
        return "dotcache22";
    }

    @Override
    public String getScope () {
        return ViewContext.APPLICATION;
    }

    @Override
    public String getClassname () {
        return DotCacheTool.class.getName();
    }

    @Override
    public Object getInstance ( Object initData ) {

        DotCacheTool viewTool = new DotCacheTool();
        viewTool.init( initData );

        setScope( ViewContext.APPLICATION );

        return viewTool;
    }

}
