package com.dotcms.osgi.oauth.viewtool;

import org.apache.velocity.tools.view.context.ViewContext;
import org.apache.velocity.tools.view.servlet.ServletToolInfo;

public class ADFSToolInfo extends ServletToolInfo {

    @Override
    public String getKey () {
        return "adfstool";
    }

    @Override
    public String getScope () {
        return ViewContext.APPLICATION;
    }

    @Override
    public String getClassname () {
        return ADFSTool.class.getName();
    }

    @Override
    public Object getInstance ( Object initData ) {

    	ADFSTool viewTool = new ADFSTool();
        viewTool.init( initData );

        setScope( ViewContext.APPLICATION );

        return viewTool;
    }

}
