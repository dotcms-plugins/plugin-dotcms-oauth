package com.dotcms.osgi.oauth.viewtool.cache;

import com.dotcms.enterprise.LicenseUtil;
import com.dotcms.enterprise.license.LicenseLevel;
import com.dotmarketing.business.CacheLocator;
import com.dotmarketing.business.DotCacheAdministrator;
import com.google.common.annotations.VisibleForTesting;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;

public class BlockDirectiveCacheImpl extends BlockDirectiveCache {



    private boolean canCache;
    private final DotCacheAdministrator cache;

    private final String group = "BlockDirectiveCache";
    private final String secondaryGroup = "BlockDirectiveHTMLPageCache";

    // regions name for the cache
    private final String[] groupNames = {
            group,
            secondaryGroup};

    public BlockDirectiveCacheImpl() {
        this(CacheLocator.getCacheAdministrator(), (LicenseUtil.getLevel() >= LicenseLevel.COMMUNITY.level));

    }

    @VisibleForTesting
    public BlockDirectiveCacheImpl(DotCacheAdministrator cache, boolean canCache) {
        this.cache = cache;
        this.canCache = canCache;
    }

    public void clearCache() {
        // clear the cache
        cache.flushGroup(group);
        cache.flushGroup(secondaryGroup);
    }

    @Override
    public void add(String key, Map<String, Serializable> value, int ttl) {
        if (key == null || value == null || !canCache) {
            return;
        }
        BlockDirectiveCacheObject cto = new BlockDirectiveCacheObject(value, ttl);
        cache.put(key, cto, group);

    }
    

    
    public void remove(String key) {
        cache.remove(key, group);
    }

    public String[] getGroups() {
        return groupNames;
    }

    public String getPrimaryGroup() {
        return group;
    }

    private static final Map<String, Serializable> EMPTY_MAP = Collections.emptyMap();

    @Override
    public Map<String, Serializable> get(String key) {
        if (!canCache) {
            return EMPTY_MAP;
        }

        BlockDirectiveCacheObject cto = (BlockDirectiveCacheObject) cache.getNoThrow(key, group);
        if (cto == null) {
            return EMPTY_MAP;
        }

        if ((cto.getTtl() * 1000) +  cto.getCreated() > System.currentTimeMillis()) {
            return cto.getMap();
        }

        cache.removeLocalOnly(key, group, true);
        return EMPTY_MAP;
    }
    



}
