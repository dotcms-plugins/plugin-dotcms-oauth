package com.dotcms.osgi.oauth.util;

import java.util.List;
import java.util.Map;
import com.dotmarketing.business.DotStateException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public class JsonUtil {

    final ObjectMapper mapper;

    public JsonUtil() {
        mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.WRAP_EXCEPTIONS);


        mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
        mapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);


    }


    public final Object generate(final String jsonString) throws JsonMappingException, JsonProcessingException {
        if (jsonString == null) {
            throw new DotStateException("jsonString cannot be null");
        }


        return jsonString.trim().startsWith("[") ? (List<Map<String, Object>>) mapper.readValue(jsonString, List.class)
                        : (Map<String, Object>) mapper.readValue(jsonString, Map.class);


    }
}
