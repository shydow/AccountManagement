package com.tangpian.am.web.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * Created by shydow on 16/7/22.
 */
@Configuration
public class WebConfig extends WebMvcConfigurerAdapter {

    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        //registry.addResourceHandler(Constants.IMG_URI + "**").addResourceLocations("file://" + Constants.UPLOAD_PATH);
    }
}
