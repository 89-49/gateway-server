package org.pgsg.gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.pgsg.common.exception.ErrorConfigProperties;
import org.pgsg.common.exception.GlobalExceptionAdvice;
import org.pgsg.common.exception.GlobalExceptionAdviceImpl;
import org.pgsg.common.filter.MdcLoggingFilter;
import org.pgsg.common.response.CommonResponseAdvice;
import org.pgsg.config.feign.FeignConfig;
import org.pgsg.config.json.JsonConfig;
import org.pgsg.config.security.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.HandlerExceptionResolver;

@AutoConfiguration
@Import({
		FeignConfig.class,
		JsonConfig.class,
		ErrorConfigProperties.class
})
public class GatewayAppCtx {

	@Bean
	public LoginFilter loginFilter(@Lazy @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
		return new LoginFilter(resolver);
	}

	@Bean
	public CustomAuthenticationEntryPoint customAuthenticationEntryPoint(
			ObjectMapper objectMapper, ErrorConfigProperties errorConfigProperties) {
		return new CustomAuthenticationEntryPoint(objectMapper, errorConfigProperties);
	}

	@Bean
	public CustomAccessDeniedHandler accessDeniedHandler(
			ObjectMapper objectMapper, ErrorConfigProperties errorConfigProperties) {
		return new CustomAccessDeniedHandler(objectMapper, errorConfigProperties);
	}

	@Bean
	@ConditionalOnMissingBean(SecurityConfig.class)
	public SecurityConfig securityConfig(
			LoginFilter loginFilter,
			CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
			CustomAccessDeniedHandler accessDeniedHandler) {
		return new SecurityConfigImpl(loginFilter, customAuthenticationEntryPoint, accessDeniedHandler);
	}

	@Bean
	@ConditionalOnMissingBean(GlobalExceptionAdvice.class)
	public GlobalExceptionAdvice globalExceptionAdvice(ErrorConfigProperties errorConfigProperties) {
		return new GlobalExceptionAdviceImpl(errorConfigProperties);
	}

	@Bean
	public CommonResponseAdvice commonResponseAdvice() {
		return new CommonResponseAdvice();
	}

	@Bean
	public FilterRegistrationBean<MdcLoggingFilter> mdcLoggingFilter() {
		FilterRegistrationBean<MdcLoggingFilter> registrationBean = new FilterRegistrationBean<>();
		registrationBean.setFilter(new MdcLoggingFilter());
		registrationBean.addUrlPatterns("/*");
		registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return registrationBean;
	}
}