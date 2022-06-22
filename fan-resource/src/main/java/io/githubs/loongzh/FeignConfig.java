package io.githubs.loongzh;

import org.springframework.context.annotation.Bean;
import reactivefeign.ReactiveOptions;
import reactivefeign.client.ReactiveHttpRequestInterceptor;
import reactivefeign.retry.BasicReactiveRetryPolicy;
import reactivefeign.spring.config.ReactiveRetryPolicies;
import reactivefeign.webclient.WebReactiveOptions;
import reactor.core.publisher.Mono;

import java.util.Arrays;

/**
 * @author fan
 * @date 2022年06月22日 21:31
 * @see <link>https://blog.csdn.net/LCBUSHIHAHA/article/details/113817966</>
 */
public class FeignConfig {

    //设置一些超时时间
    @Bean
    public ReactiveOptions reactiveOptions() {
        return new WebReactiveOptions.Builder()
                .setWriteTimeoutMillis(10000)
                .setReadTimeoutMillis(10000)
                .setConnectTimeoutMillis(10000)
                .build();
    }

    //重试机制
    @Bean
    public ReactiveRetryPolicies retryOnNext() {
        //不进行重试，retryOnSame是控制对同一个实例的重试策略，retryOnNext是控制对不同实例的重试策略。
        return new ReactiveRetryPolicies.Builder()
                .retryOnSame(BasicReactiveRetryPolicy.retryWithBackoff(0, 10))
                .retryOnNext(BasicReactiveRetryPolicy.retryWithBackoff(0, 10))
                .build();
    }
    @Bean
    public ReactiveHttpRequestInterceptor kuaidiInterceptor() {
        return reactiveHttpRequest ->
                Mono.subscriberContext().map(ctx -> {
                    if (ctx.isEmpty()) {
                        return reactiveHttpRequest;
                    }
//                    reactiveHttpRequest.headers().put(SystemConstant.TOKEN,
//                            Arrays.asList(ctx.get(SystemConstant.TOKEN)));
                    return reactiveHttpRequest;
                });
    }
}
