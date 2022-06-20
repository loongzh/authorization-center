package io.githubs.loongzh.auth.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.ObjectPostProcessor;

import java.util.function.Consumer;
import java.util.function.Function;

/**
 * ObjectPostProcessor - 工具
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-03-11 13:37
 */

@Slf4j
public class ObjectPostProcessorUtils {


    /**
     * 过滤基类，且匹配具体子类对象后，使用新对象代替原对象
     *
     * @param baseObjClass   基类class
     * @param filterObjClass 待过滤的子类class
     * @param newObj         新返回的对象
     * @param <B>            基类类型
     * @param <T>            待过滤的子类类型
     * @param <R>            新返回的对象类型
     * @return ObjectPostProcessor
     */
    public static <B, T extends B, R extends B> ObjectPostProcessor<B> objectPostReturnNewObj(Class<B> baseObjClass, Class<T> filterObjClass, R newObj) {
        return new ObjectPostProcessor<B>() {
            @Override
            public <O extends B> O postProcess(O object) {
                if (filterObjClass.isAssignableFrom(object.getClass())) {
                    log.debug("expand {} with {}", object.getClass().getSimpleName(), newObj.getClass().getSimpleName());
                    return (O) newObj;
                }
                return object;
            }
        };
    }

    /**
     * 过滤基类，且匹配具体子类对象后，对原对象执行附加操作
     *
     * @param baseObjClass      基类class
     * @param filterObjClass    待过滤的子类class
     * @param originObjConsumer 原对象的附加逻辑执行器
     * @param <B>               基类类型
     * @param <T>               待过滤的子类类型
     * @return ObjectPostProcessor
     */
    public static <B, T extends B> ObjectPostProcessor<B> objectPostAppendHandle(Class<B> baseObjClass, Class<T> filterObjClass, Consumer<T> originObjConsumer) {
        return new ObjectPostProcessor<B>() {
            @Override
            public <O extends B> O postProcess(O object) {
                if (filterObjClass.isAssignableFrom(object.getClass())) {
                    log.debug("expand {} with append handling", object.getClass().getSimpleName());
                    originObjConsumer.accept((T) object);
                    return object;
                }
                return object;
            }
        };
    }


    /**
     * 过滤基类，且匹配具体子类对象后，转换原对象为新对象（具有延迟加载的效果）
     *
     * @param baseObjClass       基类class
     * @param filterObjClass     待过滤的子类class
     * @param originObjConverter 新旧对象转换器
     * @param <B>                基类类型
     * @param <T>                待过滤的子类类型
     * @param <R>                转换后对象类型
     * @return ObjectPostProcessor
     */
    public static <B, T extends B, R extends B> ObjectPostProcessor<B> objectPostConvertObj(Class<B> baseObjClass, Class<T> filterObjClass, Function<T, R> originObjConverter) {
        return new ObjectPostProcessor<B>() {
            @Override
            public <O extends B> O postProcess(O object) {
                if (filterObjClass.isAssignableFrom(object.getClass())) {
                    R newObj = originObjConverter.apply((T) object);
                    log.debug("expand {} with convert object {}", object.getClass().getSimpleName(), newObj.getClass().getSimpleName());
                    return (O) newObj;
                }
                return object;
            }
        };
    }

}
