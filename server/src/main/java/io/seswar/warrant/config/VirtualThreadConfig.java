package io.seswar.warrant.config;

/**
 * {@code spring.threads.virtual.enabled=true} 로 충분하다.
 * WebFlux 를 도입할 이유가 없고, 도입하면 JPA 와 섞여서 오히려 복잡해진다.
 */
// @Configuration
public class VirtualThreadConfig {
}
