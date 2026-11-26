package io.seswar.warrant.identity;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

// Keycloak groups claim → roles + GROUP_* authorities → CurrentSubject.groups. No Spring context.
class KeycloakGroupsTest {

    @Test
    void 그룹은_역할과_별개로_그룹_권한으로도_남는다() {
        var authorities = new KeycloakGroups().forClaims(Map.of("groups",
                List.of("/warrant-approvers", "warrant-approvers-db")));

        assertThat(authorities).extracting(GrantedAuthority::getAuthority).containsExactlyInAnyOrder(
                "ROLE_APPROVER", "GROUP_warrant-approvers", "GROUP_warrant-approvers-db");
    }

    @Test
    void 로그인의_그룹_이름은_접두사를_뗀_그대로다() {
        var auth = new TestingAuthenticationToken("x", null,
                List.copyOf(new KeycloakGroups().forClaims(Map.of("groups", List.of("/warrant-approvers-db")))));

        assertThat(CurrentSubject.groups(auth)).containsExactly("warrant-approvers-db");
    }

    @Test
    void 그룹_claim_이_없으면_그룹도_역할도_없다() {
        assertThat(new KeycloakGroups().forClaims(Map.of())).isEmpty();
    }
}
