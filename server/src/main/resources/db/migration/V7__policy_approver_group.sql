-- 정책별 승인 그룹. 이 정책의 영장(발급 · 연장)은 이 그룹에 든 승인자만 결정할 수 있다.
-- NULL 이면 예전처럼 승인 역할(warrant-approvers)이 있는 다른 사람 누구나. 그룹은 Keycloak 그룹 이름이다.
ALTER TABLE policy ADD COLUMN approver_group TEXT;
