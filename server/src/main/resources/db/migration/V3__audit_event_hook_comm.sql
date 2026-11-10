-- 커널 판정 기록을 올리기 시작하면서 화면에 필요한 두 칸을 더한다.
-- type(EXEC · INODE_MUTATE …)만으로는 unlink 인지 rename 인지, 자기보호의 어느 훅인지 모른다 — proto Hook 번호를 그대로 둔다.
-- comm 은 16바이트로 잘리고 위조 가능한 참고 정보다. 증거는 (device_id, inode) 다.
ALTER TABLE audit_event
    ADD COLUMN hook SMALLINT,
    ADD COLUMN comm TEXT;
