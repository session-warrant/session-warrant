package io.seswar.warrant.repository;

/** 노드 안에서 감사 레코드 하나를 가리키는 키. node_id 는 조회 조건으로 따로 건다. */
public record SeqKey(long seqEpoch, long nodeSeq) {
}
