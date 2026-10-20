package io.seswar.warrant.domain.audit;

import io.seswar.warrant.domain.warrant.WarrantMode;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * audit_event 의 SMALLINT 칼럼 ↔ enum. DB 에는 순서(ordinal)가 아니라 proto 번호가 들어간다 —
 * Java enum 순서를 바꿔도 과거 행의 뜻이 바뀌지 않게.
 */
public final class AuditEnumConverters {

    private AuditEnumConverters() {
    }

    // Used by AuditEvent.verdict.
    @Converter
    public static class VerdictConverter implements AttributeConverter<Verdict, Short> {
        public Short convertToDatabaseColumn(Verdict v) { return v == null ? null : (short) v.wireValue(); }
        public Verdict convertToEntityAttribute(Short s) { return s == null ? null : Verdict.fromWire(s); }
    }

    // Used by AuditEvent.mode.
    @Converter
    public static class ModeConverter implements AttributeConverter<WarrantMode, Short> {
        public Short convertToDatabaseColumn(WarrantMode m) { return m == null ? null : (short) m.wireValue(); }
        public WarrantMode convertToEntityAttribute(Short s) { return s == null ? null : WarrantMode.fromWire(s); }
    }

    // Used by AuditEvent.tagSource.
    @Converter
    public static class TagSourceConverter implements AttributeConverter<AuditEvent.TagSource, Short> {
        public Short convertToDatabaseColumn(AuditEvent.TagSource t) { return t == null ? null : (short) t.wireValue(); }
        public AuditEvent.TagSource convertToEntityAttribute(Short s) { return s == null ? null : AuditEvent.TagSource.fromWire(s); }
    }

    // Used by AuditEvent.origin.
    @Converter
    public static class OriginConverter implements AttributeConverter<AuditEvent.Origin, Short> {
        public Short convertToDatabaseColumn(AuditEvent.Origin o) { return o == null ? null : (short) o.wireValue(); }
        public AuditEvent.Origin convertToEntityAttribute(Short s) { return s == null ? null : AuditEvent.Origin.fromWire(s); }
    }
}
