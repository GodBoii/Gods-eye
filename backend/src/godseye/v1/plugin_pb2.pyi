import datetime

from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Severity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEVERITY_UNSPECIFIED: _ClassVar[Severity]
    SEVERITY_INFO: _ClassVar[Severity]
    SEVERITY_LOW: _ClassVar[Severity]
    SEVERITY_MEDIUM: _ClassVar[Severity]
    SEVERITY_HIGH: _ClassVar[Severity]
    SEVERITY_CRITICAL: _ClassVar[Severity]

class Category(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CATEGORY_UNSPECIFIED: _ClassVar[Category]
    CATEGORY_SAST: _ClassVar[Category]
    CATEGORY_SECRET: _ClassVar[Category]
    CATEGORY_DEPENDENCY: _ClassVar[Category]
    CATEGORY_IAC: _ClassVar[Category]
    CATEGORY_RUNTIME: _ClassVar[Category]

class Reachability(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REACHABILITY_UNSPECIFIED: _ClassVar[Reachability]
    REACHABILITY_UNKNOWN: _ClassVar[Reachability]
    REACHABILITY_REACHABLE: _ClassVar[Reachability]
    REACHABILITY_UNREACHABLE: _ClassVar[Reachability]

class Capability(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CAPABILITY_UNSPECIFIED: _ClassVar[Capability]
    CAPABILITY_SAST: _ClassVar[Capability]
    CAPABILITY_SECRETS: _ClassVar[Capability]
    CAPABILITY_SCA: _ClassVar[Capability]
    CAPABILITY_SBOM: _ClassVar[Capability]
    CAPABILITY_IAC: _ClassVar[Capability]
    CAPABILITY_RUNTIME: _ClassVar[Capability]
    CAPABILITY_TRIAGE: _ClassVar[Capability]
    CAPABILITY_REMEDIATION: _ClassVar[Capability]

class ArtifactKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ARTIFACT_KIND_UNSPECIFIED: _ClassVar[ArtifactKind]
    ARTIFACT_KIND_SARIF: _ClassVar[ArtifactKind]
    ARTIFACT_KIND_CYCLONEDX: _ClassVar[ArtifactKind]
    ARTIFACT_KIND_SPDX: _ClassVar[ArtifactKind]
    ARTIFACT_KIND_THREAT_GRAPH: _ClassVar[ArtifactKind]
    ARTIFACT_KIND_MERMAID: _ClassVar[ArtifactKind]
    ARTIFACT_KIND_REDACTED_EVIDENCE: _ClassVar[ArtifactKind]

class RunStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RUN_STATUS_UNSPECIFIED: _ClassVar[RunStatus]
    RUN_STATUS_SUCCEEDED: _ClassVar[RunStatus]
    RUN_STATUS_PARTIAL: _ClassVar[RunStatus]
    RUN_STATUS_FAILED: _ClassVar[RunStatus]
    RUN_STATUS_CANCELLED: _ClassVar[RunStatus]
SEVERITY_UNSPECIFIED: Severity
SEVERITY_INFO: Severity
SEVERITY_LOW: Severity
SEVERITY_MEDIUM: Severity
SEVERITY_HIGH: Severity
SEVERITY_CRITICAL: Severity
CATEGORY_UNSPECIFIED: Category
CATEGORY_SAST: Category
CATEGORY_SECRET: Category
CATEGORY_DEPENDENCY: Category
CATEGORY_IAC: Category
CATEGORY_RUNTIME: Category
REACHABILITY_UNSPECIFIED: Reachability
REACHABILITY_UNKNOWN: Reachability
REACHABILITY_REACHABLE: Reachability
REACHABILITY_UNREACHABLE: Reachability
CAPABILITY_UNSPECIFIED: Capability
CAPABILITY_SAST: Capability
CAPABILITY_SECRETS: Capability
CAPABILITY_SCA: Capability
CAPABILITY_SBOM: Capability
CAPABILITY_IAC: Capability
CAPABILITY_RUNTIME: Capability
CAPABILITY_TRIAGE: Capability
CAPABILITY_REMEDIATION: Capability
ARTIFACT_KIND_UNSPECIFIED: ArtifactKind
ARTIFACT_KIND_SARIF: ArtifactKind
ARTIFACT_KIND_CYCLONEDX: ArtifactKind
ARTIFACT_KIND_SPDX: ArtifactKind
ARTIFACT_KIND_THREAT_GRAPH: ArtifactKind
ARTIFACT_KIND_MERMAID: ArtifactKind
ARTIFACT_KIND_REDACTED_EVIDENCE: ArtifactKind
RUN_STATUS_UNSPECIFIED: RunStatus
RUN_STATUS_SUCCEEDED: RunStatus
RUN_STATUS_PARTIAL: RunStatus
RUN_STATUS_FAILED: RunStatus
RUN_STATUS_CANCELLED: RunStatus

class Producer(_message.Message):
    __slots__ = ("plugin_id", "plugin_version", "engine_name", "engine_version", "ruleset_digest")
    PLUGIN_ID_FIELD_NUMBER: _ClassVar[int]
    PLUGIN_VERSION_FIELD_NUMBER: _ClassVar[int]
    ENGINE_NAME_FIELD_NUMBER: _ClassVar[int]
    ENGINE_VERSION_FIELD_NUMBER: _ClassVar[int]
    RULESET_DIGEST_FIELD_NUMBER: _ClassVar[int]
    plugin_id: str
    plugin_version: str
    engine_name: str
    engine_version: str
    ruleset_digest: str
    def __init__(self, plugin_id: _Optional[str] = ..., plugin_version: _Optional[str] = ..., engine_name: _Optional[str] = ..., engine_version: _Optional[str] = ..., ruleset_digest: _Optional[str] = ...) -> None: ...

class SourceLocation(_message.Message):
    __slots__ = ("artifact_uri", "start_line", "start_column", "end_line", "end_column", "symbol")
    ARTIFACT_URI_FIELD_NUMBER: _ClassVar[int]
    START_LINE_FIELD_NUMBER: _ClassVar[int]
    START_COLUMN_FIELD_NUMBER: _ClassVar[int]
    END_LINE_FIELD_NUMBER: _ClassVar[int]
    END_COLUMN_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    artifact_uri: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    symbol: str
    def __init__(self, artifact_uri: _Optional[str] = ..., start_line: _Optional[int] = ..., start_column: _Optional[int] = ..., end_line: _Optional[int] = ..., end_column: _Optional[int] = ..., symbol: _Optional[str] = ...) -> None: ...

class PackageRef(_message.Message):
    __slots__ = ("purl", "ecosystem", "name", "resolved_version")
    PURL_FIELD_NUMBER: _ClassVar[int]
    ECOSYSTEM_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_VERSION_FIELD_NUMBER: _ClassVar[int]
    purl: str
    ecosystem: str
    name: str
    resolved_version: str
    def __init__(self, purl: _Optional[str] = ..., ecosystem: _Optional[str] = ..., name: _Optional[str] = ..., resolved_version: _Optional[str] = ...) -> None: ...

class AssetRef(_message.Message):
    __slots__ = ("asset_id", "kind", "display_name")
    ASSET_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    asset_id: str
    kind: str
    display_name: str
    def __init__(self, asset_id: _Optional[str] = ..., kind: _Optional[str] = ..., display_name: _Optional[str] = ...) -> None: ...

class Evidence(_message.Message):
    __slots__ = ("summary", "locations", "telemetry_event_ids", "artifact_ids")
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    LOCATIONS_FIELD_NUMBER: _ClassVar[int]
    TELEMETRY_EVENT_IDS_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    summary: str
    locations: _containers.RepeatedCompositeFieldContainer[SourceLocation]
    telemetry_event_ids: _containers.RepeatedScalarFieldContainer[str]
    artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, summary: _Optional[str] = ..., locations: _Optional[_Iterable[_Union[SourceLocation, _Mapping]]] = ..., telemetry_event_ids: _Optional[_Iterable[str]] = ..., artifact_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class Cvss(_message.Message):
    __slots__ = ("version", "vector", "base_score")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    VECTOR_FIELD_NUMBER: _ClassVar[int]
    BASE_SCORE_FIELD_NUMBER: _ClassVar[int]
    version: str
    vector: str
    base_score: float
    def __init__(self, version: _Optional[str] = ..., vector: _Optional[str] = ..., base_score: _Optional[float] = ...) -> None: ...

class Epss(_message.Message):
    __slots__ = ("probability", "percentile", "as_of", "advisory_id")
    PROBABILITY_FIELD_NUMBER: _ClassVar[int]
    PERCENTILE_FIELD_NUMBER: _ClassVar[int]
    AS_OF_FIELD_NUMBER: _ClassVar[int]
    ADVISORY_ID_FIELD_NUMBER: _ClassVar[int]
    probability: float
    percentile: float
    as_of: _timestamp_pb2.Timestamp
    advisory_id: str
    def __init__(self, probability: _Optional[float] = ..., percentile: _Optional[float] = ..., as_of: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., advisory_id: _Optional[str] = ...) -> None: ...

class RiskContext(_message.Message):
    __slots__ = ("reachability", "reachability_reason", "cvss", "epss", "externally_exposed")
    REACHABILITY_FIELD_NUMBER: _ClassVar[int]
    REACHABILITY_REASON_FIELD_NUMBER: _ClassVar[int]
    CVSS_FIELD_NUMBER: _ClassVar[int]
    EPSS_FIELD_NUMBER: _ClassVar[int]
    EXTERNALLY_EXPOSED_FIELD_NUMBER: _ClassVar[int]
    reachability: Reachability
    reachability_reason: str
    cvss: _containers.RepeatedCompositeFieldContainer[Cvss]
    epss: _containers.RepeatedCompositeFieldContainer[Epss]
    externally_exposed: bool
    def __init__(self, reachability: _Optional[_Union[Reachability, str]] = ..., reachability_reason: _Optional[str] = ..., cvss: _Optional[_Iterable[_Union[Cvss, _Mapping]]] = ..., epss: _Optional[_Iterable[_Union[Epss, _Mapping]]] = ..., externally_exposed: _Optional[bool] = ...) -> None: ...

class PatchFile(_message.Message):
    __slots__ = ("artifact_uri", "base_sha256")
    ARTIFACT_URI_FIELD_NUMBER: _ClassVar[int]
    BASE_SHA256_FIELD_NUMBER: _ClassVar[int]
    artifact_uri: str
    base_sha256: str
    def __init__(self, artifact_uri: _Optional[str] = ..., base_sha256: _Optional[str] = ...) -> None: ...

class Remediation(_message.Message):
    __slots__ = ("explanation", "unified_diff", "files", "verification_notes")
    EXPLANATION_FIELD_NUMBER: _ClassVar[int]
    UNIFIED_DIFF_FIELD_NUMBER: _ClassVar[int]
    FILES_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_NOTES_FIELD_NUMBER: _ClassVar[int]
    explanation: str
    unified_diff: str
    files: _containers.RepeatedCompositeFieldContainer[PatchFile]
    verification_notes: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, explanation: _Optional[str] = ..., unified_diff: _Optional[str] = ..., files: _Optional[_Iterable[_Union[PatchFile, _Mapping]]] = ..., verification_notes: _Optional[_Iterable[str]] = ...) -> None: ...

class UnifiedFinding(_message.Message):
    __slots__ = ("schema_version", "finding_id", "run_id", "project_id", "fingerprint", "producer", "category", "rule_id", "title", "description", "severity", "confidence", "locations", "asset", "package", "advisory_ids", "cwe_ids", "evidence", "risk", "remediation", "observed_at", "related_finding_ids")
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    FINDING_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    PRODUCER_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    LOCATIONS_FIELD_NUMBER: _ClassVar[int]
    ASSET_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_FIELD_NUMBER: _ClassVar[int]
    ADVISORY_IDS_FIELD_NUMBER: _ClassVar[int]
    CWE_IDS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    RISK_FIELD_NUMBER: _ClassVar[int]
    REMEDIATION_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_AT_FIELD_NUMBER: _ClassVar[int]
    RELATED_FINDING_IDS_FIELD_NUMBER: _ClassVar[int]
    schema_version: str
    finding_id: str
    run_id: str
    project_id: str
    fingerprint: str
    producer: Producer
    category: Category
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    locations: _containers.RepeatedCompositeFieldContainer[SourceLocation]
    asset: AssetRef
    package: PackageRef
    advisory_ids: _containers.RepeatedScalarFieldContainer[str]
    cwe_ids: _containers.RepeatedScalarFieldContainer[str]
    evidence: Evidence
    risk: RiskContext
    remediation: Remediation
    observed_at: _timestamp_pb2.Timestamp
    related_finding_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, schema_version: _Optional[str] = ..., finding_id: _Optional[str] = ..., run_id: _Optional[str] = ..., project_id: _Optional[str] = ..., fingerprint: _Optional[str] = ..., producer: _Optional[_Union[Producer, _Mapping]] = ..., category: _Optional[_Union[Category, str]] = ..., rule_id: _Optional[str] = ..., title: _Optional[str] = ..., description: _Optional[str] = ..., severity: _Optional[_Union[Severity, str]] = ..., confidence: _Optional[float] = ..., locations: _Optional[_Iterable[_Union[SourceLocation, _Mapping]]] = ..., asset: _Optional[_Union[AssetRef, _Mapping]] = ..., package: _Optional[_Union[PackageRef, _Mapping]] = ..., advisory_ids: _Optional[_Iterable[str]] = ..., cwe_ids: _Optional[_Iterable[str]] = ..., evidence: _Optional[_Union[Evidence, _Mapping]] = ..., risk: _Optional[_Union[RiskContext, _Mapping]] = ..., remediation: _Optional[_Union[Remediation, _Mapping]] = ..., observed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., related_finding_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class ProcessIdentity(_message.Message):
    __slots__ = ("pid", "started_at", "executable_name", "container_id")
    PID_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_NAME_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_ID_FIELD_NUMBER: _ClassVar[int]
    pid: int
    started_at: _timestamp_pb2.Timestamp
    executable_name: str
    container_id: str
    def __init__(self, pid: _Optional[int] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., executable_name: _Optional[str] = ..., container_id: _Optional[str] = ...) -> None: ...

class MetricSample(_message.Message):
    __slots__ = ("name", "value", "unit")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: float
    unit: str
    def __init__(self, name: _Optional[str] = ..., value: _Optional[float] = ..., unit: _Optional[str] = ...) -> None: ...

class LogRecord(_message.Message):
    __slots__ = ("severity", "message")
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    severity: Severity
    message: str
    def __init__(self, severity: _Optional[_Union[Severity, str]] = ..., message: _Optional[str] = ...) -> None: ...

class SpanRecord(_message.Message):
    __slots__ = ("operation", "duration", "error")
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    DURATION_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    operation: str
    duration: _duration_pb2.Duration
    error: bool
    def __init__(self, operation: _Optional[str] = ..., duration: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., error: _Optional[bool] = ...) -> None: ...

class ThreadSample(_message.Message):
    __slots__ = ("thread_id", "state", "frames")
    THREAD_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    FRAMES_FIELD_NUMBER: _ClassVar[int]
    thread_id: int
    state: str
    frames: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, thread_id: _Optional[int] = ..., state: _Optional[str] = ..., frames: _Optional[_Iterable[str]] = ...) -> None: ...

class SocketSample(_message.Message):
    __slots__ = ("transport", "state", "local_endpoint_id", "remote_endpoint_id")
    TRANSPORT_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    LOCAL_ENDPOINT_ID_FIELD_NUMBER: _ClassVar[int]
    REMOTE_ENDPOINT_ID_FIELD_NUMBER: _ClassVar[int]
    transport: str
    state: str
    local_endpoint_id: str
    remote_endpoint_id: str
    def __init__(self, transport: _Optional[str] = ..., state: _Optional[str] = ..., local_endpoint_id: _Optional[str] = ..., remote_endpoint_id: _Optional[str] = ...) -> None: ...

class ResourceSnapshot(_message.Message):
    __slots__ = ("open_file_descriptors", "open_handles", "resident_memory_bytes", "cpu_cores_used", "sample_interval")
    OPEN_FILE_DESCRIPTORS_FIELD_NUMBER: _ClassVar[int]
    OPEN_HANDLES_FIELD_NUMBER: _ClassVar[int]
    RESIDENT_MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    CPU_CORES_USED_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_INTERVAL_FIELD_NUMBER: _ClassVar[int]
    open_file_descriptors: int
    open_handles: int
    resident_memory_bytes: int
    cpu_cores_used: float
    sample_interval: _duration_pb2.Duration
    def __init__(self, open_file_descriptors: _Optional[int] = ..., open_handles: _Optional[int] = ..., resident_memory_bytes: _Optional[int] = ..., cpu_cores_used: _Optional[float] = ..., sample_interval: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class DebugTelemetryEvent(_message.Message):
    __slots__ = ("schema_version", "event_id", "run_id", "project_id", "producer", "host_id", "agent_session_id", "occurred_at", "collected_at", "monotonic_offset_ns", "clock_uncertainty_ns", "process", "trace_id", "span_id", "attributes", "metric", "log", "span", "thread", "socket", "resources")
    class AttributesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PRODUCER_FIELD_NUMBER: _ClassVar[int]
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    OCCURRED_AT_FIELD_NUMBER: _ClassVar[int]
    COLLECTED_AT_FIELD_NUMBER: _ClassVar[int]
    MONOTONIC_OFFSET_NS_FIELD_NUMBER: _ClassVar[int]
    CLOCK_UNCERTAINTY_NS_FIELD_NUMBER: _ClassVar[int]
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    SPAN_ID_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    METRIC_FIELD_NUMBER: _ClassVar[int]
    LOG_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    THREAD_FIELD_NUMBER: _ClassVar[int]
    SOCKET_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    schema_version: str
    event_id: str
    run_id: str
    project_id: str
    producer: Producer
    host_id: str
    agent_session_id: str
    occurred_at: _timestamp_pb2.Timestamp
    collected_at: _timestamp_pb2.Timestamp
    monotonic_offset_ns: int
    clock_uncertainty_ns: int
    process: ProcessIdentity
    trace_id: str
    span_id: str
    attributes: _containers.ScalarMap[str, str]
    metric: MetricSample
    log: LogRecord
    span: SpanRecord
    thread: ThreadSample
    socket: SocketSample
    resources: ResourceSnapshot
    def __init__(self, schema_version: _Optional[str] = ..., event_id: _Optional[str] = ..., run_id: _Optional[str] = ..., project_id: _Optional[str] = ..., producer: _Optional[_Union[Producer, _Mapping]] = ..., host_id: _Optional[str] = ..., agent_session_id: _Optional[str] = ..., occurred_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., collected_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., monotonic_offset_ns: _Optional[int] = ..., clock_uncertainty_ns: _Optional[int] = ..., process: _Optional[_Union[ProcessIdentity, _Mapping]] = ..., trace_id: _Optional[str] = ..., span_id: _Optional[str] = ..., attributes: _Optional[_Mapping[str, str]] = ..., metric: _Optional[_Union[MetricSample, _Mapping]] = ..., log: _Optional[_Union[LogRecord, _Mapping]] = ..., span: _Optional[_Union[SpanRecord, _Mapping]] = ..., thread: _Optional[_Union[ThreadSample, _Mapping]] = ..., socket: _Optional[_Union[SocketSample, _Mapping]] = ..., resources: _Optional[_Union[ResourceSnapshot, _Mapping]] = ...) -> None: ...

class DescribeRequest(_message.Message):
    __slots__ = ("protocol_major",)
    PROTOCOL_MAJOR_FIELD_NUMBER: _ClassVar[int]
    protocol_major: int
    def __init__(self, protocol_major: _Optional[int] = ...) -> None: ...

class PluginDescriptor(_message.Message):
    __slots__ = ("plugin_id", "version", "protocol_major", "capabilities", "schema_versions", "max_concurrent_runs", "required_permissions")
    PLUGIN_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_MAJOR_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_VERSIONS_FIELD_NUMBER: _ClassVar[int]
    MAX_CONCURRENT_RUNS_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    plugin_id: str
    version: str
    protocol_major: int
    capabilities: _containers.RepeatedScalarFieldContainer[Capability]
    schema_versions: _containers.RepeatedScalarFieldContainer[str]
    max_concurrent_runs: int
    required_permissions: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, plugin_id: _Optional[str] = ..., version: _Optional[str] = ..., protocol_major: _Optional[int] = ..., capabilities: _Optional[_Iterable[_Union[Capability, str]]] = ..., schema_versions: _Optional[_Iterable[str]] = ..., max_concurrent_runs: _Optional[int] = ..., required_permissions: _Optional[_Iterable[str]] = ...) -> None: ...

class ScanTarget(_message.Message):
    __slots__ = ("workspace_snapshot_id", "process", "container_id", "findings_snapshot_id")
    WORKSPACE_SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_ID_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    workspace_snapshot_id: str
    process: ProcessIdentity
    container_id: str
    findings_snapshot_id: str
    def __init__(self, workspace_snapshot_id: _Optional[str] = ..., process: _Optional[_Union[ProcessIdentity, _Mapping]] = ..., container_id: _Optional[str] = ..., findings_snapshot_id: _Optional[str] = ...) -> None: ...

class RunLimits(_message.Message):
    __slots__ = ("wall_time", "memory_bytes", "max_input_bytes", "max_output_bytes", "max_files", "max_subprocesses")
    WALL_TIME_FIELD_NUMBER: _ClassVar[int]
    MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    MAX_INPUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    MAX_OUTPUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    MAX_FILES_FIELD_NUMBER: _ClassVar[int]
    MAX_SUBPROCESSES_FIELD_NUMBER: _ClassVar[int]
    wall_time: _duration_pb2.Duration
    memory_bytes: int
    max_input_bytes: int
    max_output_bytes: int
    max_files: int
    max_subprocesses: int
    def __init__(self, wall_time: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., memory_bytes: _Optional[int] = ..., max_input_bytes: _Optional[int] = ..., max_output_bytes: _Optional[int] = ..., max_files: _Optional[int] = ..., max_subprocesses: _Optional[int] = ...) -> None: ...

class RunRequest(_message.Message):
    __slots__ = ("run_id", "project_id", "target", "capabilities", "limits", "policy_snapshot_id", "input_digest")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    LIMITS_FIELD_NUMBER: _ClassVar[int]
    POLICY_SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    INPUT_DIGEST_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    project_id: str
    target: ScanTarget
    capabilities: _containers.RepeatedScalarFieldContainer[Capability]
    limits: RunLimits
    policy_snapshot_id: str
    input_digest: str
    def __init__(self, run_id: _Optional[str] = ..., project_id: _Optional[str] = ..., target: _Optional[_Union[ScanTarget, _Mapping]] = ..., capabilities: _Optional[_Iterable[_Union[Capability, str]]] = ..., limits: _Optional[_Union[RunLimits, _Mapping]] = ..., policy_snapshot_id: _Optional[str] = ..., input_digest: _Optional[str] = ...) -> None: ...

class Progress(_message.Message):
    __slots__ = ("phase", "completed_units", "total_units")
    PHASE_FIELD_NUMBER: _ClassVar[int]
    COMPLETED_UNITS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_UNITS_FIELD_NUMBER: _ClassVar[int]
    phase: str
    completed_units: int
    total_units: int
    def __init__(self, phase: _Optional[str] = ..., completed_units: _Optional[int] = ..., total_units: _Optional[int] = ...) -> None: ...

class Diagnostic(_message.Message):
    __slots__ = ("code", "message", "retryable")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    code: str
    message: str
    retryable: bool
    def __init__(self, code: _Optional[str] = ..., message: _Optional[str] = ..., retryable: _Optional[bool] = ...) -> None: ...

class Artifact(_message.Message):
    __slots__ = ("artifact_id", "kind", "relative_path", "sha256", "size_bytes", "media_type")
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    RELATIVE_PATH_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    SIZE_BYTES_FIELD_NUMBER: _ClassVar[int]
    MEDIA_TYPE_FIELD_NUMBER: _ClassVar[int]
    artifact_id: str
    kind: ArtifactKind
    relative_path: str
    sha256: str
    size_bytes: int
    media_type: str
    def __init__(self, artifact_id: _Optional[str] = ..., kind: _Optional[_Union[ArtifactKind, str]] = ..., relative_path: _Optional[str] = ..., sha256: _Optional[str] = ..., size_bytes: _Optional[int] = ..., media_type: _Optional[str] = ...) -> None: ...

class RunSummary(_message.Message):
    __slots__ = ("status", "finding_count", "telemetry_count", "dropped_telemetry_count", "coverage_gaps")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    FINDING_COUNT_FIELD_NUMBER: _ClassVar[int]
    TELEMETRY_COUNT_FIELD_NUMBER: _ClassVar[int]
    DROPPED_TELEMETRY_COUNT_FIELD_NUMBER: _ClassVar[int]
    COVERAGE_GAPS_FIELD_NUMBER: _ClassVar[int]
    status: RunStatus
    finding_count: int
    telemetry_count: int
    dropped_telemetry_count: int
    coverage_gaps: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, status: _Optional[_Union[RunStatus, str]] = ..., finding_count: _Optional[int] = ..., telemetry_count: _Optional[int] = ..., dropped_telemetry_count: _Optional[int] = ..., coverage_gaps: _Optional[_Iterable[str]] = ...) -> None: ...

class RunEvent(_message.Message):
    __slots__ = ("run_id", "sequence", "finding", "telemetry", "progress", "diagnostic", "artifact", "completed")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    FINDING_FIELD_NUMBER: _ClassVar[int]
    TELEMETRY_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    DIAGNOSTIC_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    COMPLETED_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    sequence: int
    finding: UnifiedFinding
    telemetry: DebugTelemetryEvent
    progress: Progress
    diagnostic: Diagnostic
    artifact: Artifact
    completed: RunSummary
    def __init__(self, run_id: _Optional[str] = ..., sequence: _Optional[int] = ..., finding: _Optional[_Union[UnifiedFinding, _Mapping]] = ..., telemetry: _Optional[_Union[DebugTelemetryEvent, _Mapping]] = ..., progress: _Optional[_Union[Progress, _Mapping]] = ..., diagnostic: _Optional[_Union[Diagnostic, _Mapping]] = ..., artifact: _Optional[_Union[Artifact, _Mapping]] = ..., completed: _Optional[_Union[RunSummary, _Mapping]] = ...) -> None: ...
