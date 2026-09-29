from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FileMetadataRecord(BaseModel):
    """Structured, schema-validated inventory record for one file found in a
    high-risk execution path (Downloads, Temp, AppData, Public, ...)."""
    filename: str
    full_path: str
    extension: str
    size_bytes: int = Field(ge=0)
    created_utc: Optional[str] = Field(default=None, description="ISO-8601 UTC creation timestamp")
    modified_utc: Optional[str] = Field(default=None, description="ISO-8601 UTC last-modified timestamp")
    accessed_utc: Optional[str] = Field(default=None, description="ISO-8601 UTC last-accessed timestamp")
    md5: Optional[str] = None
    sha256: Optional[str] = None
    is_executable: bool = False
    signature_status: str = Field(
        default="NotChecked",
        description="Signed-Valid, Signed-Invalid, Unsigned, NotApplicable, CheckFailed, or NotChecked",
    )
    signature_subject: Optional[str] = None
    content_read: bool = False
    content_preview: Optional[str] = None
    note: Optional[str] = None


class RegistryPersistenceEntry(BaseModel):
    """One extracted persistence-relevant registry value."""
    hive_file: str
    hive_type: str = Field(description="SYSTEM, SOFTWARE, or NTUSER")
    key_path: str
    value_name: Optional[str] = None
    value_type: Optional[str] = None
    value_data: Optional[str] = None
    persistence_category: str = Field(
        description="E.g. 'Run Key', 'RunOnce Key', 'Service ImagePath', 'Winlogon Shell/Userinit', 'AppInit_DLLs'"
    )
    mitre_technique: Optional[str] = Field(default=None, description="E.g. 'T1547.001'")


class CorrelatedSecurityEvent(BaseModel):
    """One pre-filtered, high-value Windows Event Log / Sysmon event."""
    event_id: int
    provider: Optional[str] = Field(default=None, description="EVTX Provider Name, e.g. 'Microsoft-Windows-Sysmon'")
    time_created_utc: Optional[str] = None
    channel: Optional[str] = None
    computer: Optional[str] = None
    event_type_label: str = Field(description="Human label, e.g. 'Process Creation', 'Logon Failure'")
    key_fields: Dict[str, Any] = Field(default_factory=dict)
    source_file: Optional[str] = None


class TimelineEvent(BaseModel):
    """One normalized event on the unified super-timeline, regardless of
    origin (MFT, EVTX, Plaso L2T CSV/JSONL/SQLite, or raw file inventory)."""
    timestamp_utc: str = Field(description="ISO-8601 UTC timestamp")
    source: str = Field(description="'MFT', 'EVTX', 'Plaso', or 'FileInventory'")
    macb: Optional[str] = Field(default=None, description="Which of Modified/Accessed/Changed/Born this represents")
    description: str
    path: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class TimestompingCandidate(BaseModel):
    """A file whose $STANDARD_INFORMATION and $FILE_NAME MFT timestamps
    disagree by more than a noise threshold -- a classic timestomping tell."""
    full_path: str
    si_created_utc: Optional[str] = None
    fn_created_utc: Optional[str] = None
    discrepancy_seconds: Optional[float] = None
    reason: str


class ExecutionArtifact(BaseModel):
    """One normalized execution-evidence record from Prefetch, Amcache, or
    Shimcache -- a single schema shared across all three sources so they can
    be cross-referenced (e.g. an Amcache entry with no matching Prefetch run)."""
    source: str = Field(description="'Prefetch', 'Amcache', or 'Shimcache'")
    executable_name: str
    full_path: Optional[str] = None
    run_count: Optional[int] = None
    last_execution_utc: Optional[str] = None
    first_seen_utc: Optional[str] = None
    volume_serial: Optional[str] = None
    sha1: Optional[str] = None
    size_bytes: Optional[int] = None
    is_masquerade_suspect: bool = False
    masquerade_reason: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ProcessAnomaly(BaseModel):
    """One flagged discrepancy/anomaly surfaced while cross-referencing
    pslist/pstree/psxview for a single process."""
    pid: int
    process_name: Optional[str] = None
    ppid: Optional[int] = None
    anomaly_type: str = Field(
        description="E.g. 'Hidden From PsList', 'PPID Spoofing', 'Masquerading Name', "
                    "'Unexpected Parent', 'Orphaned Process'"
    )
    detail: str = Field(description="What was actually observed across the plugin outputs")
    severity: str = Field(default="Medium", description="High, Medium, or Low")


class ProcessTreeFinding(BaseModel):
    """Process & Thread Mapper output: the reconstructed tree plus every
    pslist/pstree/psxview discrepancy and parent-child anomaly found."""
    total_processes: int = 0
    hidden_or_unlinked_pids: List[int] = Field(
        default_factory=list, description="Present in psxview (csrss/thread/etc scan) but absent from pslist"
    )
    anomalies: List[ProcessAnomaly] = Field(default_factory=list)
    anomaly_score: float = Field(default=0.0, description="0-100 heuristic severity score for the whole process tree")
    process_tree: List[Dict[str, Any]] = Field(default_factory=list, description="Flattened pid->children tree")


class MalwareHandoffPayload(BaseModel):
    """Everything a downstream Malware Analysis Agent (here: File_Analysis_Father_Agent's
    PeStudio/Strings agents, via ProgramDataList/raw/) needs to pick up an extracted
    injected-memory dump without re-deriving anything the memory analyzer already knows."""
    dumped_file_path: str = Field(description="Path to the extracted VAD/payload dump on disk")
    staged_for_analysis_path: Optional[str] = Field(
        default=None, description="Path once copied into ProgramDataList/raw/ for the File Analysis pipeline"
    )
    sha256: Optional[str] = None
    md5: Optional[str] = None
    source_pid: int
    source_process_name: Optional[str] = None
    virtual_address: str = Field(description="Hex VAD base address the payload was dumped from")
    region_size_bytes: Optional[int] = None
    protection: Optional[str] = Field(default=None, description="E.g. PAGE_EXECUTE_READWRITE")
    pe_header_detected: bool = False
    disassembly_highlights: List[str] = Field(
        default_factory=list, description="First few disassembled instructions/opcodes, if extracted"
    )


class InjectedMemoryRegion(BaseModel):
    """One malfind-flagged VAD region, after LLM triage for false positives
    (JIT engines, Mono/.NET/Java runtimes, legitimate self-modifying code)."""
    pid: int
    process_name: Optional[str] = None
    virtual_address: str
    protection: Optional[str] = None
    region_size_bytes: Optional[int] = None
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None
    injection_technique: Optional[str] = Field(
        default=None, description="E.g. 'Reflective DLL Injection', 'Process Hollowing', 'Shellcode Injection'"
    )
    confidence: str = Field(default="Medium", description="High, Medium, or Low")
    handoff: Optional[MalwareHandoffPayload] = None


class NetworkConnection(BaseModel):
    """One netscan row, normalized."""
    protocol: str = Field(description="TCP or UDP")
    local_addr: Optional[str] = None
    local_port: Optional[int] = None
    foreign_addr: Optional[str] = None
    foreign_port: Optional[int] = None
    state: Optional[str] = None
    pid: Optional[int] = None
    owner_process: Optional[str] = None
    created_utc: Optional[str] = None


class SocketAnomaly(BaseModel):
    connection: NetworkConnection
    reason: str = Field(description="Why this socket was flagged")
    severity: str = Field(default="Medium", description="High, Medium, or Low")


class SocketCorrelation(BaseModel):
    """Network Socket Correlator output."""
    total_connections: int = 0
    flagged_sockets: List[SocketAnomaly] = Field(default_factory=list)
    orphan_endpoints: List[NetworkConnection] = Field(
        default_factory=list, description="Connections whose owning PID no longer exists in pslist"
    )


class MalfindCorrelation(BaseModel):
    """One MALFIND Correlator output row -- a malfind hit deterministically
    cross-referenced against handles/threads/modules, with a rule-derived
    severity. No LLM tokens are spent producing this."""
    pid: int
    process_name: Optional[str] = None
    virtual_address: str
    protection: Optional[str] = None
    region_size_bytes: Optional[int] = None
    unbacked_vad: bool = Field(description="True if the VAD has no backing file (PrivateMemory, no mapped image)")
    thread_start_in_region: bool = Field(
        default=False, description="A thread's start address (windows.thrdscan.ThrdScan) falls inside this VAD"
    )
    remote_handle_present: bool = Field(
        default=False, description="Another process holds a PROCESS_VM_WRITE/PROCESS_CREATE_THREAD handle to this PID"
    )
    remote_handle_owner_pid: Optional[int] = None
    belongs_to_loaded_module: bool = Field(
        default=False, description="The VA falls inside a range windows.dlllist.DllList reports as a legitimate loaded module"
    )
    matched_rules: List[str] = Field(default_factory=list, description="Which deterministic rules fired, in order")
    confidence_score: int = Field(ge=0, le=100, description="0-100, derived purely from matched_rules")
    severity: str = Field(description="Critical, High, Medium, or Low -- derived purely from confidence_score")


class MemoryAnalysisReport(BaseModel):
    """Top-level Father Agent aggregate -- what Memory_Analysis_Master_Report.json holds."""
    orchestrator: str = "Memory_Analysis_Father_Agent"
    staging_root: str
    timestamp: str
    memory_image: Optional[str] = None
    process_tree: Optional[ProcessTreeFinding] = None
    injected_regions: List[InjectedMemoryRegion] = Field(default_factory=list)
    malfind_correlations: List[MalfindCorrelation] = Field(default_factory=list)
    socket_correlation: Optional[SocketCorrelation] = None
    total_anomalies_flagged: int = 0
    critical_findings: List[Dict[str, Any]] = Field(default_factory=list)
    handoffs_to_malware_analysis: List[MalwareHandoffPayload] = Field(default_factory=list)
    detailed_agent_reports: List[Dict[str, Any]] = Field(default_factory=list)


class FileHashSet(BaseModel):
    """Every identifying hash the Static Triage & Capability Mapper computes
    for one artifact -- exact (md5/sha256), fuzzy (ssdeep, for near-duplicate/
    variant matching), and format-specific import-table hashes (imphash for
    PE, typehash for ELF's analogous "shape of imports" signature)."""
    md5: Optional[str] = None
    sha256: Optional[str] = None
    ssdeep: Optional[str] = None
    imphash: Optional[str] = Field(default=None, description="PE import-table hash")
    typehash: Optional[str] = Field(default=None, description="ELF import/symbol-shape hash")


class MitreMapping(BaseModel):
    """One CAPA-derived capability, mapped to ATT&CK."""
    capability: str = Field(description="CAPA rule name, e.g. 'inject thread into remote process'")
    technique_id: Optional[str] = Field(default=None, description="E.g. 'T1055.002'")
    technique_name: Optional[str] = None
    tactic: Optional[str] = Field(default=None, description="E.g. 'Defense Evasion', 'Persistence'")
    confidence: str = Field(default="Medium", description="High, Medium, or Low")
    matched_addresses: List[str] = Field(default_factory=list, description="Hex addresses CAPA matched at, if provided")


class StaticAnalysisReport(BaseModel):
    """Static Triage & Capability Mapper output -- pure automation, no LLM."""
    filepath: str
    file_type: str = Field(description="'PE', 'ELF', or 'Unknown'")
    hashes: FileHashSet
    overall_entropy: float = 0.0
    section_entropies: Dict[str, float] = Field(default_factory=dict)
    packing_suspected: bool = False
    suspicious_imports: Dict[str, List[str]] = Field(
        default_factory=dict, description="category -> ['dll.ApiName', ...], e.g. 'process_injection'"
    )
    capa_capabilities: List[MitreMapping] = Field(default_factory=list)
    indicators: List[Dict[str, Any]] = Field(default_factory=list, description="Raw deterministic indicator list")
    status: str = Field(description="Clean, Suspicious, or Critical")
    summary: str = ""


class DecodedStringArtifact(BaseModel):
    """One string that only became meaningful after automated decoding."""
    encoded: str
    decoded: str
    encoding: str = Field(description="E.g. 'single-byte-xor:0x5a', 'base64', 'base64+xor:0x1a'")
    offset: Optional[str] = Field(default=None, description="Hex file/VA offset, if known")
    looks_like: Optional[str] = Field(default=None, description="'PE header', 'URL', 'IP', 'config-blob', etc.")


class DecompiledFunctionFinding(BaseModel):
    """One Ghidra-decompiled function the automation step judged worth an
    LLM's attention, plus whatever the LLM concluded about it."""
    function_name: str
    address: str
    cyclomatic_complexity: int = 0
    is_high_priority: bool = False
    priority_reason: Optional[str] = None
    intent_summary: Optional[str] = None
    crypto_algorithm_identified: Optional[str] = Field(default=None, description="E.g. 'RC4', 'AES-128-CBC', 'Custom XOR'")
    c2_config_extracted: Optional[Dict[str, Any]] = None
    suggested_rename: Optional[str] = None
    anti_analysis_technique: Optional[str] = None


class ReverseEngineeringModel(BaseModel):
    """Reverse Engineering & String Analyzer output."""
    filepath: str
    ghidra_project: Optional[str] = None
    functions_total: int = 0
    functions_analyzed_by_llm: int = 0
    high_priority_functions: List[DecompiledFunctionFinding] = Field(default_factory=list)
    decoded_strings: List[DecodedStringArtifact] = Field(default_factory=list)
    extracted_c2_config: Optional[Dict[str, Any]] = None
    status: str = Field(description="Clean, Suspicious, or Critical")
    summary: str = ""


class NetworkArtifact(BaseModel):
    """One network event observed during dynamic (sandbox) execution."""
    protocol: str = Field(description="'DNS', 'HTTP', 'HTTPS', 'TCP', or 'UDP'")
    destination: Optional[str] = Field(default=None, description="IP or domain")
    port: Optional[int] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    is_encrypted: bool = False
    is_c2_suspected: bool = False


class BehavioralIOC(BaseModel):
    """One behavioral indicator captured by the sandbox."""
    ioc_type: str = Field(description="'file', 'registry', 'process', or 'network'")
    action: str = Field(description="E.g. 'created', 'modified', 'deleted', 'spawned', 'connected'")
    value: str = Field(description="The path/key/command-line/endpoint involved")
    process_name: Optional[str] = None
    pid: Optional[int] = None
    severity: str = Field(default="Medium", description="High, Medium, or Low")


class StaticDynamicCorrelation(BaseModel):
    """One deterministic cross-check between a static capability claim and
    what the sandbox actually observed at runtime."""
    static_capability: str = Field(description="E.g. CAPA rule or MITRE technique the static pass flagged")
    dynamic_observation: Optional[str] = Field(default=None, description="What Cuckoo actually observed, if anything")
    corroborated: bool = Field(description="True if the runtime behavior matches the static expectation")
    discrepancy_note: Optional[str] = Field(
        default=None, description="Set when corroborated=False -- why the runtime behavior didn't match"
    )


class DynamicAnalysisReport(BaseModel):
    """Dynamic Sandbox Correlator & Behavior Evaluator output."""
    filepath: str
    sandbox_task_id: Optional[str] = None
    execution_succeeded: bool = False
    execution_verdict: Optional[str] = Field(default=None, description="Sandbox's own verdict/score label, if provided")
    process_tree: List[Dict[str, Any]] = Field(default_factory=list)
    behavioral_iocs: List[BehavioralIOC] = Field(default_factory=list)
    network_artifacts: List[NetworkArtifact] = Field(default_factory=list)
    correlations: List[StaticDynamicCorrelation] = Field(default_factory=list)
    anti_analysis_detected: List[str] = Field(default_factory=list, description="E.g. 'sandbox-aware sleep loop', 'VM artifact check'")
    risk_score: int = Field(ge=0, le=100, default=0)
    severity: str = Field(default="Low", description="Critical, High, Medium, or Low")
    summary: str = ""


class MalwareAnalysisReport(BaseModel):
    """Top-level File / Malware Analysis Father Agent aggregate -- what
    File_Analysis_Master_Report.json holds."""
    orchestrator: str = "File_Analysis_Father_Agent"
    staging_root: str
    timestamp: str
    target_file: Optional[str] = None
    static: Optional[StaticAnalysisReport] = None
    reverse_engineering: Optional[ReverseEngineeringModel] = None
    reverse_engineering_skipped_reason: Optional[str] = None
    dynamic: Optional[DynamicAnalysisReport] = None
    dynamic_skipped_reason: Optional[str] = Field(
        default=None, description="Set when the Father Agent's conditional logic skipped sandbox execution"
    )
    total_anomalies_flagged: int = 0
    critical_findings: List[Dict[str, Any]] = Field(default_factory=list)
    detailed_agent_reports: List[Dict[str, Any]] = Field(default_factory=list)


class ForensicAnomaly(BaseModel):
    filepath: str = Field(description="The full path of the suspicious artifact")
    anomaly_type: str = Field(description="E.g., 'Double Extension', 'Unsigned Binary', 'Suspicious Path'")
    severity: str = Field(description="High, Medium, or Low")
    justification: str = Field(description="Why this was flagged based on the parsed data")
    recommended_action: str = Field(description="What the HITL analyst should investigate next")


class AgentAnalysisReport(BaseModel):
    agent_name: str
    status: str = Field(description="Clean, Suspicious, or Critical")
    anomalies_found: List[ForensicAnomaly] = []
    summary: str = Field(description="A brief overview of the findings")


class AgentResponse(BaseModel):
    agent_name: str
    raw_data_parsed: Any
    ai_analysis: Dict
    status: str = "PENDING_APPROVAL"


class HumanFeedback(BaseModel):
    action: str
    feedback: Optional[str] = None
