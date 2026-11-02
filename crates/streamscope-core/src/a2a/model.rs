//! Protocol-agnostic A2A domain types. The dispatcher, policy, guardrail,
//! and audit layers operate on these — never on dialect-specific wire shapes
//! (`wire::v1_0` converts in; a future 0.3 dialect converts into the same
//! types).

use serde_json::Value;

/// The 11 A2A operations (1.0 vocabulary). `Unknown` carries the raw method
/// string for the `-32601` reply and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum A2aMethod {
    SendMessage,
    SendStreamingMessage,
    GetTask,
    ListTasks,
    CancelTask,
    SubscribeToTask,
    CreateTaskPushNotificationConfig,
    GetTaskPushNotificationConfig,
    ListTaskPushNotificationConfigs,
    DeleteTaskPushNotificationConfig,
    GetExtendedAgentCard,
    Unknown(String),
}

impl A2aMethod {
    pub fn parse(method: &str) -> Self {
        match method {
            "SendMessage" => Self::SendMessage,
            "SendStreamingMessage" => Self::SendStreamingMessage,
            "GetTask" => Self::GetTask,
            "ListTasks" => Self::ListTasks,
            "CancelTask" => Self::CancelTask,
            "SubscribeToTask" => Self::SubscribeToTask,
            "CreateTaskPushNotificationConfig" => Self::CreateTaskPushNotificationConfig,
            "GetTaskPushNotificationConfig" => Self::GetTaskPushNotificationConfig,
            "ListTaskPushNotificationConfigs" => Self::ListTaskPushNotificationConfigs,
            "DeleteTaskPushNotificationConfig" => Self::DeleteTaskPushNotificationConfig,
            "GetExtendedAgentCard" => Self::GetExtendedAgentCard,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::SendMessage => "SendMessage",
            Self::SendStreamingMessage => "SendStreamingMessage",
            Self::GetTask => "GetTask",
            Self::ListTasks => "ListTasks",
            Self::CancelTask => "CancelTask",
            Self::SubscribeToTask => "SubscribeToTask",
            Self::CreateTaskPushNotificationConfig => "CreateTaskPushNotificationConfig",
            Self::GetTaskPushNotificationConfig => "GetTaskPushNotificationConfig",
            Self::ListTaskPushNotificationConfigs => "ListTaskPushNotificationConfigs",
            Self::DeleteTaskPushNotificationConfig => "DeleteTaskPushNotificationConfig",
            Self::GetExtendedAgentCard => "GetExtendedAgentCard",
            Self::Unknown(s) => s,
        }
    }

    /// The four push-notification-config operations (rejected in v1 — the
    /// rewritten card advertises `pushNotifications: false`).
    pub fn is_push_notification_config(&self) -> bool {
        matches!(
            self,
            Self::CreateTaskPushNotificationConfig
                | Self::GetTaskPushNotificationConfig
                | Self::ListTaskPushNotificationConfigs
                | Self::DeleteTaskPushNotificationConfig
        )
    }

    /// Operations answered with an SSE stream.
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::SendStreamingMessage | Self::SubscribeToTask)
    }

    /// Operations that carry a caller-authored message — what the **request**
    /// hops screen. Every other operation addresses a task by id and sends no
    /// content of its own.
    pub fn is_message(&self) -> bool {
        matches!(self, Self::SendMessage | Self::SendStreamingMessage)
    }

    /// Operations whose reply can carry agent-authored content — what the
    /// **response** hops screen.
    ///
    /// This is deliberately wider than [`is_message`]: a long-running agent
    /// answers `SendMessage` with an empty `TASK_STATE_SUBMITTED` task and
    /// delivers its actual work later, through `GetTask` / `SubscribeToTask` /
    /// `ListTasks` — and `CancelTask` returns the canceled task with whatever it
    /// produced before it stopped. Screening only the methods that *sent* a
    /// message would leave the entire asynchronous flow — the normal one for real
    /// agents — unscreened, which is precisely the channel the response phase
    /// exists to close.
    ///
    /// `GetExtendedAgentCard` is in the list too: a card is not a task, but its
    /// `description` / `skills[].description` prose is agent-authored text the
    /// caller's model reads as documentation — a documented A2A injection vector.
    /// `card::rewrite_card` fixes the card's endpoint and auth scheme; a rewrite is
    /// not a screen.
    ///
    /// Only the four push-notification-config methods stay out — they are refused
    /// outright and never reach an agent.
    pub fn reply_carries_content(&self) -> bool {
        !self.is_push_notification_config() && !matches!(self, Self::Unknown(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2aRole {
    User,
    Agent,
}

/// Task lifecycle state. `Other` keeps an unrecognized wire value lossless
/// (forward compatibility — never silently dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum A2aTaskState {
    Submitted,
    Working,
    Completed,
    Failed,
    Canceled,
    Rejected,
    InputRequired,
    AuthRequired,
    Other(String),
}

impl A2aTaskState {
    /// Terminal states close streams and forbid `SubscribeToTask`.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Canceled | Self::Rejected
        )
    }
}

/// One content part of a message or artifact. Media semantics mirror
/// `DomainContentBlock`: unrecognized shapes land in `Unknown` (lossless),
/// never dropped.
#[derive(Debug, Clone, PartialEq)]
pub enum A2aPart {
    Text {
        text: String,
        media_type: Option<String>,
    },
    /// Inline binary — kept base64-encoded as on the wire; decoded only by
    /// the media-blob capture path.
    Raw {
        base64: String,
        media_type: Option<String>,
        filename: Option<String>,
    },
    Url {
        url: String,
        media_type: Option<String>,
        filename: Option<String>,
    },
    Data {
        data: Value,
        media_type: Option<String>,
    },
    Unknown(Value),
}

#[derive(Debug, Clone, PartialEq)]
pub struct A2aMessage {
    pub message_id: String,
    pub context_id: Option<String>,
    pub task_id: Option<String>,
    pub role: A2aRole,
    pub parts: Vec<A2aPart>,
    pub extensions: Vec<String>,
    pub reference_task_ids: Vec<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct A2aArtifact {
    pub artifact_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub parts: Vec<A2aPart>,
    pub extensions: Vec<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct A2aTaskStatus {
    pub state: A2aTaskState,
    /// Agent-authored status explanation.
    pub message: Option<Box<A2aMessage>>,
    /// ISO 8601 UTC as on the wire.
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct A2aTask {
    pub id: String,
    pub context_id: Option<String>,
    pub status: A2aTaskStatus,
    pub artifacts: Vec<A2aArtifact>,
    pub history: Vec<A2aMessage>,
    pub metadata: Option<Value>,
}

/// One streamed `StreamResponse` payload (also the non-streaming
/// `SendMessage` result shape via `Task`/`Message`).
#[derive(Debug, Clone, PartialEq)]
pub enum A2aStreamEvent {
    Task(A2aTask),
    Message(A2aMessage),
    StatusUpdate {
        task_id: String,
        context_id: Option<String>,
        status: A2aTaskStatus,
    },
    ArtifactUpdate {
        task_id: String,
        context_id: Option<String>,
        artifact: A2aArtifact,
        append: bool,
        last_chunk: bool,
    },
    Unknown(Value),
}

impl A2aStreamEvent {
    /// Correlators for audit columns: `(context_id, task_id, state)` — each
    /// only when this event carries it.
    pub fn correlators(&self) -> (Option<&str>, Option<&str>, Option<&A2aTaskState>) {
        match self {
            Self::Task(t) => (t.context_id.as_deref(), Some(t.id.as_str()), Some(&t.status.state)),
            Self::Message(m) => (m.context_id.as_deref(), m.task_id.as_deref(), None),
            Self::StatusUpdate {
                task_id,
                context_id,
                status,
            } => (context_id.as_deref(), Some(task_id.as_str()), Some(&status.state)),
            Self::ArtifactUpdate {
                task_id, context_id, ..
            } => (context_id.as_deref(), Some(task_id.as_str()), None),
            Self::Unknown(_) => (None, None, None),
        }
    }
}

/// Parsed `SendMessage` / `SendStreamingMessage` params — the deep-treatment
/// path (policy + guardrail + full capture). Other methods forward their
/// params as raw JSON and only extract ids.
#[derive(Debug, Clone)]
pub struct A2aSendParams {
    pub message: A2aMessage,
    /// `configuration` forwarded opaquely (returnImmediately, historyLength,
    /// acceptedOutputModes — the gateway does not alter execution mode).
    pub configuration: Option<Value>,
    pub metadata: Option<Value>,
    /// AgentInterface tenant echo — forwarded verbatim.
    pub tenant: Option<String>,
}

/// A parsed inbound JSON-RPC call.
#[derive(Debug, Clone)]
pub struct A2aRequest {
    /// JSON-RPC request id (echoed on the response envelope).
    pub rpc_id: Value,
    pub method: A2aMethod,
    /// Raw params as received — the forwarding source of truth (the typed
    /// views above are read-only extractions).
    pub params: Value,
}

/// Correlator/context ids extracted from any method's params for audit.
#[derive(Debug, Clone, Default)]
pub struct A2aParamIds {
    pub task_id: Option<String>,
    pub context_id: Option<String>,
}

impl A2aRequest {
    /// Best-effort id extraction across the method vocabulary: `id` is the
    /// task id for task-scoped ops; `taskId`/`contextId` appear on push-config
    /// and list filters.
    pub fn param_ids(&self) -> A2aParamIds {
        let get = |key: &str| {
            self.params
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let task_id = match self.method {
            A2aMethod::GetTask
            | A2aMethod::CancelTask
            | A2aMethod::SubscribeToTask => get("id"),
            _ => get("taskId"),
        };
        A2aParamIds {
            task_id,
            context_id: get("contextId"),
        }
    }
}

