//! MCP protocol types for security screening server

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// JSON-RPC version constant
pub const JSONRPC_VERSION: &str = "2.0";

/// MCP protocol version
pub const MCP_VERSION: &str = "2024-11-05";

/// JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: RequestId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// JSON-RPC request ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
}

/// JSON-RPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

impl JsonRpcError {
    pub fn parse_error() -> Self {
        Self {
            code: error_codes::PARSE_ERROR,
            message: "Parse error".to_string(),
            data: None,
        }
    }

    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: error_codes::METHOD_NOT_FOUND,
            message: format!("Method not found: {}", method),
            data: None,
        }
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: error_codes::INVALID_PARAMS,
            message: msg.into(),
            data: None,
        }
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self {
            code: error_codes::INTERNAL_ERROR,
            message: msg.into(),
            data: None,
        }
    }
}

/// Server capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(default)]
    pub list_changed: bool,
}

/// Server info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Initialize result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}

/// Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: InputSchema,
}

/// JSON Schema for tool input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, PropertySchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

impl InputSchema {
    pub fn object() -> Self {
        Self {
            schema_type: "object".to_string(),
            properties: HashMap::new(),
            required: Vec::new(),
        }
    }

    pub fn with_property(mut self, name: impl Into<String>, schema: PropertySchema) -> Self {
        self.properties.insert(name.into(), schema);
        self
    }

    pub fn with_required(mut self, name: impl Into<String>, schema: PropertySchema) -> Self {
        let name = name.into();
        self.required.push(name.clone());
        self.properties.insert(name, schema);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
}

impl PropertySchema {
    pub fn string(description: impl Into<String>) -> Self {
        Self {
            schema_type: "string".to_string(),
            description: Some(description.into()),
            enum_values: None,
        }
    }

    pub fn boolean(description: impl Into<String>) -> Self {
        Self {
            schema_type: "boolean".to_string(),
            description: Some(description.into()),
            enum_values: None,
        }
    }

    pub fn with_enum(mut self, values: Vec<&str>) -> Self {
        self.enum_values = Some(values.into_iter().map(|s| s.to_string()).collect());
        self
    }
}

/// Tool call request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolRequest {
    pub name: String,
    #[serde(default)]
    pub arguments: HashMap<String, Value>,
}

/// Tool call result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<Content>,
    #[serde(default)]
    pub is_error: bool,
}

impl CallToolResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text { text: text.into() }],
            is_error: false,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text {
                text: message.into(),
            }],
            is_error: true,
        }
    }

    pub fn json(value: Value) -> Self {
        Self {
            content: vec![Content::Text {
                text: serde_json::to_string_pretty(&value).unwrap_or_default(),
            }],
            is_error: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Content {
    #[serde(rename = "text")]
    Text { text: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MCP is camelCase on the wire. These fields were emitted snake_case
    /// (`protocol_version` / `server_info` / `list_changed` / `inputSchema` / `is_error`),
    /// which made `initialize` unparseable to spec-conforming clients — the server built and
    /// answered, but every client dropped the connection. Pin the wire names so a future
    /// struct edit cannot silently regress the handshake.
    #[test]
    fn initialize_result_is_camel_case_on_the_wire() {
        let v = serde_json::to_value(InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
            },
            server_info: ServerInfo {
                name: "security-mcp".to_string(),
                version: "0".to_string(),
            },
        })
        .unwrap();

        assert!(v.get("protocolVersion").is_some(), "got: {v}");
        assert!(v.get("serverInfo").is_some(), "got: {v}");
        assert!(
            v["capabilities"]["tools"].get("listChanged").is_some(),
            "got: {v}"
        );
        // ...and never the snake_case spellings.
        assert!(v.get("protocol_version").is_none(), "got: {v}");
        assert!(v.get("server_info").is_none(), "got: {v}");
    }

    #[test]
    fn tool_and_call_result_are_camel_case_on_the_wire() {
        let t = serde_json::to_value(Tool {
            name: "scan".to_string(),
            description: None,
            input_schema: InputSchema {
                schema_type: "object".to_string(),
                properties: HashMap::new(),
                required: Vec::new(),
            },
        })
        .unwrap();
        assert!(t.get("inputSchema").is_some(), "got: {t}");
        assert!(t.get("input_schema").is_none(), "got: {t}");

        let r = serde_json::to_value(CallToolResult::text("ok")).unwrap();
        assert!(r.get("isError").is_some(), "got: {r}");
        assert!(r.get("is_error").is_none(), "got: {r}");
    }
}
