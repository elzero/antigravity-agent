use base64::{
    engine::general_purpose::{
        STANDARD as BASE64_STANDARD, STANDARD_NO_PAD as BASE64_STANDARD_NO_PAD,
        URL_SAFE as BASE64_URL_SAFE, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
    },
    Engine as _,
};
use prost::Message;
use serde_json::Value;

pub fn decode_base64(raw: &str, field_name: &str) -> Result<Vec<u8>, String> {
    BASE64_STANDARD
        .decode(raw)
        .or_else(|_| BASE64_STANDARD_NO_PAD.decode(raw))
        .or_else(|_| BASE64_URL_SAFE.decode(raw))
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(raw))
        .map_err(|e| format!("{} Base64 解码失败: {}", field_name, e))
}

pub fn decode_oauth_token(raw: &str) -> Result<Value, String> {
    let wrapper_bytes = decode_base64(raw, crate::constants::database::OAUTH_TOKEN)?;
    let wrapper = crate::proto::state_sync::OAuthTokenWrapper::decode(wrapper_bytes.as_slice())
        .map_err(|e| format!("oauthToken Wrapper Proto 解码失败: {}", e))?;

    let inner = wrapper
        .inner
        .ok_or_else(|| "oauthToken 缺少 inner".to_string())?;
    let data = inner
        .data
        .ok_or_else(|| "oauthToken 缺少 data".to_string())?;

    // 尝试两种格式：新版(JSON) 和 旧版(Base64 Proto)
    let oauth_info_result = if data.oauth_info_base64.starts_with('{') {
        // 新版格式：直接是 JSON 字符串
        serde_json::from_str::<Value>(&data.oauth_info_base64)
            .map_err(|e| format!("oauth_info_base64 JSON 解析失败: {}", e))
    } else {
        // 旧版格式：Base64 编码的 Proto 数据
        let oauth_info_bytes =
            decode_base64(&data.oauth_info_base64, "oauthToken.data.oauth_info_base64")?;
        let oauth_info = crate::proto::state_sync::OAuthInfo::decode(oauth_info_bytes.as_slice())
            .map_err(|e| format!("oauthToken OAuthInfo Proto 解码失败: {}", e))?;

        Ok(serde_json::json!({
            "accessToken": oauth_info.access_token,
            "refreshToken": oauth_info.refresh_token,
            "tokenType": oauth_info.token_type,
            "expirySeconds": oauth_info.expiry.map(|t| t.seconds),
        }))
    };

    let oauth_info = oauth_info_result?;

    // 合并 sentinelKey 和 oauth_info 内容
    let mut result = oauth_info;
    if let Some(obj) = result.as_object_mut() {
        obj.insert("sentinelKey".to_string(), Value::String(inner.sentinel_key.clone()));
    }

    Ok(result)
}

pub fn decode_user_status(raw: &str) -> Result<Value, String> {
    let wrapper_bytes = decode_base64(raw, crate::constants::database::USER_STATUS)?;
    let wrapper = crate::proto::state_sync::UserStatusWrapper::decode(wrapper_bytes.as_slice())
        .map_err(|e| format!("userStatus Wrapper Proto 解码失败: {}", e))?;

    let inner = wrapper
        .inner
        .ok_or_else(|| "userStatus 缺少 inner".to_string())?;
    let data = inner
        .data
        .ok_or_else(|| "userStatus 缺少 data".to_string())?;

    let raw_data_bytes = decode_base64(&data.raw_data, "userStatus.data.raw_data")?;
    let context = crate::proto::state_sync::UserContext::decode(raw_data_bytes.as_slice())
        .map_err(|e| format!("userStatus raw_data UserContext Proto 解码失败: {}", e))?;

    Ok(serde_json::json!({
        "sentinelKey": inner.sentinel_key,
        "rawDataType": "proto",
        "rawData": crate::utils::user_context_view::user_context_to_json(context),
    }))
}

/// 优先从 OAuth Token 中提取 Access Token，如果没有或失败，则回退到 api_key
pub fn extract_preferred_access_token(
    oauth_token_raw: Option<&str>,
    auth_status_json: &Value,
) -> Result<String, String> {
    if let Some(token_raw) = oauth_token_raw {
        // 尝试解码 OAuth Token
        match decode_oauth_token(token_raw) {
            Ok(token_value) => {
                // 如果解码成功，尝试获取 accessToken
                let access_token = token_value
                    .get("accessToken")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());

                if let Some(at) = access_token {
                    return Ok(at);
                }
                // 如果 OAuth Token 里拿不到 accessToken，或者为空，则回退到下面的逻辑
            }
            // 解码失败，也回退
            Err(_) => {}
        }
    }

    // 回退：从 auth_status_json 中获取 apiKey
    let api_key = auth_status_json
        .get("apiKey")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
        .to_string();

    if api_key.is_empty() {
        return Err("无法获取有效的 Access Token (OAuth Token 和 API Key 均不可用)".to_string());
    }

    Ok(api_key)
}

/// 从 OAuth Token 中提取 Refresh Token
pub fn extract_refresh_token(oauth_token_raw: Option<&str>) -> Option<String> {
    let token_raw = oauth_token_raw?;
    match decode_oauth_token(token_raw) {
        Ok(token_value) => token_value
            .get("refreshToken")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        Err(_) => None,
    }
}
