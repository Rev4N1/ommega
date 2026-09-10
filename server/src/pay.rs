//! Aggregated-payment (Yipay / Mapay protocol) support.
//!
//! Supported platforms: Rainbow Yipay, PayJS, Mapay and other aggregated-payment platforms sharing the same protocol.
//! Just configure in `.env`:
//!   PAY_GATEWAY     = platform order endpoint, e.g. https://pay.example.com/submit.php
//!   PAY_PID         = merchant id
//!   PAY_KEY         = merchant key
//!   PAY_NOTIFY_URL  = async notify URL (this service: /api/card/pay_callback/)
//!   PAY_RETURN_URL  = sync return URL after payment completes
//!
//! Protocol notes (Yipay standard):
//!   - Order: POST form params pid/type/out_trade_no/notify_url/return_url/name/money to the gateway,
//!     together with an MD5 sign; the platform returns JSON: { code, msg, trade_no, qrcode, cashier_url, url }.
//!   - Sign: concatenate params by ascending key name as `k1=v1&k2=v2&...&key=<merchant key>`, then lowercase MD5.
//!   - Notify: the platform calls back notify_url (GET/POST form) carrying sign; once the signature verifies and
//!     trade_status == "TRADE_SUCCESS" the payment succeeded, and you must reply with the plain text `success`.

use std::collections::BTreeMap;

use md5::{Digest, Md5};
use serde_json::Value;

/// Compute the MD5 hex digest (lowercase) of a string.
pub fn md5_hex(s: &str) -> String {
    let digest = Md5::digest(s.as_bytes());
    format!("{digest:x}")
}

/// Render a QR code as an inline SVG `data:` URI so the front-end can show it
/// with a plain `<img>` tag, with no external JS/CDN dependency.
pub fn qrcode_svg_data_uri(content: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(content.as_bytes()).ok()?;
    let svg_text = code
        .render::<svg::Color>()
        .min_dimensions(260, 260)
        .quiet_zone(true)
        .build();
    let encoded =
        percent_encoding::utf8_percent_encode(&svg_text, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    Some(format!("data:image/svg+xml;charset=utf-8,{encoded}"))
}

/// Yipay signature: params sorted by ascending key, skipping empty values, append `key=<merchant key>`, lowercase MD5.
pub fn sign(params: &BTreeMap<String, String>, key: &str) -> String {
    let mut s = String::new();
    for (k, v) in params {
        if k == "sign" || k == "sign_type" || v.is_empty() {
            continue;
        }
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('&');
    }
    s.push_str("key=");
    s.push_str(key);
    md5_hex(&s)
}

/// Verify the callback signature (case-insensitive comparison).
pub fn verify_sign(params: &BTreeMap<String, String>, key: &str) -> bool {
    let Some(got) = params.get("sign") else {
        return false;
    };
    let expected = sign(params, key);
    got.eq_ignore_ascii_case(&expected)
}

/// Data returned by an aggregated-payment order.
pub struct OrderResp {
    /// Platform transaction number
    pub trade_no: String,
    /// QR code content (can be used directly to render a QR code)
    pub qrcode: String,
    /// Cashier URL (can be opened directly)
    pub cashier_url: String,
    /// Generic redirect link
    pub url: String,
}

/// Call the aggregated-payment platform to create a payment order.
pub async fn submit_order(
    gateway: &str,
    pid: &str,
    key: &str,
    pay_type: &str,
    out_trade_no: &str,
    notify_url: &str,
    return_url: &str,
    name: &str,
    money: &str,
) -> Result<OrderResp, String> {
    let mut params = BTreeMap::new();
    params.insert("pid".to_string(), pid.to_string());
    params.insert("type".to_string(), pay_type.to_string());
    params.insert("out_trade_no".to_string(), out_trade_no.to_string());
    params.insert("notify_url".to_string(), notify_url.to_string());
    params.insert("return_url".to_string(), return_url.to_string());
    params.insert("name".to_string(), name.to_string());
    params.insert("money".to_string(), money.to_string());
    let sign = sign(&params, key);
    params.insert("sign".to_string(), sign);
    params.insert("sign_type".to_string(), "MD5".to_string());

    let client = reqwest::Client::new();
    let resp = client
        .post(gateway)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("gateway request failed: {e}"))?;
    let text = resp
        .text()
        .await
        .map_err(|e| format!("failed to read gateway response: {e}"))?;

    let v: Value = serde_json::from_str(&text)
        .map_err(|_| format!("malformed gateway response: {text}"))?;
    let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    if code != 1 {
        let msg = v.get("msg").and_then(|m| m.as_str()).unwrap_or("unknown");
        return Err(format!("platform order failed (code={code}): {msg}"));
    }

    Ok(OrderResp {
        trade_no: v
            .get("trade_no")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        qrcode: v
            .get("qrcode")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        cashier_url: v
            .get("cashier_url")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        url: v
            .get("url")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// Parse a URL-encoded form / query string into a map.
pub fn parse_form(input: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for pair in input.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        let k = percent_decode(k);
        let v = percent_decode(v);
        if !k.is_empty() {
            m.insert(k, v);
        }
    }
    m
}

fn percent_decode(s: &str) -> String {
    // `+` denotes space in form encoding.
    let s = s.replace('+', " ");
    percent_encoding::percent_decode_str(&s)
        .decode_utf8_lossy()
        .to_string()
}
