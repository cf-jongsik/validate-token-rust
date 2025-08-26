use base64::prelude::*;
use hmac::{Hmac, Mac};
use js_sys::Date;
use sha2::Sha256;
use url::Url;
use wasm_bindgen::JsValue;
use worker::*;

const DEFAULT_HMAC_SECRET: &str = "default-secret";
const TOKEN_VALIDITY_SECONDS: f64 = 300000.0;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let secret = env
        .secret("HMAC_SECRET")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_else(|| DEFAULT_HMAC_SECRET.to_string());

    if secret.is_empty() {
        console_error!("missing secret");
        return Ok(Response::from_html("missing secret")?.with_status(400));
    }

    let url = Url::parse(&req.url()?.to_string())?;
    let mut query_pairs: std::collections::HashMap<String, String> = url
        .query()
        .unwrap_or_default()
        .split('&')
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap();
            (key.to_string(), value.to_string())
        })
        .collect();
    match query_pairs.get("function_id") {
        Some(id) if id == "APPS_LOGIN_DEFAULT" => {}
        Some(_) => {
            console_error!("Not a login request - bypassing HMAC validation");
            return Fetch::Request(req).send().await;
        }
        None => {
            console_error!("missing function_id - bypassing HMAC validation");
            return Fetch::Request(req).send().await;
        }
    }
    let oait_param = query_pairs.get("oait").ok_or_else(|| "")?.to_string();
    if oait_param.is_empty() {
        console_error!("Missing oait parameter");
        return Ok(Response::from_html("Missing oait parameter")?.with_status(400));
    }
    let tokens: Vec<&str> = oait_param.split("++").collect();
    if tokens.len() < 2 {
        console_error!("Invalid token format-oaitParam: {}", oait_param);
        return Ok(Response::from_html("Invalid token format")?.with_status(403));
    }

    let forms_token = tokens[0];
    let cloudflare_token = tokens[1].trim();
    let access_token = tokens.get(2).unwrap_or(&"");

    let client_ip = extract_client_ip(&req);
    console_log!(
        "formsToken:{}, clientIP:{}, providedToken:{}, accessToken:{}",
        forms_token,
        client_ip,
        cloudflare_token,
        access_token
    );

    let token_validity_seconds = env
        .var("TOKEN_VALIDITY_SECONDS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(TOKEN_VALIDITY_SECONDS);

    if !verify_hmac_token(
        &client_ip,
        cloudflare_token,
        &secret,
        token_validity_seconds,
    ) {
        return Ok(Response::from_html("Invalid or expired token")?.with_status(403));
    }

    let mut new_url = Url::from(url);
    new_url.query_pairs_mut().clear();
    query_pairs.remove("oait");
    for (key, value) in query_pairs {
        new_url.query_pairs_mut().append_pair(&key, &value);
    }
    if !forms_token.is_empty() {
        new_url.query_pairs_mut().append_pair("oait", forms_token);
    }

    let mut request_init = RequestInit::new();
    request_init.with_method(req.method());
    request_init.with_headers(req.headers().clone());
    let body = req.clone()?.bytes().await?;
    if !body.is_empty() {
        request_init.with_body(Some(JsValue::from(body)));
    }
    let new_req = Request::new_with_init(&new_url.to_string(), &request_init)?;

    let new_response = Fetch::Request(new_req).send().await?;
    let new_headers = new_response.headers().clone();

    // Add access token cookie if available
    if !access_token.is_empty() {
        new_headers.set(
            "Set-Cookie",
            &format!(
                "CF_Authorization={}; Path=/; HttpOnly; Secure; SameSite=Strict",
                access_token
            ),
        )?;
    }

    Ok(Response::from_body(new_response.body().clone())?
        .with_headers(new_headers)
        .with_status(new_response.status_code()))
}

fn extract_client_ip(req: &Request) -> String {
    req.headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .or_else(|| {
            req.headers()
                .get("X-Forwarded-For")
                .ok()
                .flatten()
                .and_then(|xff| xff.split(',').next().map(|ip| ip.trim().to_string()))
        })
        .unwrap_or_else(|| {
            console_error!("No client IP found in headers, using default");
            "127.0.0.1".to_string()
        })
}

fn verify_hmac_token(
    client_ip: &str,
    provided_token: &str,
    secret: &str,
    validity_seconds: f64,
) -> bool {
    let token_parts: Vec<&str> = provided_token.split('-').collect();
    if token_parts.len() != 2 {
        return false;
    }

    let timestamp: f64 = match token_parts[0].parse() {
        Ok(ts) => ts,
        Err(_) => return false,
    };

    let provided_hash = token_parts[1];
    let current_time = Date::now() / 1000.0;

    if current_time - timestamp > validity_seconds {
        return false;
    }

    let expected_hash = generate_hash(client_ip, secret, timestamp);
    constant_time_compare(&expected_hash, provided_hash)
}

fn generate_hash(client_ip: &str, hmac_secret: &str, timestamp: f64) -> String {
    let message = format!("{}:{}", client_ip, timestamp);
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    BASE64_STANDARD.encode(mac.finalize().into_bytes())
}

fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        console_error!("length mismatch!");
        return false;
    }

    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
