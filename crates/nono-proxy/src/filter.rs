use hyper::{Body, Request, Response, StatusCode};
use std::sync::Arc;

pub struct Filter {
    allowed_domains: Vec<String>,
    blocked_content_types: Vec<String>,
}

impl Filter {
    pub fn new(allowed_domains: Vec<String>, blocked_content_types: Vec<String>) -> Self {
        Self {
            allowed_domains,
            blocked_content_types,
        }
    }

    pub async fn apply(
        &self,
        req: Request<Body>,
        res: Response<Body>,
    ) -> Result<Response<Body>, hyper::Error> {
        // Domain filtering (simplified)
        let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("unknown");
        if !self.allowed_domains.iter().any(|d| host.ends_with(d)) {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())?);
        }

        // Content-type filtering
        let content_type = res.headers().get("content-type").and_then(|v| v.to_str().ok());
        if let Some(ct) = content_type {
            if self.blocked_content_types.iter().any(|p| ct.starts_with(p)) {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::empty())?);
            }
        }

        Ok(res)
    }
}