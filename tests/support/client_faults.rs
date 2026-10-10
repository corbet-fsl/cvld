//! Wire corruption after a real door mutation; shared native/browser vectors.
use axum::{body::Body, response::Response};

/// Both values have the real schema's type. Ordinary Value decoding would
/// silently retain the second issuer and accept this ambiguous owner response.
pub fn duplicate_public_response(value: &serde_json::Value) -> Response {
    let body = serde_json::to_string(value).unwrap();
    assert!(body.starts_with('{'));
    Response::new(Body::from(format!(r#"{{"issuer":[],{}"#, &body[1..])))
}

pub fn corrupted_response(mode: usize) -> Response {
    match mode {
        0 => Response::new(Body::from("{")),
        1 => Response::builder()
            .status(403)
            .body(Body::from("{\"error\":\"unavailable\"}"))
            .unwrap(),
        2 => Response::new(Body::from("null")),
        3 => Response::builder()
            .status(302)
            .header("location", "/v1/logout")
            .body(Body::empty())
            .unwrap(),
        4 => Response::new(Body::from("{\"error\":\"unauthorized\"}")),
        5 => Response::builder()
            .header("content-length", 17 * 1024 * 1024)
            .body(Body::empty())
            .unwrap(),
        6 => Response::new(Body::from_stream(futures_util::stream::iter([
            Ok(axum::body::Bytes::from_static(b"{")),
            Err(std::io::Error::other("synthetic truncated response")),
        ]))),
        7 => Response::new(Body::from_stream(futures_util::stream::iter([Ok::<
            _,
            std::io::Error,
        >(
            vec![b' '; 17 * 1024 * 1024],
        )]))),
        8 => Response::new(Body::from("{\"unexpected\":true}")),
        9 => Response::new(Body::from("{\"issuer\":[]}")),
        10 => Response::new(Body::from_stream(futures_util::stream::once(async {
            tokio::time::sleep(std::time::Duration::from_secs(31)).await;
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{}"))
        }))),
        11 => Response::builder()
            .status(401)
            .body(Body::from(
                r#"{"error":"unavailable","error":"unauthorized"}"#,
            ))
            .unwrap(),
        12 => Response::new(Body::from(r#"{"duplicate":false,"duplicate":true}"#)),
        _ => panic!("unknown wire-corruption vector"),
    }
}
