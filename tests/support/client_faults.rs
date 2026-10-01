//! Wire corruption after a real door mutation; shared native/browser vectors.
use axum::{body::Body, response::Response};

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
        _ => panic!("unknown wire-corruption vector"),
    }
}
