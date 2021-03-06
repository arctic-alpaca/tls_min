
use axum::{handler::Handler, http::{Request, Response}, response::IntoResponse};
use core::task::{Context, Poll};
use futures::{stream::Stream};
use hyper::Body;

use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::pin::Pin;
use std::vec::Vec;
use std::{io, net::SocketAddr, sync};
use axum::extract::ConnectInfo;
use futures::future::poll_fn;
use hyper::server::accept::Accept;

use hyper::server::conn::{AddrIncoming, Http};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self};
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tower::{MakeService, ServiceBuilder};

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "tls_min=trace,tower_http=debug")
    }
    tracing_subscriber::fmt::init();

    let mut certs_path = std::env::current_dir().unwrap();
    certs_path.push("self_signed_certs");
    certs_path.push("cert.pem");
    let mut keys_path = std::env::current_dir().unwrap();
    keys_path.push("self_signed_certs");
    keys_path.push("key.pem");

    let tls_addr = SocketAddr::from(([127, 0, 0, 1], 4001));
    let certs = load_certs(certs_path.as_path()).unwrap();
    let mut keys = load_keys(keys_path.as_path()).unwrap();
    let tls_cfg = {
        let mut config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
            .unwrap();
        // have to add h2 later and work out how to deal with that
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        sync::Arc::new(config)
    };

    let tcp_listener = TcpListener::bind(&tls_addr).await.unwrap();
    let mut tcp_listener = AddrIncoming::from_listener(tcp_listener).unwrap();
    let tls_acceptor = TlsAcceptor::from(tls_cfg);

    let tls_service = ServiceBuilder::new().service(handler);
    let non_tls_service = ServiceBuilder::new().service(handler);
    let mut tls_service_maker = tls_service.into_make_service_with_connect_info::<SocketAddr, _>();

    let tls_server = tokio::spawn ( async move {
    loop {
        let stream = poll_fn(|cx| Pin::new(&mut tcp_listener).poll_accept(cx))
            .await
            .unwrap()
            .unwrap();

        let tls_acceptor = tls_acceptor.clone();

        let app = tls_service_maker.make_service(&stream).await.unwrap();

        tokio::spawn(async move {
            if let Ok(stream) = tls_acceptor.accept(stream).await {
                let _ = Http::new().serve_connection(stream, app).await;
            }
        });
    }});
    let non_tls_addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    let non_tls_server = axum::Server::bind(&non_tls_addr)
        .serve(non_tls_service.into_make_service_with_connect_info::<SocketAddr, _>());
    tokio::select! {
        _ = (tls_server) => {
            tracing::trace!("tls server stopped");
            return;},
        _ = (non_tls_server) => {
            tracing::trace!("non_tls server stopped");
            return;},
    };
}

struct HyperAcceptor<'a> {
    acceptor: Pin<Box<dyn Stream<Item = Result<TlsStream<TcpStream>, io::Error>> + 'a>>,
}

impl hyper::server::accept::Accept for HyperAcceptor<'_> {
    type Conn = TlsStream<TcpStream>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}

async fn handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> impl IntoResponse {
    tracing::trace!("server incoming request, addr = {:?}", addr);
    tracing::trace!("server incoming request, req = {:?}", req);

    Response::new(Body::from("Hello, world!"))
        .into_response()
        .map(axum::body::box_body)
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}
