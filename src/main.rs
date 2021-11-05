use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::vec::Vec;
use tokio_rustls::rustls::{Certificate, PrivateKey};
use async_stream::stream;
use axum::{
    extract::{ConnectInfo, Extension},
    handler::Handler,
    http::{uri::Uri, Request, Response},
    response::IntoResponse,
    AddExtensionLayer,
};
use core::task::{Context, Poll};
use futures::{future::TryFutureExt, stream::Stream};
use hyper::Server;
use hyper::{client::HttpConnector, Body};
use std::pin::Pin;
use std::{convert::TryFrom, io, net::SocketAddr, sync};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tower::ServiceBuilder;


type Client = hyper::client::Client<HttpConnector, Body>;

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "tls_min=trace,tower_http=debug")
    }
    tracing_subscriber::fmt::init();

    tokio::spawn(server());

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

    let tcp = TcpListener::bind(&tls_addr).await.unwrap();
    let tls_acceptor = TlsAcceptor::from(tls_cfg);

    let incoming_tls_stream = stream! {
        loop {
            let (socket, _) = tcp.accept().await?;
            let stream = tls_acceptor.accept(socket).map_err(|e| {
                println!("[!] Voluntary server halt due to client-connection error...");
                // Errors could be handled here, instead of server aborting.
                // Ok(None)
                error(format!("TLS Error: {:?}", e))
            });
            yield stream.await;
        }
    };

    let tls_service = ServiceBuilder::new()
        .service(handler_proxy)
        .layer(ServiceBuilder::new().layer(AddExtensionLayer::new(Client::new())));

    // This is the approach that's currently not working
    /*
    let tls_server_non_working = Server::builder(HyperAcceptor {
        acceptor: Box::pin(incoming_tls_stream),
    })
    .serve(tls_service.into_make_service_with_connect_info::<SocketAddr, _>())
    .await
    .unwrap();
    */

    let tls_server_working = Server::builder(HyperAcceptor {
        acceptor: Box::pin(incoming_tls_stream),
    })
    .serve(tls_service.into_make_service())
    .await
    .unwrap();
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

async fn handler_proxy(
    Extension(client): Extension<Client>,
    mut req: Request<Body>,
) -> impl IntoResponse {
    tracing::trace!("reverse proxy incoming request, https");
    tracing::trace!("reverse proxy incoming request, req = {:?}", req);

    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);

    let uri = format!("http://127.0.0.1:3000{}", path_query);

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    let response = client.request(req).await.unwrap();
    tracing::trace!("proxy response: {:?}", response);
    response.into_response().map(axum::body::box_body)
}

async fn server() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    tracing::debug!("server listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(handler_server.into_make_service_with_connect_info::<SocketAddr, _>())
        .await
        .unwrap();
}

async fn handler_server(
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
