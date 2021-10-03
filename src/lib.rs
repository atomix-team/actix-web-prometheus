/*!
Prometheus instrumentation for [actix-web](https://github.com/actix/actix-web).
This middleware is inspired by and forked from [actix-web-prom](https://github.com/nlopes/actix-web-prom).
By default three metrics are tracked (this assumes the namespace `actix_web_prometheus`):
  - `actix_web_prometheus_incoming_requests` (labels: endpoint, method, status): the total number
   of HTTP requests handled by the actix HttpServer.
  - `actix_web_prometheus_response_code` (labels: endpoint, method, statuscode, type): Response codes
   of all HTTP requests handled by the actix HttpServer.
  - `actix_web_prometheus_response_time` (labels: endpoint, method, status): Total the request duration
   of all HTTP requests handled by the actix HttpServer.
# Usage
First add `actix-web-prom` to your `Cargo.toml`:
```toml
[dependencies]
actix-web-prometheus = "0.1.0-beta.8"
```
You then instantiate the prometheus middleware and pass it to `.wrap()`:
```rust
use std::collections::HashMap;
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prometheus::{PrometheusMetrics, PrometheusMetricsBuilder};
fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut labels = HashMap::new();
    labels.insert("label1".to_string(), "value1".to_string());
    let prometheus = PrometheusMetricsBuilder::new("api")
        .endpoint("/metrics")
        .const_labels(labels)
        .build()
        .unwrap();
# if false {
        HttpServer::new(move || {
            App::new()
                .wrap(prometheus.clone())
                .service(web::resource("/health").to(health))
        })
        .bind("127.0.0.1:8080")?
        .run()
        .await?;
# }
    Ok(())
}
```
Using the above as an example, a few things are worth mentioning:
 - `api` is the metrics namespace
 - `/metrics` will be auto exposed (GET requests only) with Content-Type header `content-type: text/plain; version=0.0.4; charset=utf-8`
 - `Some(labels)` is used to add fixed labels to the metrics; `None` can be passed instead
  if no additional labels are necessary.
A call to the /metrics endpoint will expose your metrics:
```shell
$ curl http://localhost:8080/metrics
# HELP actix_web_prometheus_incoming_requests Incoming Requests
# TYPE actix_web_prometheus_incoming_requests counter
actix_web_prometheus_incoming_requests{endpoint="/metrics",method="GET",status="200"} 23
# HELP actix_web_prometheus_response_code Response Codes
# TYPE actix_web_prometheus_response_code counter
actix_web_prometheus_response_code{endpoint="/metrics",method="GET",statuscode="200",type="200"} 23
# HELP actix_web_prometheus_response_time Response Times
# TYPE actix_web_prometheus_response_time histogram
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="0.005"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="0.01"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="0.025"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="0.05"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="0.1"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="0.25"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="0.5"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="1"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="2.5"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="5"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="10"} 23
actix_web_prometheus_response_time_bucket{endpoint="/metrics",method="GET",status="200",le="+Inf"} 23
actix_web_prometheus_response_time_sum{endpoint="/metrics",method="GET",status="200"} 0.00410981
actix_web_prometheus_response_time_count{endpoint="/metrics",method="GET",status="200"} 23
```

## Features
If you enable `process` feature of this crate, default process metrics will also be collected.
[Default process metrics](https://prometheus.io/docs/instrumenting/writing_clientlibs/#process-metrics)

```shell
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 0.22
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1048576
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 78
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 17526784
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1628105774.92
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 1893163008
```

## Custom metrics
You instantiate `PrometheusMetrics` and then use its `.registry` to register your custom
metric (in this case, we use a `IntCounterVec`).
Then you can pass this counter through `.data()` to have it available within the resource
responder.
```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_prometheus::{PrometheusMetrics, PrometheusMetricsBuilder};
use prometheus::{opts, IntCounterVec};
fn health(counter: web::Data<IntCounterVec>) -> HttpResponse {
    counter.with_label_values(&["endpoint", "method", "status"]).inc();
    HttpResponse::Ok().finish()
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let prometheus = PrometheusMetricsBuilder::new("api")
        .endpoint("/metrics")
        .build()
        .unwrap();
    let counter_opts = opts!("counter", "some random counter").namespace("api");
    let counter = IntCounterVec::new(counter_opts, &["endpoint", "method", "status"]).unwrap();
    prometheus
        .registry
        .register(Box::new(counter.clone()))
        .unwrap();
# if false {
        HttpServer::new(move || {
            App::new()
                .wrap(prometheus.clone())
                .app_data(web::Data::new(counter.clone()))
                .service(web::resource("/health").to(health))
        })
        .bind("127.0.0.1:8080")?
        .run()
        .await?;
# }
    Ok(())
}
```
 */

pub mod error;
pub use error::Error;

use actix_web::{
    dev::{BodySize, MessageBody, Service, ServiceRequest, ServiceResponse, Transform},
    http::{header::CONTENT_TYPE, HeaderValue, Method, StatusCode},
    web::Bytes,
    Error as ActixError,
};
use futures_lite::future::{ready, Ready};
use futures_lite::ready;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

#[derive(Debug)]
/// Builder to create new PrometheusMetrics struct.HistogramVec
///
/// It allow set optional parameters like registry, buckets, etc.
pub struct PrometheusMetricsBuilder {
    namespace: String,
    endpoint: Option<String>,
    const_labels: HashMap<String, String>,
    registry: Option<Registry>,
    buckets: Vec<f64>,
}

impl PrometheusMetricsBuilder {
    /// Create new PrometheusMetricsBuilder
    ///
    /// namespace example: "actix"
    pub fn new(namespace: &str) -> Self {
        Self {
            namespace: namespace.into(),
            endpoint: None,
            const_labels: HashMap::new(),
            registry: Some(Registry::new()),
            buckets: prometheus::DEFAULT_BUCKETS.to_vec(),
        }
    }

    /// Set actix web endpoint
    ///
    /// Example: "/metrics"
    pub fn endpoint(mut self, value: &str) -> Self {
        self.endpoint = Some(value.into());
        self
    }

    /// Set histogram buckets
    pub fn buckets(mut self, value: &[f64]) -> Self {
        self.buckets = value.to_vec();
        self
    }

    /// Set labels to add on every metrics
    pub fn const_labels(mut self, value: HashMap<String, String>) -> Self {
        self.const_labels = value;
        self
    }

    /// Set registry
    ///
    /// By default one is set and is internal to PrometheusMetrics
    pub fn registry(mut self, value: Registry) -> Self {
        self.registry = Some(value);
        self
    }

    /// Instantiate PrometheusMetrics struct
    pub fn build(self) -> Result<PrometheusMetrics, Error> {
        let registry = match self.registry {
            Some(registry) => registry,
            None => Registry::new(),
        };

        let incoming_requests = IntCounterVec::new(
            Opts::new("incoming_requests", "Incoming Requests")
                .namespace(&self.namespace)
                .const_labels(self.const_labels.clone()),
            &["endpoint", "method", "status"],
        )?;

        let response_time = HistogramVec::new(
            HistogramOpts::new("response_time", "Response Times")
                .namespace(&self.namespace)
                .const_labels(self.const_labels.clone())
                .buckets(self.buckets.clone()),
            &["endpoint", "method", "status"],
        )?;

        let response_codes = IntCounterVec::new(
            Opts::new("response_code", "Response Codes")
                .namespace(&self.namespace)
                .const_labels(self.const_labels.clone()),
            &["endpoint", "method", "statuscode", "type"],
        )?;

        registry.register(Box::new(incoming_requests.clone()))?;
        registry.register(Box::new(response_time.clone()))?;
        registry.register(Box::new(response_codes.clone()))?;

        Ok(PrometheusMetrics {
            clock: quanta::Clock::new(),
            registry,
            namespace: self.namespace,
            endpoint: self.endpoint,
            const_labels: self.const_labels,
            incoming_requests,
            response_time,
            response_codes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PrometheusMetrics {
    pub registry: Registry,
    pub(crate) namespace: String,
    pub(crate) endpoint: Option<String>,
    pub(crate) const_labels: HashMap<String, String>,
    pub(crate) clock: quanta::Clock,
    pub(crate) incoming_requests: IntCounterVec,
    pub(crate) response_time: HistogramVec,
    pub(crate) response_codes: IntCounterVec,
}

impl PrometheusMetrics {
    fn metrics(&self) -> String {
        use prometheus::{Encoder, TextEncoder};

        let mut buffer = vec![];
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buffer)
            .unwrap();

        #[cfg(feature = "process")]
        {
            let mut process_metrics = vec![];
            TextEncoder::new()
                .encode(&prometheus::gather(), &mut process_metrics)
                .unwrap();

            buffer.extend_from_slice(&process_metrics);
        }

        String::from_utf8(buffer).unwrap()
    }

    fn matches(&self, path: &str, method: &Method) -> bool {
        if self.endpoint.is_some() {
            self.endpoint.as_ref().unwrap() == path && method == Method::GET
        } else {
            false
        }
    }

    fn update_metrics(
        &self,
        path: &str,
        method: &Method,
        status_code: StatusCode,
        start: u64,
        end: u64,
    ) {
        let method = method.to_string();
        let status = status_code.as_u16().to_string();

        let elapsed = self.clock.delta(start, end);
        let duration = elapsed.as_secs_f64();

        self.response_time
            .with_label_values(&[path, &method, &status])
            .observe(duration);

        self.incoming_requests
            .with_label_values(&[path, &method, &status])
            .inc();

        match status_code.as_u16() {
            500..=599 => self
                .response_codes
                .with_label_values(&[path, &method, &status, "500"])
                .inc(),
            400..=499 => self
                .response_codes
                .with_label_values(&[path, &method, &status, "400"])
                .inc(),
            300..=399 => self
                .response_codes
                .with_label_values(&[path, &method, &status, "300"])
                .inc(),
            200..=299 => self
                .response_codes
                .with_label_values(&[path, &method, &status, "200"])
                .inc(),
            100..=199 => self
                .response_codes
                .with_label_values(&[path, &method, &status, "100"])
                .inc(),
            _ => (),
        };
    }
}

impl<S, B> Transform<S, ServiceRequest> for PrometheusMetrics
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    B: MessageBody + 'static,
    B::Error: Into<Box<dyn StdError + 'static>>,
{
    type Response = ServiceResponse<StreamMetrics<AnyBody>>;
    type Error = ActixError;
    type Transform = PrometheusMetricsMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PrometheusMetricsMiddleware {
            service,
            inner: Rc::new(self.clone()),
        }))
    }
}

pub struct PrometheusMetricsMiddleware<S> {
    service: S,
    inner: Rc<PrometheusMetrics>,
}

#[pin_project::pin_project]
pub struct MetricsResponse<S, B>
where
    B: MessageBody,
    S: Service<ServiceRequest>,
{
    #[pin]
    fut: S::Future,
    start: u64,
    inner: Rc<PrometheusMetrics>,
    _t: PhantomData<B>,
}

impl<S, B> Future for MetricsResponse<S, B>
where
    B: MessageBody + 'static,
    B::Error: Into<Box<dyn StdError + 'static>>,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
{
    type Output = Result<ServiceResponse<StreamMetrics<AnyBody>>, ActixError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let start = *this.start;

        let res = match ready!(this.fut.poll(cx)) {
            Ok(res) => res,
            Err(e) => return Poll::Ready(Err(e)),
        };

        let req = res.request();
        let method = req.method().clone();
        let pattern_or_path = req
            .match_pattern()
            .unwrap_or_else(|| req.path().to_string());
        let path = req.path().to_string();
        let inner = this.inner.clone();

        Poll::Ready(Ok(res.map_body(move |mut head, body| {
            // We short circuit the response status and body to serve the endpoint
            // automagically. This way the user does not need to set the middleware *AND*
            // an endpoint to serve middleware results. The user is only required to set
            // the middleware and tell us what the endpoint should be.
            if inner.matches(&path, &method) {
                head.status = StatusCode::OK;
                head.headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                );

                let body = AnyBody::from_message(inner.metrics());

                StreamMetrics {
                    body,
                    size: 0,
                    start,
                    inner,
                    status: head.status,
                    path: pattern_or_path,
                    method,
                }
            } else {
                let body = AnyBody::from_message(body);

                StreamMetrics {
                    body,
                    size: 0,
                    start,
                    inner,
                    status: head.status,
                    path: pattern_or_path,
                    method,
                }
            }
        })))
    }
}

impl<S, B> Service<ServiceRequest> for PrometheusMetricsMiddleware<S>
where
    B: MessageBody + 'static,
    B::Error: Into<Box<dyn StdError + 'static>>,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
{
    type Response = ServiceResponse<StreamMetrics<AnyBody>>;
    type Error = S::Error;
    type Future = MetricsResponse<S, B>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        MetricsResponse {
            fut: self.service.call(req),
            start: self.inner.clock.start(),
            inner: self.inner.clone(),
            _t: PhantomData,
        }
    }
}

use actix_web::dev::AnyBody;
use pin_project::{pin_project, pinned_drop};
use std::collections::HashMap;
use std::marker::PhantomData;

#[doc(hidden)]
#[pin_project(PinnedDrop)]
pub struct StreamMetrics<B> {
    #[pin]
    body: B,
    size: usize,
    start: u64,
    inner: Rc<PrometheusMetrics>,
    status: StatusCode,
    path: String,
    method: Method,
}

#[pinned_drop]
impl<B> PinnedDrop for StreamMetrics<B> {
    fn drop(self: Pin<&mut Self>) {
        // update the metrics for this request at the very end of responding
        self.inner.update_metrics(
            &self.path,
            &self.method,
            self.status,
            self.start,
            self.inner.clock.end(),
        );
    }
}

impl<B> MessageBody for StreamMetrics<B>
where
    B: MessageBody,
    B::Error: Into<ActixError>,
{
    type Error = ActixError;

    fn size(&self) -> BodySize {
        self.body.size()
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        let this = self.project();

        // TODO: MSRV 1.51: poll_map_err
        match ready!(this.body.poll_next(cx)) {
            Some(Ok(chunk)) => {
                *this.size += chunk.len();
                Poll::Ready(Some(Ok(chunk)))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(err.into()))),
            None => Poll::Ready(None),
        }
    }
}

// TODO: rework tests
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use actix_web::rt as actix_rt;
//     use actix_web::test::{call_service, init_service, read_body, read_response, TestRequest};
//     use actix_web::{web, App, HttpResponse};
//
//     use actix_web::middleware::Compat;
//     use prometheus::{Counter, Encoder, Opts, TextEncoder};
//
//     #[actix_rt::test]
//     async fn middleware_basic() {
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .endpoint("/metrics")
//             .build()
//             .unwrap();
//
//         let mut app = init_service(
//             App::new()
//                 .wrap(prometheus)
//                 .service(web::resource("/health_check").to(HttpResponse::Ok)),
//         )
//         .await;
//
//         let res = call_service(
//             &mut app,
//             TestRequest::with_uri("/health_check").to_request(),
//         )
//         .await;
//         assert!(res.status().is_success());
//         assert_eq!(read_body(res).await, "");
//
//         let res = call_service(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//         assert_eq!(
//             res.headers().get(CONTENT_TYPE).unwrap(),
//             "text/plain; version=0.0.4; charset=utf-8"
//         );
//         let body = String::from_utf8(read_body(res).await.to_vec()).unwrap();
//         println!("{:#?}", body);
//         assert!(&body.contains(
//             &String::from_utf8(web::Bytes::from(
//                 "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
// # TYPE actix_web_prom_http_requests_duration_seconds histogram
// actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/health_check\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
// "
//             ).to_vec()).unwrap()));
//         assert!(body.contains(
//             &String::from_utf8(
//                 web::Bytes::from(
//                     "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
// # TYPE actix_web_prom_http_requests_total counter
// actix_web_prom_http_requests_total{endpoint=\"/health_check\",method=\"GET\",status=\"200\"} 1
// "
//                 )
//                 .to_vec()
//             )
//             .unwrap()
//         ));
//     }
//
//     #[actix_rt::test]
//     async fn middleware_scope() {
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .endpoint("/internal/metrics")
//             .build()
//             .unwrap();
//
//         let mut app = init_service(
//             App::new().service(
//                 web::scope("/internal")
//                     .wrap(Compat::new(prometheus))
//                     .service(web::resource("/health_check").to(HttpResponse::Ok)),
//             ),
//         )
//         .await;
//
//         let res = call_service(
//             &mut app,
//             TestRequest::with_uri("/internal/health_check").to_request(),
//         )
//         .await;
//         assert!(res.status().is_success());
//         assert_eq!(read_body(res).await, "");
//
//         let res = call_service(
//             &mut app,
//             TestRequest::with_uri("/internal/metrics").to_request(),
//         )
//         .await;
//         assert_eq!(
//             res.headers().get(CONTENT_TYPE).unwrap(),
//             "text/plain; version=0.0.4; charset=utf-8"
//         );
//         let body = String::from_utf8(read_body(res).await.to_vec()).unwrap();
//         assert!(&body.contains(
//             &String::from_utf8(web::Bytes::from(
//                 "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
// # TYPE actix_web_prom_http_requests_duration_seconds histogram
// actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/internal/health_check\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
// "
//             ).to_vec()).unwrap()));
//         assert!(body.contains(
//             &String::from_utf8(
//                 web::Bytes::from(
//                     "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
// # TYPE actix_web_prom_http_requests_total counter
// actix_web_prom_http_requests_total{endpoint=\"/internal/health_check\",method=\"GET\",status=\"200\"} 1
// "
//                 )
//                     .to_vec()
//             )
//                 .unwrap()
//         ));
//     }
//
//     #[actix_rt::test]
//     async fn middleware_match_pattern() {
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .endpoint("/metrics")
//             .build()
//             .unwrap();
//
//         let mut app = init_service(
//             App::new()
//                 .wrap(prometheus)
//                 .service(web::resource("/resource/{id}").to(HttpResponse::Ok)),
//         )
//         .await;
//
//         let res = call_service(
//             &mut app,
//             TestRequest::with_uri("/resource/123").to_request(),
//         )
//         .await;
//         assert!(res.status().is_success());
//         assert_eq!(read_body(res).await, "");
//
//         let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//         let body = String::from_utf8(res.to_vec()).unwrap();
//         assert!(&body.contains(
//             &String::from_utf8(web::Bytes::from(
//                 "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
// # TYPE actix_web_prom_http_requests_duration_seconds histogram
// actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/resource/{id}\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
// "
//             ).to_vec()).unwrap()));
//         assert!(body.contains(
//             &String::from_utf8(
//                 web::Bytes::from(
//                     "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
// # TYPE actix_web_prom_http_requests_total counter
// actix_web_prom_http_requests_total{endpoint=\"/resource/{id}\",method=\"GET\",status=\"200\"} 1
// "
//                 )
//                 .to_vec()
//             )
//             .unwrap()
//         ));
//     }
//
//     #[actix_rt::test]
//     async fn middleware_metrics_exposed_with_conflicting_pattern() {
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .endpoint("/metrics")
//             .build()
//             .unwrap();
//
//         let mut app = init_service(
//             App::new()
//                 .wrap(prometheus)
//                 .service(web::resource("/{path}").to(HttpResponse::Ok)),
//         )
//         .await;
//
//         let res = call_service(&mut app, TestRequest::with_uri("/something").to_request()).await;
//         assert!(res.status().is_success());
//         assert_eq!(read_body(res).await, "");
//
//         let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//         let body = String::from_utf8(res.to_vec()).unwrap();
//         assert!(&body.contains(
//             &String::from_utf8(web::Bytes::from(
//                 "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests"
//             ).to_vec()).unwrap()));
//     }
//
//     #[actix_rt::test]
//     async fn middleware_basic_failure() {
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .endpoint("/prometheus")
//             .build()
//             .unwrap();
//
//         let mut app = init_service(
//             App::new()
//                 .wrap(prometheus)
//                 .service(web::resource("/health_check").to(HttpResponse::Ok)),
//         )
//         .await;
//
//         call_service(
//             &mut app,
//             TestRequest::with_uri("/health_checkz").to_request(),
//         )
//         .await;
//         let res = read_response(&mut app, TestRequest::with_uri("/prometheus").to_request()).await;
//         assert!(String::from_utf8(res.to_vec()).unwrap().contains(
//             &String::from_utf8(
//                 web::Bytes::from(
//                     "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
// # TYPE actix_web_prom_http_requests_total counter
// actix_web_prom_http_requests_total{endpoint=\"/health_checkz\",method=\"GET\",status=\"404\"} 1
// "
//                 )
//                 .to_vec()
//             )
//             .unwrap()
//         ));
//     }
//
//     #[actix_rt::test]
//     async fn middleware_custom_counter() {
//         let counter_opts = Opts::new("counter", "some random counter").namespace("actix_web_prom");
//         let counter = IntCounterVec::new(counter_opts, &["endpoint", "method", "status"]).unwrap();
//
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .endpoint("/metrics")
//             .build()
//             .unwrap();
//
//         prometheus
//             .registry
//             .register(Box::new(counter.clone()))
//             .unwrap();
//
//         let mut app = init_service(
//             App::new()
//                 .wrap(prometheus)
//                 .service(web::resource("/health_check").to(HttpResponse::Ok)),
//         )
//         .await;
//
//         // Verify that 'counter' does not appear in the output before we use it
//         call_service(
//             &mut app,
//             TestRequest::with_uri("/health_check").to_request(),
//         )
//         .await;
//         let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//         assert!(!String::from_utf8(res.to_vec()).unwrap().contains(
//             &String::from_utf8(
//                 web::Bytes::from(
//                     "# HELP actix_web_prom_counter some random counter
// # TYPE actix_web_prom_counter counter
// actix_web_prom_counter{endpoint=\"endpoint\",method=\"method\",status=\"status\"} 1
// "
//                 )
//                 .to_vec()
//             )
//             .unwrap()
//         ));
//
//         // Verify that 'counter' appears after we use it
//         counter
//             .with_label_values(&["endpoint", "method", "status"])
//             .inc();
//         counter
//             .with_label_values(&["endpoint", "method", "status"])
//             .inc();
//         call_service(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//         let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//         assert!(String::from_utf8(res.to_vec()).unwrap().contains(
//             &String::from_utf8(
//                 web::Bytes::from(
//                     "# HELP actix_web_prom_counter some random counter
// # TYPE actix_web_prom_counter counter
// actix_web_prom_counter{endpoint=\"endpoint\",method=\"method\",status=\"status\"} 2
// "
//                 )
//                 .to_vec()
//             )
//             .unwrap()
//         ));
//     }
//
//     #[actix_rt::test]
//     async fn middleware_none_endpoint() {
//         // Init PrometheusMetrics with none URL
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .build()
//             .unwrap();
//
//         let mut app =
//             init_service(App::new().wrap(prometheus.clone()).service(
//                 web::resource("/metrics").to(|| HttpResponse::Ok().body("not prometheus")),
//             ))
//             .await;
//
//         let response =
//             read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//
//         // Assert app works
//         assert_eq!(
//             String::from_utf8(response.to_vec()).unwrap(),
//             "not prometheus"
//         );
//
//         // Assert counter counts
//         let mut buffer = Vec::new();
//         let encoder = TextEncoder::new();
//         let metric_families = prometheus.registry.gather();
//         encoder.encode(&metric_families, &mut buffer).unwrap();
//         let output = String::from_utf8(buffer).unwrap();
//
//         assert!(output.contains(
//             "actix_web_prom_http_requests_total{endpoint=\"/metrics\",method=\"GET\",status=\"200\"} 1"
//         ));
//     }
//
//     #[actix_rt::test]
//     async fn middleware_custom_registry_works() {
//         // Init Prometheus Registry
//         let registry = Registry::new();
//
//         let counter_opts = Opts::new("test_counter", "test counter help");
//         let counter = Counter::with_opts(counter_opts).unwrap();
//         registry.register(Box::new(counter.clone())).unwrap();
//
//         counter.inc_by(10_f64);
//
//         // Init PrometheusMetrics
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .registry(registry)
//             .endpoint("/metrics")
//             .build()
//             .unwrap();
//
//         let mut app = init_service(
//             App::new()
//                 .wrap(prometheus.clone())
//                 .service(web::resource("/test").to(|| HttpResponse::Ok().finish())),
//         )
//         .await;
//
//         // all http counters are 0 because this is the first http request,
//         // so we should get only 10 on test counter
//         let response =
//             read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//
//         let ten_test_counter =
//             "# HELP test_counter test counter help\n# TYPE test_counter counter\ntest_counter 10\n";
//         assert_eq!(
//             String::from_utf8(response.to_vec()).unwrap(),
//             ten_test_counter
//         );
//
//         // all http counters are 1 because this is the second http request,
//         // plus 10 on test counter
//         let response =
//             read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//         let response_string = String::from_utf8(response.to_vec()).unwrap();
//
//         let one_http_counters = "# HELP actix_web_prom_http_requests_total Total number of HTTP requests\n# TYPE actix_web_prom_http_requests_total counter\nactix_web_prom_http_requests_total{endpoint=\"/metrics\",method=\"GET\",status=\"200\"} 1";
//
//         assert!(response_string.contains(ten_test_counter));
//         assert!(response_string.contains(one_http_counters));
//     }
//
//     #[actix_rt::test]
//     async fn middleware_const_labels() {
//         let mut labels = HashMap::new();
//         labels.insert("label1".to_string(), "value1".to_string());
//         labels.insert("label2".to_string(), "value2".to_string());
//         let prometheus = PrometheusMetricsBuilder::new("actix_web_prom")
//             .endpoint("/metrics")
//             .const_labels(labels)
//             .build()
//             .unwrap();
//
//         let mut app = init_service(
//             App::new()
//                 .wrap(prometheus)
//                 .service(web::resource("/health_check").to(HttpResponse::Ok)),
//         )
//         .await;
//
//         let res = call_service(
//             &mut app,
//             TestRequest::with_uri("/health_check").to_request(),
//         )
//         .await;
//         assert!(res.status().is_success());
//         assert_eq!(read_body(res).await, "");
//
//         let res = read_response(&mut app, TestRequest::with_uri("/metrics").to_request()).await;
//         let body = String::from_utf8(res.to_vec()).unwrap();
//         assert!(&body.contains(
//             &String::from_utf8(web::Bytes::from(
//                 "# HELP actix_web_prom_http_requests_duration_seconds HTTP request duration in seconds for all requests
// # TYPE actix_web_prom_http_requests_duration_seconds histogram
// actix_web_prom_http_requests_duration_seconds_bucket{endpoint=\"/health_check\",label1=\"value1\",label2=\"value2\",method=\"GET\",status=\"200\",le=\"0.005\"} 1
// "
//             ).to_vec()).unwrap()));
//         assert!(body.contains(
//             &String::from_utf8(
//                 web::Bytes::from(
//                     "# HELP actix_web_prom_http_requests_total Total number of HTTP requests
// # TYPE actix_web_prom_http_requests_total counter
// actix_web_prom_http_requests_total{endpoint=\"/health_check\",label1=\"value1\",label2=\"value2\",method=\"GET\",status=\"200\"} 1
// "
//                 )
//                     .to_vec()
//             )
//                 .unwrap()
//         ));
//     }
// }
