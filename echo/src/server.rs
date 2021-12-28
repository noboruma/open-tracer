use tokio::net::UnixListener;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;

use tonic::{ Request, Response, Status};
pub mod kernel_tracer {
    tonic::include_proto!("kernel_tracer");
}

use kernel_tracer::trace_info::Message;
use kernel_tracer::kernel_tracer_server::{KernelTracer, KernelTracerServer};
use kernel_tracer::{PidTraceInfoRequest, TraceInfo, KernelVersion};
use kernel_tracer::KernelInfo;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, Mutex};

use crate::kernel_version::{extract_kernel_version, UNKNOWN_KERNEL_VERSION};
use crate::metrics;

use self::kernel_tracer::Metrics;

use crate::unix::UnixStream;

use futures::TryFutureExt;

const CHANNEL_SIZE: usize = 100;

type ProcessID = String;
type PathStr   = String;
type InfoContainer = HashMap<ProcessID, ProcessInfo>;

#[derive(Clone)]
pub struct ProcessInfo {
    pub command: String,
    pub open_files: HashSet<PathStr>,
}

pub struct ProcessInfoCache {
    pub info: RwLock<InfoContainer>,
    last_accessed: Mutex<HashSet<ProcessID>>,
}

pub async fn run_server(socket: UnixListener, mg: OpenFilesKernelTracer) -> Result<(), tonic::transport::Error>{

    let incoming = async_stream::stream! {
        loop {
            let item = socket.accept().map_ok(|(st, _)| UnixStream(st)).await;
            yield item;
        }
    };
    return Server::builder()
        .add_service(KernelTracerServer::new(mg))
        .serve_with_incoming(incoming)
        .await;
}

impl ProcessInfoCache {

    pub fn new() -> ProcessInfoCache {
        return ProcessInfoCache {
            info:  RwLock::new(HashMap::new()),
            last_accessed: Mutex::new(HashSet::new()),
        }
    }

    pub fn bump_up(&self, pidstr: &ProcessID) {
        let mut last_accessed = self.last_accessed.lock().unwrap();
        last_accessed.insert(pidstr.clone());
    }

    pub fn clean_up(&self) {
        let mut last_accessed = self.last_accessed.lock().unwrap();
        let mut info = self.info.write().unwrap();
        if info.len() > last_accessed.len() {
            let mut to_remove = Vec::new();
            {
                for (k, _) in info.iter() {
                    if !last_accessed.contains(k) {
                        to_remove.push(k.clone());
                    }
                }
            }

            {
                for i in to_remove.iter() {
                    info.remove(i);
                }
            }
        }
        last_accessed.clear();
    }

    fn extract_paths(&self, pid: ProcessID) -> Vec<PathStr> {
        let process_info = self.info.read().unwrap();
        let &ev = &process_info.get(&pid);
        let mut res = Vec::new();
        match ev {
            Some(info) =>
                for path in &info.open_files {
                    res.push(path.clone());
                },
            None => (),
        }
        return res;
    }
}

#[derive(Clone)]
pub struct OpenFilesKernelTracer {
    pub process_info: Arc<ProcessInfoCache>,
    pub metrics: Arc<metrics::Metrics>,
}

#[tonic::async_trait]
impl KernelTracer for OpenFilesKernelTracer {

    type GetPIDTraceInfoStream = ReceiverStream<Result<TraceInfo, Status>>;

    async fn get_pid_trace_info(
        &self,
        request: Request<PidTraceInfoRequest>,
    ) -> Result<Response<Self::GetPIDTraceInfoStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(CHANNEL_SIZE);

        let process_info = self.process_info.clone();
        tokio::spawn(async move {
            let pid = request.into_inner().pid;
            process_info.bump_up(&pid);
            let paths = process_info.extract_paths(pid);
            for path in &paths {
                tx.send(Ok(TraceInfo{ message: Option::Some(Message::Path(path.clone())) })).await.unwrap();
            };
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_kernel_support(&self, _: tonic::Request<kernel_tracer::Empty>) -> Result<Response<KernelInfo>, Status> {
        let bpf_kernel_version = extract_kernel_version(env!("OPEN_TRACER_EBPF_BIN_ABS_PATH"))
            .unwrap_or(UNKNOWN_KERNEL_VERSION);
        Ok(Response::new(KernelInfo{
            version: Some(KernelVersion{
                major: format!("{}", bpf_kernel_version.0),
                minor: format!("{}", bpf_kernel_version.1),
                patch: String::new(),
            })
        }))
    }

    async fn get_metrics(&self, _: tonic::Request<kernel_tracer::Empty>) -> Result<Response<Metrics>, Status> {
        Ok( Response::new(Metrics {
            event_failure_count: self.metrics.get_missing(),
            event_success_count: self.metrics.get_handled(),
            ebf_buffer_capacity: self.metrics.get_buffer_capacity(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::FromIterator};

    use std::array::IntoIter;

    use super::{ProcessInfoCache, ProcessInfo};

    fn init() -> ProcessInfo {
        return ProcessInfo {
            command: "comm".to_owned(),
            open_files: HashSet::<_>::from_iter(IntoIter::new(["file1".to_owned()])),
        };
    }

    #[test]
    fn check_process_info_cache_clean(){
        // Init
        let default_info = init();
        let cache = ProcessInfoCache::new();
        let pidstr = "pid1".to_owned();
        {
            let mut info = cache.info.write().unwrap();
            info.insert(pidstr.clone(), default_info);
        }

        // Act
        cache.clean_up();

        // Verify
        let info = cache.info.write().unwrap();
        let res = info.get(&pidstr);
        assert!(res.is_none(), "Clean up failed");
    }

    #[test]
    fn check_process_info_cache_bumpup(){
        // Init
        let default_info = init();
        let cache = ProcessInfoCache::new();
        let pidstr = "pid1".to_owned();
        {
            let mut info = cache.info.write().unwrap();
            info.insert(pidstr.clone(), default_info);
        }

        // Act
        cache.bump_up(&pidstr);
        cache.clean_up();

        // Verify
        let info = cache.info.write().unwrap();
        let res = info.get(&pidstr);
        assert!(res.is_some(), "Bump up failed");
    }
}
