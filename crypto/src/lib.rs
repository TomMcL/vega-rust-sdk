use std::{time::Duration, collections::{HashMap, VecDeque}, sync::Arc};
use chrono::Utc;
use futures::lock::Mutex;

use crypto::Signer;
use errors::Error;
use log::{error, info};
use prost::Message;
use rand::{thread_rng, Rng};
use sha3::{Digest, Sha3_256};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tokio::sync::mpsc::{Receiver, Sender, self};
use tonic::transport::Channel;
use vega_protobufs::vega::{
    api::v1::{
        core_service_client::CoreServiceClient, submit_raw_transaction_request,
        CheckTransactionRequest, LastBlockHeightRequest, SubmitTransactionRequest, ObserveEventBusRequest,
    },
    commands::v1::{
        input_data::Command, transaction::From as From_, InputData, ProofOfWork, Signature,
        Transaction, TxVersion,
    }, events::v1::{BusEventType, bus_event::Event},
};

mod crypto;
pub mod errors;
pub mod pow;
pub mod slip10;

const CHAIN_ID_DELIMITER: char = 0 as char;
const SIGNATURE_ALGORITHM: &str = "vega/ed25519";

#[derive(Clone)]
pub struct Transact {
    signer: Signer,
    client: Arc<Mutex<CoreServiceClient<tonic::transport::Channel>>>,
    pow_req: Sender<bool>,
    pow_recv: Arc<Mutex<Receiver<(u64, ProofOfWork)>>>,
    chain_id: String,
}

#[derive(Clone, Debug)]
pub enum Credentials<'s> {
    /// An hex encoded private key
    PrivateKey(&'s str),
    /// A mnemonic phrase and derivation count
    /// this is to be compatible with the the vega wallet
    /// standard derivation
    Mnemonic(&'s str, usize),
}

#[derive(Clone, Debug)]
pub enum Payload {
    Command(Command),
    Transaction(Transaction),
}

impl From<Command> for Payload {
    fn from(c: Command) -> Self {
        Payload::Command(c)
    }
}

impl From<Transaction> for Payload {
    fn from(t: Transaction) -> Self {
        Payload::Transaction(t)
    }
}

#[derive(Clone, Debug)]
pub struct CheckTxResult {
    pub success: bool,
    pub code: u32,
    pub error: Option<String>,
    pub log: Option<String>,
    pub info: Option<String>,
    pub gas_wanted: i64,
    pub gas_used: i64,
}

pub async fn run_pre_power(
    client: Arc<Mutex<CoreServiceClient<Channel>>>,
    pow_request: Receiver<bool>,
    pow_sender: Sender<(u64, ProofOfWork)>,
    gen_per_block: usize,
)
{
    let mut req_stream = ReceiverStream::new(pow_request);

    let stream_req = async_stream::stream! {
            yield ObserveEventBusRequest{
            r#type: vec![BusEventType::BeginBlock.into()],
            ..Default::default()
        }
    };

    let mut block_end_stream;
    let spam_dets;

    {
        let mut cl = client.lock().await;
        block_end_stream = match cl.observe_event_bus(stream_req).await
        {
            Ok(s) => s.into_inner(),
            Err(e) => panic!("{:?}", e),
        };
        spam_dets = cl
            .last_block_height(LastBlockHeightRequest {})
            .await
            .unwrap().into_inner();
    }

    let difficulty = spam_dets.spam_pow_difficulty as usize;
    let difficulty_step = spam_dets.spam_pow_number_of_tx_per_block as usize;
    let historic_blocks_to_keep = (spam_dets.spam_pow_number_of_past_blocks - 10) as usize;

    let mut gen_interval = tokio::time::interval(Duration::from_millis(100));

    let mut used_blocks: HashMap<u64, usize> = HashMap::new();
    let mut block_hashes: HashMap<u64, String> = HashMap::new();
    let mut block_queue: VecDeque<u64> = VecDeque::new();
    let mut available_pows: VecDeque<(u64, ProofOfWork)> = VecDeque::new();

    let mut oldest_block: u64 = spam_dets.height;
    let mut latest_block: u64 = spam_dets.height;
    let mut to_send: u64 = 0;

    loop {
        tokio::select! {
            _ = req_stream.next() => {
                to_send += 1;
                
                while to_send > 0 && available_pows.len() > 0 {
                    let pow = available_pows.pop_back().unwrap();
                    if pow.0 >= oldest_block {
                        if let Err(e) = pow_sender.send(pow).await {
                            error!("{}", e);
                        } else {
                            to_send -= 1;
                        }
                    }
                }
            }
            _ = gen_interval.tick() => {
                let mut search_block = latest_block;
                while search_block >= oldest_block {
                    let mut num_used = used_blocks.get(&search_block).unwrap_or(&gen_per_block).to_owned();
                    if num_used < gen_per_block {
                        while num_used < gen_per_block {

                            let txid = random_hash();

                            let (pow_nonce, _) = pow::solve(
                                &block_hashes.get(&search_block).unwrap(),
                                &txid,
                                difficulty + num_used / difficulty_step,
                            ).unwrap();

                            available_pows.push_front((
                                search_block.to_owned(),
                                ProofOfWork {
                                    tid: txid,
                                    nonce: pow_nonce,
                                }
                            ));
                            num_used += 1;
                            used_blocks.insert(search_block, num_used);
                        }
                        break;
                    } else {
                        search_block -= 1;
                    }
                }
                gen_interval.reset();
            }
            Some(be) = block_end_stream.next() => {
                for evt in be.unwrap().events {
                    match evt.event {
                        Some(Event::BeginBlock(e)) => {
                            latest_block = e.height;
                            used_blocks.insert(e.height, 0);
                            block_hashes.insert(e.height, e.hash);
                            block_queue.push_front(e.height);
                            if block_queue.len() > historic_blocks_to_keep {
                                let to_rem = block_queue.pop_back().unwrap();
                                used_blocks.remove(&to_rem);
                                block_hashes.remove(&to_rem);
                                oldest_block = block_queue.iter().last().unwrap().to_owned();
                            }
                        },
                        _ => unreachable!(),
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct SendTxResult {
    pub success: bool,
    pub code: u32,
    pub error: Option<String>,
    pub hash: String,
}

impl Transact {
    pub async fn new<'s, D>(creds: Credentials<'s>, node_address: D, gen_pows_per_block: usize) -> Result<Transact, Error>
    where
        D: std::convert::TryInto<tonic::transport::Endpoint> + std::marker::Send + Clone,
        D::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        let signer = match creds {
            Credentials::PrivateKey(secret) => crypto::Signer::from_secret_key(secret)?,
            Credentials::Mnemonic(mnemonic, derivations) => {
                crypto::Signer::from_mnemonic(mnemonic, derivations)?
            }
        };

        let (pow_req, pow_req_recv) = mpsc::channel(10);
        let (pow_sender, pow_recv) = mpsc::channel(10);

        let client = Arc::new(Mutex::new(CoreServiceClient::connect(node_address).await?));
        let res = client.lock().await
        .last_block_height(LastBlockHeightRequest {})
        .await?;

        tokio::spawn(
            run_pre_power(
                Arc::clone(&client),
                pow_req_recv,
                pow_sender,
                gen_pows_per_block,
            )
        );

        return Ok(Transact { signer, client, pow_req, pow_recv: Arc::new(Mutex::new(pow_recv)), chain_id: res.get_ref().chain_id.to_string() });
    }

    pub async fn sign(&self, cmd: &Command) -> Result<Transaction, Error> {
        // first get the block infos
        self.pow_req.send(true).await.unwrap();

        let (height, pow) = self.pow_recv.lock().await.recv().await.unwrap().to_owned();

        let input_data = InputData {
            nonce: gen_nonce(),
            block_height: height,
            command: Some(cmd.clone()),
        }
        .encode_to_vec();

        let signature = hex::encode(self.signer.sign(&build_signable_message(
            &input_data,
            &self.chain_id,
        )));

        return Ok(Transaction {
            from: Some(From_::PubKey(hex::encode(self.signer.pubkey()))),
            version: TxVersion::V3.into(),
            input_data,
            signature: Some(Signature {
                value: signature,
                algo: SIGNATURE_ALGORITHM.into(),
                version: 1,
            }),
            pow: Some(pow),
        });
    }

    pub async fn send<P>(&self, p: P) -> Result<SendTxResult, Error>
    where
        P: Into<Payload>,
    {
        let tx = match p.into() {
            Payload::Command(c) => self.sign(&c).await?,
            Payload::Transaction(tx) => tx,
        };
        let resp = self
            .client.lock().await
            .submit_transaction(SubmitTransactionRequest {
                tx: Some(tx),
                r#type: submit_raw_transaction_request::Type::Async.into(),
            })
            .await?;

        let err = match resp.get_ref().success {
            true => None,
            false => Some(resp.get_ref().data.to_string()),
        };

        return Ok(SendTxResult {
            success: resp.get_ref().success,
            hash: resp.get_ref().tx_hash.clone(),
            code: resp.get_ref().code,
            error: err,
        });
    }

    pub async fn check<P>(&mut self, p: P) -> Result<CheckTxResult, Error>
    where
        P: Into<Payload>,
    {
        let tx = match p.into() {
            Payload::Command(c) => self.sign(&c).await?,
            Payload::Transaction(tx) => tx,
        };
        let resp = self
            .client.lock().await
            .check_transaction(CheckTransactionRequest { tx: Some(tx) })
            .await?;

        let err = match resp.get_ref().success {
            true => None,
            false => Some(resp.get_ref().data.to_string()),
        };

        let info = match resp.get_ref().info.is_empty() {
            true => None,
            false => Some(resp.get_ref().info.to_string()),
        };

        let log = match resp.get_ref().log.is_empty() {
            true => None,
            false => Some(resp.get_ref().log.to_string()),
        };

        return Ok(CheckTxResult {
            success: resp.get_ref().success,
            code: resp.get_ref().code,
            gas_used: resp.get_ref().gas_used,
            gas_wanted: resp.get_ref().gas_wanted,
            error: err,
            info: info,
            log: log,
        });
    }

    /// The public key hex encoded
    pub fn public_key(&self) -> String {
        return hex::encode(self.signer.pubkey());
    }

    /// The secret key hex encoded
    pub fn secret_key(&self) -> String {
        return hex::encode(self.signer.secret());
    }
}

fn build_signable_message(input_data: &[u8], chain_id: &str) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    out.extend_from_slice(chain_id.as_bytes());
    out.extend_from_slice(&[CHAIN_ID_DELIMITER as u8]);
    out.extend_from_slice(input_data);
    return out;
}

fn gen_nonce() -> u64 {
    let mut rng = rand::thread_rng();
    return rng.gen_range(0..u64::MAX);
}

fn random_hash() -> String {
    let msg = thread_rng()
        .sample_iter::<u8, _>(rand::distributions::Standard)
        .take(10)
        .collect::<Vec<u8>>();
    let mut hasher = Sha3_256::new();
    hasher.update(msg);
    let h = hasher.finalize().to_vec();
    return hex::encode(h).to_uppercase();
}
