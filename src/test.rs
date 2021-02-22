use std::{
    fs::File,
    thread::sleep,
    time::Duration,
};
use async_trait::async_trait;
use ctor::ctor;
use env_logger;
use lazy_static::lazy_static;
use log::{debug, warn};
use openssl::{
    ec::EcKey,
    rsa::Rsa,
};
use rand::random;
use rusoto_core::{
    Region,
    request::HttpClient,
};
use rusoto_credential::{
    AwsCredentials, CredentialsError, DefaultCredentialsProvider, ProfileProvider, ProvideAwsCredentials};
use rusoto_route53::{
    Change, ChangeBatch, ChangeResourceRecordSetsRequest, GetChangeRequest, ResourceRecord, ResourceRecordSet, Route53, Route53Client};
use serde::Deserialize;
use crate::{
    account::AcmeAccountRequest,
    authorization::CHALLENGE_TYPE_DNS_01,
    directory::{AcmeDirectory, LETSENCRYPT_STAGING_DIRECTORY_URL},
    identifier::AcmeIdentifier,
    key::KeyAlg,
    order::AcmeOrderRequest,
};

const CHANGE_PREFIX: &str = "/change/";

#[derive(Debug, Deserialize)]
struct TestSettings {
    #[serde(rename="EcEmail")]
    ec_email: String,

    #[serde(rename="EcKey")]
    ec_key: String,

    #[serde(rename="RsaEmail")]
    rsa_email: String,

    #[serde(rename="RsaKey")]
    rsa_key: String,

    #[serde(rename="DnsDomain")]
    dns_domain: String,

    #[serde(rename="AwsProfile")]
    aws_profile: Option<String>,

    #[serde(rename="Route53ZoneId")]
    route53_zone_id: Option<String>,

    #[serde(rename="Challenges")]
    challenges: Vec<String>,
}

#[async_trait]
impl ProvideAwsCredentials for &TestSettings {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        match &self.aws_profile {
            None => DefaultCredentialsProvider::new()?.credentials().await,
            Some(profile) => ProfileProvider::with_default_credentials(profile)?.credentials().await,
        } 
    }
}


const TEST_SETTINGS_FILENAME: &str = ".test-settings.json";

lazy_static! {
    static ref TEST_SETTINGS: TestSettings = {
        let mut settings_file = File::open(TEST_SETTINGS_FILENAME)
            .unwrap_or_else(|e| panic!("Unable to open {}: {:#}", TEST_SETTINGS_FILENAME, e));
        let s: TestSettings = serde_json::from_reader(&mut settings_file)
            .unwrap_or_else(|e| panic!("Unable to parse {}: {:#}", TEST_SETTINGS_FILENAME, e));
        s
    };
}

#[ctor]
fn init() {
    env_logger::try_init().unwrap_or_else(|e| eprintln!("Failed to initialize env_logger: {:#}", e));
}

#[tokio::test]
async fn test_ec_dns01() {
    let eckey = EcKey::private_key_from_pem(TEST_SETTINGS.ec_key.as_bytes()).unwrap();
    let keyalg = KeyAlg::Ed25519(eckey);
    dns_test_core(keyalg, &TEST_SETTINGS.ec_email).await;
}

#[tokio::test]
async fn test_rsa_dns01() {
    let rsakey = Rsa::private_key_from_pem(TEST_SETTINGS.rsa_key.as_bytes()).unwrap();
    let keyalg = KeyAlg::RsaSha256(rsakey);
    dns_test_core(keyalg, &TEST_SETTINGS.rsa_email).await;
}

async fn dns_test_core(keyalg: KeyAlg, email: &str) {
    let dir = AcmeDirectory::from_url(LETSENCRYPT_STAGING_DIRECTORY_URL, keyalg.clone()).await.unwrap();

    let req = AcmeAccountRequest{
        contact: Some(vec![format!("mailto:{}", email)]),
        terms_of_service_agreed: Some(true),
        external_account_binding: None,
        only_return_existing: None,
    };
    let (dir, account) = dir.login(&req).await.unwrap();
    debug!("Account: {:#?}", account);

    let hostname = format!("test-{:x}.{}", random::<u16>(), TEST_SETTINGS.dns_domain);

    let req = AcmeOrderRequest::for_identifiers(vec![AcmeIdentifier::dns(&hostname)]);
    let order = dir.new_order(&req).await.unwrap();
    debug!("Order: {:#?}", order);

    let authorizations = order.get_authorizations(&dir).await.unwrap();
    for (auth_url, ref auth) in authorizations {
        debug!("Authorization: {:#?}", auth);
        let dns_challenge = auth.get_challenge_by_type(CHALLENGE_TYPE_DNS_01).unwrap();

        if let Some(route53_zone_id) = &TEST_SETTINGS.route53_zone_id {
            let http_client = HttpClient::new().unwrap();
            let challenge_value = dns_challenge.get_txt_record(&keyalg).unwrap();
            let r53 = Route53Client::new_with(http_client, &*TEST_SETTINGS, Region::UsEast1);
            let crrs_req = ChangeResourceRecordSetsRequest {
                hosted_zone_id: route53_zone_id.to_string(),
                change_batch: ChangeBatch{
                    comment: None,
                    changes: vec![
                        Change {
                            action: "UPSERT".to_string(),
                            resource_record_set: ResourceRecordSet {
                                alias_target: None,
                                failover: None,
                                geo_location: None,
                                health_check_id: None,
                                multi_value_answer: None,
                                name: format!("_acme-challenge.{}", auth.identifier.value),
                                region: None,resource_records: Some(vec![
                                    ResourceRecord {
                                        value: challenge_value,
                                    }
                                ]),
                                set_identifier: None,
                                ttl: Some(10),
                                traffic_policy_instance_id: None,
                                type_: "TXT".to_string(),
                                weight: None,
                            },
                        }
                    ],
                }
            };

            debug!("Changing resource record: {:?}", crrs_req);
            let crrs_result = r53.change_resource_record_sets(crrs_req).await.unwrap();
            debug!("crrs: {:?}", crrs_result);
            let mut change_info = crrs_result.change_info;
            while change_info.status == "PENDING" {
                debug!("Change {} is still pending", change_info.id);
                sleep(Duration::from_millis(500));

                // Bug in Rusoto -- when the Change isn't a raw ChangeId but a path like /change/1234, it duplicates the
                // /change/ part in the url: https://route53.amazonaws.com/2013-04-01/change//change/1234
                // The double slash results in a signature error (and would be erroneous, anyway).
                let mut change_id = change_info.id.clone();
                if change_id.starts_with(CHANGE_PREFIX) {
                    change_id = change_id.split_at(CHANGE_PREFIX.len()).1.to_string();
                }
                let gc_req = GetChangeRequest { id: change_id, };
                change_info = r53.get_change(gc_req).await.unwrap().change_info;
            }
            debug!("Change {} status is {}", change_info.id, change_info.status);

            let challenge_response = dns_challenge.respond(&dir).await.unwrap();
            debug!("Challenge response: {:?}", challenge_response);

            let mut auth = dir.get_authorization(&auth_url).await.unwrap();
            let mut dns_challenge_status = "pending".to_string();

            for _retry in 0..10 {
                debug!("Authorization: {:?}", auth);
                for challenge in auth.challenges {
                    if challenge.challenge_type == "dns-01" {
                        dns_challenge_status = challenge.status;
                    }
                }

                if dns_challenge_status == "valid" {
                    break
                }

                sleep(Duration::from_millis(1000));
                auth = dir.get_authorization(&auth_url).await.unwrap();
            }

            assert!(dns_challenge_status == "valid");
        } else {
            warn!("Skipping dns-01 challenge test -- Route53ZoneId not set.")
        }
    }
}
